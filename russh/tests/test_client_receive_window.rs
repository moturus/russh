use std::sync::Arc;

use russh::{Channel, ChannelId, ChannelMsg, ReceiveCredit, client, server};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

const WINDOW: u32 = 8192;

#[derive(Clone, Copy)]
enum Mode {
    Consume,
    Release,
    Automatic,
}

struct Client {
    manual: bool,
    credits: mpsc::UnboundedSender<Option<ReceiveCredit>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        _: u32,
        _: u32,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let credit = self.manual.then(|| session.receive_credit(id).unwrap());
        self.credits.send(credit).unwrap();
        Ok(())
    }
}

struct Server(mpsc::UnboundedSender<Channel<server::Msg>>);

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(channel).unwrap();
        reply.accept().await;
        Ok(())
    }
}

async fn read_window(channel: &mut Channel<client::Msg>) {
    let mut received = 0;
    while received < WINDOW as usize {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                assert!(data.iter().all(|byte| *byte == 0x5a));
                received += data.len();
            }
            other => panic!("expected window data, got {other:?}"),
        }
    }
    assert_eq!(received, WINDOW as usize);
}

async fn transfer(mode: Mode) -> anyhow::Result<()> {
    timeout(Duration::from_secs(5), async {
        let (socket, peer) = tokio::io::duplex(64 * 1024);
        let (opened_tx, mut opened) = mpsc::unbounded_channel();
        let starting = tokio::spawn(server::run_stream(
            Arc::new(server::Config {
                keys: vec![russh::keys::PrivateKey::random(
                    &mut rand::rng(),
                    russh::keys::ssh_key::Algorithm::Ed25519,
                )?],
                inactivity_timeout: None,
                ..Default::default()
            }),
            socket,
            Server(opened_tx),
        ));
        let (credits_tx, mut credits) = mpsc::unbounded_channel();
        let mut client = client::connect_stream(
            Arc::new(client::Config {
                window_size: WINDOW,
                maximum_packet_size: 1024,
                inactivity_timeout: None,
                ..Default::default()
            }),
            peer,
            Client {
                manual: !matches!(mode, Mode::Automatic),
                credits: credits_tx,
            },
        )
        .await?;
        let server = starting.await??;
        assert!(client.authenticate_none("user").await?.success());
        let mut channel = client.channel_open_session().await?;
        let remote = opened.recv().await.unwrap();
        let mut credit = credits.recv().await.unwrap();
        remote.data_bytes(vec![0x5a; WINDOW as usize]).await?;
        read_window(&mut channel).await;
        // A pong orders every automatic adjustment from the first window
        // ahead of this observation at the sending peer.
        client.send_ping().await?;
        if matches!(mode, Mode::Automatic) {
            assert!(remote.writable_packet_size().await > 0);
        } else {
            assert_eq!(remote.writable_packet_size().await, 0);
        }
        match mode {
            Mode::Consume => {
                let credit = credit.as_ref().unwrap();
                credit.consumed(WINDOW / 2);
                credit.consumed(WINDOW / 2);
            }
            Mode::Release | Mode::Automatic => drop(credit.take()),
        }
        let (sent, ()) = tokio::join!(
            remote.data_bytes(vec![0x5a; WINDOW as usize]),
            read_window(&mut channel),
        );
        sent?;
        if matches!(mode, Mode::Consume) {
            assert_eq!(remote.writable_packet_size().await, 0);
        }
        remote.eof().await?;
        remote.close().await?;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Close) => break,
                None => panic!("channel ended without close"),
                Some(_) => {}
            }
        }
        client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await?;
        assert!(matches!(
            client.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        assert!(matches!(
            server.await,
            Ok(()) | Err(russh::Error::Disconnect)
        ));
        Ok(())
    })
    .await
    .expect("client receive credit stalled")
}

#[tokio::test]
async fn client_credit_waits_for_consumption_and_wakes_the_sender() -> anyhow::Result<()> {
    transfer(Mode::Consume).await
}

#[tokio::test]
async fn dropping_the_last_client_credit_restores_automatic_mode() -> anyhow::Result<()> {
    transfer(Mode::Release).await
}

#[tokio::test]
async fn ordinary_client_channels_keep_automatic_credit() -> anyhow::Result<()> {
    transfer(Mode::Automatic).await
}
