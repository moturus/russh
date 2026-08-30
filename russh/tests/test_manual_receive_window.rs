use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, ReceiveCredit, client};
use ssh_key::PrivateKey;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep, timeout};

const WINDOW_SIZE: u32 = 8192;

#[tokio::test]
async fn credit_wakes_a_peer_with_an_exhausted_window() -> anyhow::Result<()> {
    assert_eq!(run_transfer(Consume::WholeFromTask, 2).await?, 16384);
    Ok(())
}

#[tokio::test]
async fn inline_incremental_credit_does_not_wedge_the_session() -> anyhow::Result<()> {
    assert_eq!(run_transfer(Consume::InHalvesInline, 4).await?, 32768);
    Ok(())
}

#[tokio::test]
async fn channels_without_a_credit_handle_remain_automatic() -> anyhow::Result<()> {
    assert_eq!(run_transfer(Consume::Never, 4).await?, 32768);
    Ok(())
}

#[tokio::test]
async fn dropping_credit_after_exhaustion_unblocks_the_peer() -> anyhow::Result<()> {
    assert_eq!(run_transfer(Consume::DropAfterFirst, 4).await?, 32768);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Consume {
    WholeFromTask,
    InHalvesInline,
    Never,
    DropAfterFirst,
}

async fn run_transfer(consume: Consume, windows: usize) -> anyhow::Result<usize> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let received = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(TestServer::run(listener, consume, received.clone()));

    let result = timeout(Duration::from_secs(10), async {
        let config = Arc::new(client::Config {
            inactivity_timeout: None,
            ..Default::default()
        });
        let key =
            Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let mut session = russh::client::connect(config, addr, Client).await?;
        assert!(
            session
                .authenticate_publickey(
                    "user",
                    PrivateKeyWithHashAlg::new(
                        key,
                        session.best_supported_rsa_hash().await.unwrap().flatten(),
                    ),
                )
                .await?
                .success(),
            "authentication failed"
        );

        // No channel request follows the open. Manual accounting must already
        // govern the first byte sent after the open confirmation.
        let channel = session.channel_open_session().await?;
        let payload = vec![0u8; WINDOW_SIZE as usize];
        let total = windows * WINDOW_SIZE as usize;
        for _ in 0..windows {
            channel.data(&payload[..]).await?;
        }
        while received.load(Ordering::SeqCst) < total {
            sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, anyhow::Error>(received.load(Ordering::SeqCst))
    })
    .await
    .expect("transfer stalled waiting for receive-window credit");

    server.abort();
    let _ = server.await;
    result
}

#[derive(Clone)]
struct TestServer {
    consume: Consume,
    received: Arc<AtomicUsize>,
    credit: Option<ReceiveCredit>,
}

impl TestServer {
    async fn run(listener: TcpListener, consume: Consume, received: Arc<AtomicUsize>) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: WINDOW_SIZE,
            event_buffer_size: 1,
            inactivity_timeout: None,
            keepalive_interval: None,
            ..Default::default()
        });
        let mut server = Self {
            consume,
            received,
            credit: None,
        };
        server.run_on_socket(config, &listener).await.unwrap();
    }
}

impl server::Server for TestServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.consume != Consume::Never {
            self.credit = Some(
                session
                    .receive_credit(channel.id())
                    .expect("incoming channel is visible before confirmation"),
            );
        }
        reply.accept().await;
        tokio::spawn(async move {
            let _channel = channel;
            std::future::pending::<()>().await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.received.fetch_add(data.len(), Ordering::SeqCst);
        if self.consume == Consume::DropAfterFirst {
            self.credit.take();
            return Ok(());
        }
        let Some(credit) = self.credit.clone() else {
            return Ok(());
        };
        let len = data.len() as u32;
        match self.consume {
            Consume::InHalvesInline => {
                credit.consumed(len / 2);
                credit.consumed(len - len / 2);
            }
            _ => {
                tokio::spawn(async move { credit.consumed(len) });
            }
        }
        Ok(())
    }
}

struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
