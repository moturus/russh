use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh::{client, server};
use tokio::sync::oneshot;
use tokio::time::timeout;

struct Server {
    entered: Option<oneshot::Sender<()>>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Relaxed);
    }
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        }
        Ok(server::Auth::Accept)
    }
}

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn fixture(
    entered: Option<oneshot::Sender<()>>,
) -> (
    server::RunningSession<Server>,
    client::Handle<Client>,
    Arc<AtomicBool>,
) {
    let config = Arc::new(server::Config {
        keys: vec![
            russh::keys::PrivateKey::random(
                &mut rand::rng(),
                russh::keys::ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        ],
        inactivity_timeout: None,
        ..Default::default()
    });
    let dropped = Arc::new(AtomicBool::new(false));
    let handler = Server {
        entered,
        dropped: dropped.clone(),
    };
    let (server_stream, client_stream) = tokio::io::duplex(4096);
    let server = tokio::spawn(server::run_stream(config, server_stream, handler));
    let client = client::connect_stream(Arc::new(client::Config::default()), client_stream, Client)
        .await
        .unwrap();
    (server.await.unwrap().unwrap(), client, dropped)
}

#[tokio::test]
async fn abort_releases_a_blocked_auth_callback_and_transport() {
    timeout(Duration::from_secs(5), async {
        let (entered, started) = oneshot::channel();
        let (server, mut client, dropped) = fixture(Some(entered)).await;
        let authenticating = tokio::spawn(async move { client.authenticate_none("user").await });
        started.await.unwrap();

        server.abort();
        assert!(matches!(server.await, Err(russh::Error::Disconnect)));
        assert!(dropped.load(Ordering::Relaxed));
        assert!(matches!(
            authenticating.await.unwrap().unwrap(),
            client::AuthResult::Failure {
                remaining_methods,
                partial_success: false,
            } if remaining_methods == russh::MethodSet::empty()
        ));
    })
    .await
    .expect("aborting a blocked callback left the session or peer alive");
}

#[tokio::test]
async fn abort_releases_an_authenticated_idle_session() {
    timeout(Duration::from_secs(5), async {
        let (server, mut client, dropped) = fixture(None).await;
        assert!(client.authenticate_none("user").await.unwrap().success());

        server.abort();
        assert!(matches!(server.await, Err(russh::Error::Disconnect)));
        assert!(dropped.load(Ordering::Relaxed));
        assert!(client.send_ping().await.is_err());
    })
    .await
    .expect("aborting an idle session left its transport alive");
}
