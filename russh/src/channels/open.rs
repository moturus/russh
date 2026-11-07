use tokio::sync::mpsc;

use crate::{ChannelId, ReceiveCredit};

/// Internal ownership transfer for an application-controlled outgoing open.
#[doc(hidden)]
#[derive(Debug)]
pub struct PendingChannelCredit<M> {
    credit: ReceiveCredit,
    cleanup: OpenCleanup<M>,
}

impl<M> PendingChannelCredit<M> {
    pub(crate) fn new(
        id: ChannelId,
        sender: mpsc::UnboundedSender<M>,
        credit: ReceiveCredit,
        abandon: fn(ChannelId) -> M,
    ) -> Self {
        Self {
            credit,
            cleanup: OpenCleanup { id, sender: Some(sender), abandon },
        }
    }

    pub(crate) fn finish(self) -> ReceiveCredit {
        self.cleanup.disarm();
        self.credit
    }
}

struct OpenCleanup<M> {
    id: ChannelId,
    sender: Option<mpsc::UnboundedSender<M>>,
    abandon: fn(ChannelId) -> M,
}

impl<M> std::fmt::Debug for OpenCleanup<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenCleanup")
            .field("id", &self.id)
            .field("armed", &self.sender.is_some())
            .finish()
    }
}

impl<M> OpenCleanup<M> {
    fn disarm(mut self) {
        self.sender = None;
    }
}

impl<M> Drop for OpenCleanup<M> {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send((self.abandon)(self.id));
        }
    }
}
