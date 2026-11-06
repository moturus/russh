use std::future::Future;
use std::pin::Pin;

use tokio::sync::mpsc::{OwnedPermit, Sender, error::SendError, error::TrySendError};

use super::{Handler, Session};
use crate::{ChannelId, ChannelMsg, Error};

type Permit = Result<OwnedPermit<ChannelMsg>, SendError<()>>;

pub(super) enum Delivery {
    Ready(OwnedPermit<ChannelMsg>),
    Closed,
}

impl Delivery {
    pub(super) fn send(&mut self, message: ChannelMsg) {
        if let Self::Ready(permit) = std::mem::replace(self, Self::Closed) {
            permit.send(message);
        }
    }
}

pub(super) struct PendingChannelPacket {
    pub(super) channel: ChannelId,
    packet: Vec<u8>,
    pub(super) permit: Pin<Box<dyn Future<Output = Permit> + Send>>,
}

impl std::fmt::Debug for PendingChannelPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingChannelPacket")
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Reserve before processing the packet, so a deferred packet has neither
    /// changed protocol state nor invoked a callback. Only one can be pending.
    pub(super) fn reserve_delivery(&mut self, channel: ChannelId, packet: &[u8]) -> Option<Delivery> {
        let Some(sender) = self.channels.get(&channel) else {
            return Some(Delivery::Closed);
        };
        let sender: Sender<ChannelMsg> = std::ops::Deref::deref(sender).clone();
        match sender.try_reserve_owned() {
            Ok(permit) => Some(Delivery::Ready(permit)),
            Err(TrySendError::Closed(_)) => Some(Delivery::Closed),
            Err(TrySendError::Full(sender)) => {
                self.pending_channel_packet = Some(PendingChannelPacket {
                    channel,
                    packet: packet.to_vec(),
                    permit: Box::pin(sender.reserve_owned()),
                });
                None
            }
        }
    }

    pub(super) async fn complete_channel_packet<H: Handler>(
        &mut self,
        handler: &mut H,
        permit: Permit,
    ) -> Result<(), H::Error> {
        let pending = self.pending_channel_packet.take().ok_or(Error::Inconsistent)?;
        let delivery = match permit {
            Ok(permit) => Delivery::Ready(permit),
            Err(_) => Delivery::Closed,
        };
        self.client_read_authenticated_with_slot(handler, &pending.packet, Some(delivery))
            .await
    }
}
