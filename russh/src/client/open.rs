use tokio::sync::{mpsc, oneshot};

use super::{ChannelRef, Handle, Handler, Msg, Session};
use crate::{Channel, ChannelId, Error, ReceiveCredit};

impl<H: Handler> Handle<H> {
    /// Open a forwarding channel with receive credit controlled by the caller.
    ///
    /// Manual accounting governs the first data packet, even if this future is
    /// not polled again after confirmation. Cancellation releases application
    /// state immediately; a pending protocol record lasts until the peer replies
    /// or disconnects, and a late success is closed.
    pub async fn channel_open_direct_tcpip_with_credit<A: Into<String>, B: Into<String>>(
        &self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<(Channel<Msg>, ReceiveCredit), Error> {
        let (sender, receiver) = mpsc::channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window = channel_ref.window_size().clone();
        let (credit, handoff) = oneshot::channel();
        self.sender
            .send(Msg::ChannelOpenDirectTcpIpWithCredit {
                host_to_connect: host_to_connect.into(),
                port_to_connect,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
                credit,
            })
            .await
            .map_err(|_| Error::SendError)?;
        // The queued value owns cleanup even before this receiver is polled.
        let handoff = handoff.await.map_err(|_| Error::Disconnect)?;
        let channel = self.wait_channel_confirmation(receiver, window).await?;
        Ok((channel, handoff.finish()))
    }
}

impl Session {
    pub(super) fn abandon_channel_open(&mut self, id: ChannelId) -> Result<(), Error> {
        self.channels.remove(&id);
        if self
            .pending_channel_packet
            .as_ref()
            .is_some_and(|pending| pending.channel == id)
        {
            self.pending_channel_packet = None;
        }
        let Some(parameters) = self
            .common
            .encrypted
            .as_mut()
            .and_then(|enc| enc.channels.get_mut(&id))
        else {
            return Ok(());
        };
        if parameters.confirmed {
            self.close(id)
        } else {
            // As in OpenSSH, keep the outstanding channel ID for its reply.
            // There is no application receiver, payload, or credit handoff left.
            parameters.application_consumed = None;
            Ok(())
        }
    }
}
