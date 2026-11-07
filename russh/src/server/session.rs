use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use channels::WindowSizeRef;
use kex::ServerKex;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{
    OwnedPermit, Receiver, Sender, UnboundedReceiver, UnboundedSender, channel,
};
use tokio::sync::oneshot;

use super::*;
use crate::channels::{Channel, ChannelMsg, ChannelReadHalf, ChannelRef, ChannelWriteHalf};
use crate::helpers::NameList;
use crate::kex::{EXTENSION_SUPPORT_AS_CLIENT, KexCause, SessionKexState};
use crate::{ChannelOpenFailure, ReceiveCredit, map_err, msg};

/// A connected server session. This type is unique to a client.
#[derive(Debug)]
pub struct Session {
    pub(crate) common: CommonSession<Arc<Config>>,
    pub(crate) sender: Handle,
    pub(crate) priority_receiver: UnboundedReceiver<Msg>,
    pub(crate) receiver: Receiver<Msg>,
    pub(crate) receive_credit_sender: tokio::sync::mpsc::UnboundedSender<ReceiveWindowEvent>,
    pub(crate) receive_credit_receiver: tokio::sync::mpsc::UnboundedReceiver<ReceiveWindowEvent>,
    pub(crate) pending_channel_data: Option<PendingChannelData>,
    pub(crate) target_window_size: u32,
    pub(crate) pending_reads: Vec<Vec<u8>>,
    pub(crate) pending_len: u32,
    pub(crate) channels: HashMap<ChannelId, ChannelRef>,
    pub(crate) open_global_requests: VecDeque<GlobalRequestResponse>,
    pub(crate) kex: SessionKexState<ServerKex>,
}

type ChannelPermit = Pin<
    Box<
        dyn Future<
                Output = Result<OwnedPermit<ChannelMsg>, tokio::sync::mpsc::error::SendError<()>>,
            > + Send,
    >,
>;

pub(crate) struct PendingChannelData {
    channel: ChannelId,
    data: bytes::Bytes,
    ext: Option<u32>,
    permit: ChannelPermit,
}

impl std::fmt::Debug for PendingChannelData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingChannelData")
            .field("channel", &self.channel)
            .field("data_len", &self.data.len())
            .field("ext", &self.ext)
            .finish_non_exhaustive()
    }
}

impl PendingChannelData {
    pub(crate) fn new(
        channel: ChannelId,
        data: bytes::Bytes,
        ext: Option<u32>,
        sender: Sender<ChannelMsg>,
    ) -> Self {
        Self {
            channel,
            data,
            ext,
            permit: Box::pin(sender.reserve_owned()),
        }
    }
}

#[derive(Debug)]
pub enum Msg {
    ChannelOpenAgent {
        channel_ref: ChannelRef,
    },
    ChannelOpenSession {
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectTcpIp {
        host_to_connect: String,
        port_to_connect: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    ChannelOpenDirectStreamLocal {
        socket_path: String,
        channel_ref: ChannelRef,
    },
    ChannelOpenForwardedTcpIp {
        connected_address: String,
        connected_port: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    #[doc(hidden)]
    ChannelOpenForwardedTcpIpWithCredit {
        connected_address: String,
        connected_port: u32,
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
        credit: oneshot::Sender<PendingChannelCredit>,
    },
    #[doc(hidden)]
    AbandonChannelOpen { id: ChannelId },
    ChannelOpenForwardedStreamLocal {
        server_socket_path: String,
        channel_ref: ChannelRef,
    },
    ChannelOpenX11 {
        originator_address: String,
        originator_port: u32,
        channel_ref: ChannelRef,
    },
    TcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
        address: String,
        port: u32,
    },
    CancelTcpIpForward {
        /// Provide a channel for the reply result to request a reply from the server
        reply_channel: Option<oneshot::Sender<bool>>,
        address: String,
        port: u32,
    },
    Disconnect {
        reason: crate::Disconnect,
        description: String,
        language_tag: String,
    },
    Channel(ChannelId, ChannelMsg),
    ChannelOpenReply {
        pending: PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    },
}

impl From<(ChannelId, ChannelMsg)> for Msg {
    fn from((id, msg): (ChannelId, ChannelMsg)) -> Self {
        Msg::Channel(id, msg)
    }
}

pub use crate::PendingChannelOpen;

#[doc(hidden)]
pub type PendingChannelCredit = crate::channels::PendingChannelCredit<Msg>;

/// A handle passed to channel-open callbacks that the handler uses to
/// accept or reject the incoming channel request.
///
/// Dropping the handle without calling [`accept`](ChannelOpenHandle::accept) or
/// [`reject`](ChannelOpenHandle::reject) automatically sends an
/// `AdministrativelyProhibited` rejection to the client.
pub type ChannelOpenHandle = crate::ChannelOpenHandleInner<Msg>;

#[derive(Clone, Debug)]
/// Handle to a session, used to send messages to a client outside of
/// the request/response cycle.
pub struct Handle {
    pub(crate) priority_sender: UnboundedSender<Msg>,
    pub(crate) sender: Sender<Msg>,
    pub(crate) channel_buffer_size: usize,
}

impl Handle {
    /// Send data to the session referenced by this handler.
    pub async fn data(
        &self,
        id: ChannelId,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        let data = data.into();
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Data { data }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::Data { data }) => data,
                _ => unreachable!(),
            })
    }

    /// Send data to the session referenced by this handler.
    pub async fn extended_data(
        &self,
        id: ChannelId,
        ext: u32,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), bytes::Bytes> {
        let data = data.into();
        self.sender
            .send(Msg::Channel(id, ChannelMsg::ExtendedData { ext, data }))
            .await
            .map_err(|e| match e.0 {
                Msg::Channel(_, ChannelMsg::ExtendedData { data, .. }) => data,
                _ => unreachable!(),
            })
    }

    /// Send EOF to the session referenced by this handler.
    pub async fn eof(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Eof))
            .await
            .map_err(|_| ())
    }

    /// Send success to the session referenced by this handler.
    pub async fn channel_success(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Success))
            .await
            .map_err(|_| ())
    }

    /// Send failure to the session referenced by this handler.
    pub async fn channel_failure(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Failure))
            .await
            .map_err(|_| ())
    }

    /// Close a channel.
    pub async fn close(&self, id: ChannelId) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::Close))
            .await
            .map_err(|_| ())
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub async fn xon_xoff_request(&self, id: ChannelId, client_can_do: bool) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::XonXoff { client_can_do }))
            .await
            .map_err(|_| ())
    }

    /// Send the exit status of a program.
    pub async fn exit_status_request(&self, id: ChannelId, exit_status: u32) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(id, ChannelMsg::ExitStatus { exit_status }))
            .await
            .map_err(|_| ())
    }

    /// Notifies the client that it can open TCP/IP forwarding channels for a port.
    pub async fn forward_tcpip(&self, address: String, port: u32) -> Result<u32, ()> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::TcpIpForward {
                reply_channel: Some(reply_send),
                address,
                port,
            })
            .await
            .map_err(|_| ())?;

        match reply_recv.await {
            Ok(Some(port)) => Ok(port),
            Ok(None) => Err(()), // crate::Error::RequestDenied
            Err(e) => {
                error!("Unable to receive TcpIpForward result: {e:?}");
                Err(()) // crate::Error::Disconnect
            }
        }
    }

    /// Notifies the client that it can no longer open TCP/IP forwarding channel for a port.
    pub async fn cancel_forward_tcpip(&self, address: String, port: u32) -> Result<(), ()> {
        let (reply_send, reply_recv) = oneshot::channel();
        self.sender
            .send(Msg::CancelTcpIpForward {
                reply_channel: Some(reply_send),
                address,
                port,
            })
            .await
            .map_err(|_| ())?;
        match reply_recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(()), // crate::Error::RequestDenied
            Err(e) => {
                error!("Unable to receive CancelTcpIpForward result: {e:?}");
                Err(()) // crate::Error::Disconnect
            }
        }
    }

    /// Open an agent forwarding channel. This can be used once the client has
    /// confirmed that it allows agent forwarding. See
    /// [PROTOCOL.agent](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent).
    pub async fn channel_open_agent(&self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenAgent { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;

        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Request a session channel (the most basic type of
    /// channel). This function returns `Ok(..)` immediately if the
    /// connection is authenticated, but the channel only becomes
    /// usable when it's confirmed by the server, as indicated by the
    /// `confirmed` field of the corresponding `Channel`.
    pub async fn channel_open_session(&self) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenSession { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;

        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a TCP/IP forwarding channel. This is usually done when a
    /// connection comes to a locally forwarded TCP/IP port. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub async fn channel_open_direct_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        host_to_connect: A,
        port_to_connect: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectTcpIp {
                host_to_connect: host_to_connect.into(),
                port_to_connect,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a direct streamlocal (Unix domain socket) channel on the client.
    pub async fn channel_open_direct_streamlocal<A: Into<String>>(
        &self,
        socket_path: A,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenDirectStreamLocal {
                socket_path: socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_forwarded_tcpip<A: Into<String>, B: Into<String>>(
        &self,
        connected_address: A,
        connected_port: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenForwardedTcpIp {
                connected_address: connected_address.into(),
                connected_port,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    /// Open a forwarding channel with receive credit controlled by the caller.
    ///
    /// Manual accounting governs the first data packet, even if this future is
    /// not polled again after confirmation. Cancellation releases application
    /// state immediately; a pending protocol record lasts until the peer replies
    /// or disconnects, and a late success is closed.
    pub async fn channel_open_forwarded_tcpip_with_credit<A: Into<String>, B: Into<String>>(
        &self,
        connected_address: A,
        connected_port: u32,
        originator_address: B,
        originator_port: u32,
    ) -> Result<(Channel<Msg>, ReceiveCredit), Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window = channel_ref.window_size().clone();
        let (credit, handoff) = oneshot::channel();
        self.sender
            .send(Msg::ChannelOpenForwardedTcpIpWithCredit {
                connected_address: connected_address.into(),
                connected_port,
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
                credit,
            })
            .await
            .map_err(|_| Error::SendError)?;
        let handoff = handoff.await.map_err(|_| Error::Disconnect)?;
        let channel = self.wait_channel_confirmation(receiver, window).await?;
        Ok((channel, handoff.finish()))
    }

    pub async fn channel_open_forwarded_streamlocal<A: Into<String>>(
        &self,
        server_socket_path: A,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenForwardedStreamLocal {
                server_socket_path: server_socket_path.into(),
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    pub async fn channel_open_x11<A: Into<String>>(
        &self,
        originator_address: A,
        originator_port: u32,
    ) -> Result<Channel<Msg>, Error> {
        let (sender, receiver) = channel(self.channel_buffer_size);
        let channel_ref = ChannelRef::new(sender);
        let window_size_ref = channel_ref.window_size().clone();

        self.sender
            .send(Msg::ChannelOpenX11 {
                originator_address: originator_address.into(),
                originator_port,
                channel_ref,
            })
            .await
            .map_err(|_| Error::SendError)?;
        self.wait_channel_confirmation(receiver, window_size_ref)
            .await
    }

    async fn wait_channel_confirmation(
        &self,
        mut receiver: Receiver<ChannelMsg>,
        window_size_ref: WindowSizeRef,
    ) -> Result<Channel<Msg>, Error> {
        loop {
            match receiver.recv().await {
                Some(ChannelMsg::Open {
                    id,
                    max_packet_size,
                    window_size,
                }) => {
                    window_size_ref.grow(window_size).await;

                    return Ok(Channel {
                        write_half: ChannelWriteHalf {
                            id,
                            sender: self.sender.clone(),
                            max_packet_size,
                            window_size: window_size_ref,
                        },
                        read_half: ChannelReadHalf { receiver },
                    });
                }
                Some(ChannelMsg::OpenFailure(reason)) => {
                    return Err(Error::ChannelOpenFailure(reason));
                }
                None => {
                    return Err(Error::Disconnect);
                }
                msg => {
                    debug!("msg = {msg:?}");
                }
            }
        }
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub async fn exit_signal_request(
        &self,
        id: ChannelId,
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    ) -> Result<(), ()> {
        self.sender
            .send(Msg::Channel(
                id,
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                },
            ))
            .await
            .map_err(|_| ())
    }

    /// Allows a server to disconnect a client session
    pub async fn disconnect(
        &self,
        reason: Disconnect,
        description: String,
        language_tag: String,
    ) -> Result<(), Error> {
        self.sender
            .send(Msg::Disconnect {
                reason,
                description,
                language_tag,
            })
            .await
            .map_err(|_| Error::SendError)
    }
}

impl Session {
    fn maybe_decompress(&mut self, buffer: &SSHBuffer) -> Result<IncomingSshPacket, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let mut decomp = Vec::new();
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: enc.decompress.decompress(
                    &buffer.buffer[5..],
                    &mut decomp,
                )?.into(),
                seqn: buffer.seqn,
            })
        } else {
            Ok(IncomingSshPacket {
                #[allow(clippy::indexing_slicing)] // length checked
                buffer: buffer.buffer[5..].into(),
                seqn: buffer.seqn,
            })
        }
    }

    /// Dispatch a single message received on the session's internal channel
    /// (sent via [`Handle`]). Shared by the `select!` receiver arm and the
    /// pre-`select!` backlog drain so the two can't drift apart.
    fn dispatch_msg(&mut self, msg: Msg) -> Result<(), Error> {
        match msg {
            Msg::Channel(id, ChannelMsg::Data { data }) => {
                self.data(id, data)?;
            }
            Msg::Channel(id, ChannelMsg::ExtendedData { ext, data }) => {
                self.extended_data(id, ext, data)?;
            }
            Msg::Channel(id, ChannelMsg::Eof) => {
                self.eof(id)?;
            }
            Msg::Channel(id, ChannelMsg::Close) => {
                self.close(id)?;
            }
            Msg::Channel(id, ChannelMsg::Success) => {
                self.channel_success(id)?;
            }
            Msg::Channel(id, ChannelMsg::Failure) => {
                self.channel_failure(id)?;
            }
            Msg::Channel(id, ChannelMsg::XonXoff { client_can_do }) => {
                self.xon_xoff_request(id, client_can_do)?;
            }
            Msg::Channel(id, ChannelMsg::ExitStatus { exit_status }) => {
                self.exit_status_request(id, exit_status)?;
            }
            Msg::Channel(
                id,
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                },
            ) => {
                self.exit_signal_request(id, signal_name, core_dumped, &error_message, &lang_tag)?;
            }
            Msg::Channel(id, ChannelMsg::WindowAdjusted { new_size }) => {
                debug!("window adjusted to {new_size:?} for channel {id:?}");
            }
            Msg::ChannelOpenAgent { channel_ref } => {
                let id = self.channel_open_agent()?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenSession { channel_ref } => {
                let id = self.channel_open_session()?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenDirectTcpIp {
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_direct_tcpip(
                    &host_to_connect,
                    port_to_connect,
                    &originator_address,
                    originator_port,
                )?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenDirectStreamLocal {
                socket_path,
                channel_ref,
            } => {
                let id = self.channel_open_direct_streamlocal(&socket_path)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenForwardedTcpIp {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_forwarded_tcpip(
                    &connected_address,
                    connected_port,
                    &originator_address,
                    originator_port,
                )?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenForwardedTcpIpWithCredit {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
                channel_ref,
                credit,
            } => {
                if channel_ref.is_closed() || credit.is_closed() {
                    return Ok(());
                }
                let id = self.channel_open_forwarded_tcpip(
                    &connected_address,
                    connected_port,
                    &originator_address,
                    originator_port,
                )?;
                let receive_credit = self.receive_credit(id).ok_or(Error::Inconsistent)?;
                self.channels.insert(id, channel_ref);
                let handoff = PendingChannelCredit::new(
                    id,
                    self.sender.priority_sender.clone(),
                    receive_credit,
                    |id| Msg::AbandonChannelOpen { id },
                );
                // A queued, unpolled handoff still owns cancellation cleanup.
                let _ = credit.send(handoff);
            }
            Msg::AbandonChannelOpen { id } => self.abandon_channel_open(id)?,
            Msg::ChannelOpenForwardedStreamLocal {
                server_socket_path,
                channel_ref,
            } => {
                let id = self.channel_open_forwarded_streamlocal(&server_socket_path)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::ChannelOpenX11 {
                originator_address,
                originator_port,
                channel_ref,
            } => {
                let id = self.channel_open_x11(&originator_address, originator_port)?;
                self.channels.insert(id, channel_ref);
            }
            Msg::TcpIpForward {
                address,
                port,
                reply_channel,
            } => {
                self.tcpip_forward(&address, port, reply_channel)?;
            }
            Msg::CancelTcpIpForward {
                address,
                port,
                reply_channel,
            } => {
                self.cancel_tcpip_forward(&address, port, reply_channel)?;
            }
            Msg::Disconnect {
                reason,
                description,
                language_tag,
            } => {
                self.common
                    .disconnect(reason, &description, &language_tag)?;
            }
            Msg::ChannelOpenReply { pending, result } => {
                self.finalize_channel_open_reply(pending, result)?;
            }
            other => {
                // should be unreachable, since the receiver only gets
                // messages from methods implemented within russh
                unimplemented!("unimplemented (client-only?) message: {other:?}")
            }
        }
        Ok(())
    }

    fn abandon_channel_open(&mut self, id: ChannelId) -> Result<(), Error> {
        self.channels.remove(&id);
        if self.pending_channel_data.as_ref().is_some_and(|pending| pending.channel == id) {
            self.pending_channel_data = None;
        }
        let Some(parameters) = self.common.encrypted.as_mut()
            .and_then(|enc| enc.channels.get_mut(&id)) else { return Ok(()); };
        if parameters.confirmed {
            self.close(id)
        } else {
            parameters.open_abandoned = true;
            parameters.application_consumed = None;
            Ok(())
        }
    }

    /// Put a channel's receive window under application control.
    ///
    /// Russh then returns window credit only after the application reports
    /// consuming bytes through the returned handle. Repeated calls share the
    /// same accounting state. This is available during a `channel_open_*`
    /// callback, before russh confirms the channel and exposes its initial
    /// window to the peer. Dropping every handle restores automatic mode.
    pub fn receive_credit(&mut self, channel: ChannelId) -> Option<ReceiveCredit> {
        let params = self.common.encrypted.as_mut()?.channels.get_mut(&channel)?;
        Some(ReceiveCredit::new(params.application_receive_credit(
            self.receive_credit_sender.clone(),
        )))
    }

    fn flush_receive_credit(&mut self, channel: ChannelId) -> Result<bool, Error> {
        match self.common.encrypted.as_mut() {
            Some(enc) => enc.flush_receive_credit(channel, self.target_window_size),
            None => Ok(false),
        }
    }

    pub(crate) fn replenish_receive_window<H: Handler>(
        &mut self,
        handler: &mut H,
        channel: ChannelId,
    ) -> Result<(), Error> {
        if let Some(encrypted) = self.common.encrypted.as_mut() {
            if encrypted.refill_receive_window(channel, self.target_window_size)? {
                let window = handler.adjust_window(channel, self.target_window_size);
                if window > 0 {
                    self.target_window_size = window;
                }
            }
            encrypted.flush_receive_credit(channel, self.target_window_size)?;
        }
        Ok(())
    }

    async fn complete_pending_channel_data<H: Handler + Send>(
        &mut self,
        handler: &mut H,
        permit: Result<OwnedPermit<ChannelMsg>, tokio::sync::mpsc::error::SendError<()>>,
    ) -> Result<(), H::Error> {
        let Some(pending) = self.pending_channel_data.take() else {
            return Err(Error::Inconsistent.into());
        };
        if let Ok(permit) = permit {
            let message = match pending.ext {
                Some(ext) => ChannelMsg::ExtendedData {
                    ext,
                    data: pending.data.clone(),
                },
                None => ChannelMsg::Data {
                    data: pending.data.clone(),
                },
            };
            permit.send(message);
        }
        self.replenish_receive_window(handler, pending.channel)?;
        self.flush()?;
        match pending.ext {
            Some(ext) => {
                handler
                    .extended_data(pending.channel, ext, &pending.data, self)
                    .await
            }
            None => handler.data(pending.channel, &pending.data, self).await,
        }
    }

    pub(crate) async fn run<H, R>(
        mut self,
        mut stream: SshRead<R>,
        mut handler: H,
    ) -> Result<(), H::Error>
    where
        H: Handler + Send + 'static,
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.flush()?;

        map_err!(self.common.packet_writer.flush_into(&mut stream).await)?;

        let (stream_read, mut stream_write) = stream.split();
        let buffer = SSHBuffer::new();

        // Allow handing out references to the cipher
        let mut opening_cipher = Box::new(clear::Key) as Box<dyn OpeningKey + Send>;
        std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

        let keepalive_timer =
            future_or_pending(self.common.config.keepalive_interval, tokio::time::sleep);
        pin!(keepalive_timer);

        let inactivity_timer =
            future_or_pending(self.common.config.inactivity_timeout, tokio::time::sleep);
        pin!(inactivity_timer);

        let reading = start_reading(stream_read, buffer, opening_cipher);
        pin!(reading);
        let mut is_reading = None;

        #[allow(clippy::panic)] // false positive in macro
        while !self.common.disconnected {
            self.common.received_data = false;
            let mut sent_keepalive = false;

            // Drain messages already queued on the session channel (e.g. shell
            // output pushed via `Handle::data()` from a spawned task) before
            // blocking in `select!`. `select!` only handles one queued message
            // per loop iteration, so a task producing faster than the loop
            // drains falls behind. Capped so high-rate output can't starve
            // client input (Ctrl+C, resize): once the cap is hit we fall through
            // to `select!`, which picks up any client-side event first. Gated on
            // `!kex.active()` to match the `select!` receiver arm.
            const MAX_MESSAGES_PER_BATCH: usize = 64;
            // Leave application messages in the bounded receiver once a peer's
            // channel window is exhausted. Network reads remain active so a
            // window adjustment can release the queued data.
            if !self.kex.active() && !self.common.has_any_pending_data() {
                let mut drained = 0;
                while drained < MAX_MESSAGES_PER_BATCH {
                    // Only Empty/Disconnected end the drain; both mean "nothing
                    // more to hand off right now", so treat them the same.
                    let msg = match self.priority_receiver.try_recv() {
                        Ok(msg) => msg,
                        Err(_) => match self.receiver.try_recv() {
                            Ok(msg) => msg,
                            Err(_) => break,
                        },
                    };
                    self.dispatch_msg(msg)?;
                    drained += 1;
                    if self.common.has_any_pending_data() {
                        break;
                    }
                }
                if drained > 0 {
                    self.flush()?;
                    crate::flush_or_timeout(
                        &mut self.common.packet_writer,
                        &mut stream_write,
                        inactivity_timer.as_mut(),
                    )
                    .await?;
                }
                // A drained Disconnect sets this; don't block in `select!` after.
                if self.common.disconnected {
                    continue;
                }
            }

            let rekey_timer = future_or_pending(self.rekey_time_remaining(), tokio::time::sleep);
            pin!(rekey_timer);

            let has_pending_channel_data = self.pending_channel_data.is_some();
            tokio::select! {
                r = &mut reading, if !has_pending_channel_data => {
                    let (stream_read, mut buffer, mut opening_cipher) = match r {
                        Ok((_, stream_read, buffer, opening_cipher)) => (stream_read, buffer, opening_cipher),
                        Err(e) => return Err(e.into())
                    };
                    if buffer.buffer.len() < 5 {
                        is_reading = Some((stream_read, buffer, opening_cipher));
                        break
                    }

                    let mut pkt = self.maybe_decompress(&buffer)?;

                    match pkt.buffer.first() {
                        None => (),
                        Some(&crate::msg::DISCONNECT) => {
                            debug!("break");
                            is_reading = Some((stream_read, buffer, opening_cipher));
                            break;
                        }
                        Some(_) => {
                            self.common.received_data = true;
                            // TODO it'd be cleaner to just pass cipher to reply()
                            std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);

                            let kex_was_active = self.kex.active();
                            match reply(&mut self, &mut handler, &mut pkt).await {
                                Ok(_) => {},
                                Err(e) => return Err(e),
                            }
                            buffer.seqn = pkt.seqn; // TODO reply changes seqn internall, find cleaner way

                            if kex_was_active && !self.kex.active() {
                                buffer.bytes = 0;
                            } else if self.automatic_rekey_allowed()
                                && buffer.bytes >= self.common.config.limits.rekey_read_limit
                            {
                                debug!("rekey read limit reached after {} inbound bytes", buffer.bytes);
                                if let Some(enc) = self.common.encrypted.as_mut() {
                                    // flush checks this
                                    enc.rekey_wanted = true;
                                }
                            }

                            std::mem::swap(&mut opening_cipher, &mut self.common.remote_to_local);
                        }
                    }
                    reading.set(start_reading(stream_read, buffer, opening_cipher));
                }
                () = &mut rekey_timer => {
                    // The flush after the select sees the elapsed limit.
                    debug!("rekey time limit reached");
                }
                () = &mut keepalive_timer => {
                    self.common.alive_timeouts = self.common.alive_timeouts.saturating_add(1);
                    if self.common.config.keepalive_max != 0 && self.common.alive_timeouts > self.common.config.keepalive_max {
                        debug!("Timeout, client not responding to keepalives");
                        return Err(crate::Error::KeepaliveTimeout.into());
                    }
                    sent_keepalive = true;
                    self.keepalive_request()?;
                }
                () = &mut inactivity_timer => {
                    debug!("timeout");
                    return Err(crate::Error::InactivityTimeout.into());
                }
                msg = self.priority_receiver.recv(), if !self.kex.active() => {
                    match msg {
                        Some(msg) => self.dispatch_msg(msg)?,
                        None => {
                            debug!("self.priority_receiver: received None");
                        }
                    }
                }
                msg = self.receiver.recv(), if !self.kex.active() && !self.common.has_any_pending_data() => {
                    // Channel open replies must be dispatched before any
                    // channel traffic queued after them: `msg` may be data for
                    // a channel whose confirmation is still sitting in the
                    // priority queue, and dispatching that data first would
                    // silently drop it (the channel is only registered when
                    // its open reply is processed).
                    while let Ok(reply) = self.priority_receiver.try_recv() {
                        self.dispatch_msg(reply)?;
                    }
                    match msg {
                        Some(msg) => self.dispatch_msg(msg)?,
                        None => {
                            debug!("self.receiver: received None");
                        }
                    }
                }
                event = self.receive_credit_receiver.recv(), if !self.kex.active() => {
                    match event {
                        Some(ReceiveWindowEvent::Credit(channel)) => {
                            self.flush_receive_credit(channel)?;
                        }
                        Some(ReceiveWindowEvent::AbandonedOpen(channel)) => {
                            if let Some(encrypted) = self.common.encrypted.as_mut() {
                                encrypted.channels.remove(&channel);
                            }
                        }
                        None => {}
                    }
                }
                permit = future_or_pending(
                    self.pending_channel_data.as_mut(),
                    |pending| pending.permit.as_mut(),
                ), if has_pending_channel_data => {
                    self.complete_pending_channel_data(&mut handler, permit).await?;
                }
            }
            self.flush()?;

            crate::flush_or_timeout(
                &mut self.common.packet_writer,
                &mut stream_write,
                inactivity_timer.as_mut(),
            )
            .await?;

            if self.common.received_data {
                // Reset the number of failed keepalive attempts. We don't
                // bother detecting keepalive response messages specifically
                // (OpenSSH_9.6p1 responds with REQUEST_FAILURE aka 82). Instead
                // we assume that the client is still alive if we receive any
                // data from it.
                self.common.alive_timeouts = 0;
            }
            if (self.common.received_data || sent_keepalive)
                && let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    keepalive_timer.as_mut().as_pin_mut(),
                    self.common.config.keepalive_interval,
                )
            {
                sleep.as_mut().reset(tokio::time::Instant::now() + d);
            }
            if !sent_keepalive
                && let (futures::future::Either::Right(ref mut sleep), Some(d)) = (
                    inactivity_timer.as_mut().as_pin_mut(),
                    self.common.config.inactivity_timeout,
                )
            {
                sleep.as_mut().reset(tokio::time::Instant::now() + d);
            }
        }
        debug!("disconnected");
        // Shutdown
        map_err!(stream_write.shutdown().await)?;
        loop {
            if let Some((stream_read, buffer, opening_cipher)) = is_reading.take() {
                reading.set(start_reading(stream_read, buffer, opening_cipher));
            }
            tokio::select! {
                r = &mut reading => match r {
                    Ok((0, _, _, _)) => break,
                    Ok((_, r, b, opening_cipher)) => {
                        is_reading = Some((r, b, opening_cipher));
                    }
                    // at this stage of session shutdown, EOF is not unexpected
                    Err(Error::IO(ref e)) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e.into()),
                },
                // The client was told to disconnect and never closed its side;
                // dropping the stream closes it for them.
                () = &mut inactivity_timer => {
                    debug!("timeout waiting for the client to close");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Get a handle to this session.
    pub fn handle(&self) -> Handle {
        self.sender.clone()
    }

    pub fn writable_packet_size(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get(channel)
        {
            return channel
                .sender_window_size
                .min(channel.sender_maximum_packet_size);
        }
        0
    }

    pub fn window_size(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get(channel)
        {
            return channel.sender_window_size;
        }
        0
    }

    pub fn max_packet_size(&self, channel: &ChannelId) -> u32 {
        if let Some(ref enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get(channel)
        {
            return channel.sender_maximum_packet_size;
        }
        0
    }

    /// Flush the session, i.e. encrypt the pending buffer.
    pub fn flush(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            // Tearing down: get the queued packets (incl. DISCONNECT) out in
            // order, kex or not.
            let is_rekeying = self.kex.active() && !self.common.disconnected;
            if enc.flush(
                &self.common.config.as_ref().limits,
                &mut self.common.packet_writer,
                is_rekeying,
            )? && self.kex == SessionKexState::Idle
                && Self::automatic_rekey_eligible(&enc.state)
            {
                debug!("starting rekeying");
                if enc.exchange.take().is_some() {
                    // USERAUTH_SUCCESS was just flushed with the pre-authentication
                    // compression state. If automatic rekeying is the first
                    // post-authentication traffic, activate delayed server
                    // compression before emitting KEXINIT, just as the next peer
                    // packet would normally do.
                    if matches!(enc.state, EncryptedState::InitCompression) {
                        if enc.server_compression.is_deferred() {
                            enc.server_compression
                                .init_compress(self.common.packet_writer.compress());
                        }
                        enc.state = EncryptedState::Authenticated;
                    }
                    self.begin_rekey()?;
                }
            }
        }
        Ok(())
    }

    /// `InitCompression` counts: USERAUTH_SUCCESS is flushed in that state and
    /// an idle peer never sends the packet that would advance it.
    fn automatic_rekey_eligible(state: &EncryptedState) -> bool {
        matches!(
            state,
            EncryptedState::InitCompression | EncryptedState::Authenticated
        )
    }

    /// Is a limit-triggered rekey allowed now? no kex in flight & authed
    fn automatic_rekey_allowed(&self) -> bool {
        !self.kex.active()
            && self
                .common
                .encrypted
                .as_ref()
                .is_some_and(|enc| Self::automatic_rekey_eligible(&enc.state))
    }

    fn rekey_time_remaining(&self) -> Option<Duration> {
        if !self.automatic_rekey_allowed() {
            return None;
        }
        self.common
            .encrypted
            .as_ref()?
            .rekey_time_remaining(&self.common.config.limits, &self.common.packet_writer)
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.flush_pending(channel)
        } else {
            Ok(0)
        }
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(ref enc) = self.common.encrypted {
            enc.sender_window_size(channel)
        } else {
            0
        }
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(ref enc) = self.common.encrypted {
            enc.has_pending_data(channel)
        } else {
            false
        }
    }

    /// Retrieves the configuration of this session.
    pub fn config(&self) -> &Config {
        &self.common.config
    }

    /// Sends a disconnect message.
    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.common.disconnect(reason, description, language_tag)
    }

    /// Sends a debug message to the client.
    ///
    /// Debug messages are intended for debugging purposes and may be
    /// optionally displayed by the client, depending on the
    /// `always_display` flag and client configuration.
    ///
    /// # Parameters
    ///
    /// - `always_display`: If `true`, the client is encouraged to
    ///   display the message regardless of user preferences.
    /// - `message`: The debug message to be sent.
    /// - `language_tag`: The language tag of the message.
    ///
    /// # Notes
    ///
    /// This message is informational and does not affect the SSH session
    /// state. Most clients (e.g., OpenSSH) will only display the message
    /// if verbose mode is enabled.
    pub fn debug(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        self.common.debug(always_display, message, language_tag)
    }

    /// Send a "success" reply to a /global/ request (requests without
    /// a channel number, such as TCP/IP forwarding or
    /// cancelling). Always call this function if the request was
    /// successful (it checks whether the client expects an answer).
    pub fn request_success(&mut self) {
        if self.common.wants_reply
            && let Some(ref mut enc) = self.common.encrypted
        {
            self.common.wants_reply = false;
            push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
        }
    }

    /// Send a "failure" reply to a global request (it checks whether the
    /// client expects an answer).
    pub fn request_failure(&mut self) {
        if self.common.wants_reply
            && let Some(ref mut enc) = self.common.encrypted
        {
            self.common.wants_reply = false;
            push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
        }
    }

    /// Send a "success" reply to a channel request. Always call this
    /// function if the request was successful (it checks whether the
    /// client expects an answer).
    pub fn channel_success(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get_mut(&channel)
        {
            assert!(channel.confirmed);
            if channel.wants_reply {
                channel.wants_reply = false;
                debug!("channel_success {channel:?}");
                push_packet!(enc.write, {
                    msg::CHANNEL_SUCCESS.encode(&mut enc.write)?;
                    channel.recipient_channel.encode(&mut enc.write)?;
                })
            }
        }
        Ok(())
    }

    /// Send a "failure" reply to a global request.
    pub fn channel_failure(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get_mut(&channel)
        {
            assert!(channel.confirmed);
            if channel.wants_reply {
                channel.wants_reply = false;
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_FAILURE);
                    channel.recipient_channel.encode(&mut enc.write)?;
                })
            }
        }
        Ok(())
    }

    fn finalize_channel_open_reply(
        &mut self,
        mut pending: PendingChannelOpen,
        result: Result<(), ChannelOpenFailure>,
    ) -> Result<(), Error> {
        if let Some(cleanup) = pending.channel_cleanup.take() {
            cleanup.disarm();
        }
        if let Some(ref mut enc) = self.common.encrypted {
            match result {
                Ok(()) => {
                    let Some(channel) = enc.channels.get_mut(&pending.sender_channel) else {
                        return Err(Error::Inconsistent);
                    };
                    channel.confirmed = true;
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN_CONFIRMATION.encode(&mut enc.write)?;
                        pending.recipient_channel.encode(&mut enc.write)?;
                        pending.sender_channel.0.encode(&mut enc.write)?;
                        pending.window_size.encode(&mut enc.write)?;
                        pending.packet_size.encode(&mut enc.write)?;
                    });
                    self.channels
                        .insert(pending.sender_channel, pending.channel_ref);
                }
                Err(reason) => {
                    enc.channels.remove(&pending.sender_channel);
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN_FAILURE.encode(&mut enc.write)?;
                        pending.recipient_channel.encode(&mut enc.write)?;
                        reason.code().encode(&mut enc.write)?;
                        reason.description().encode(&mut enc.write)?;
                        "en".encode(&mut enc.write)?;
                    });
                }
            }
        }
        Ok(())
    }

    /// Send a "failure" reply to a request to open a channel open.
    pub fn channel_open_failure(
        &mut self,
        channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        language: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN_FAILURE);
                channel.encode(&mut enc.write)?;
                reason.code().encode(&mut enc.write)?;
                description.encode(&mut enc.write)?;
                language.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Close a channel.
    pub fn close(&mut self, channel: ChannelId) -> Result<(), Error> {
        self.channels.remove(&channel);
        // A pending delivery also owns a sender that would keep the queue alive.
        if self
            .pending_channel_data
            .as_ref()
            .is_some_and(|p| p.channel == channel)
        {
            self.pending_channel_data = None;
        }
        if let Some(ref mut enc) = self.common.encrypted {
            enc.close(channel)
        } else {
            unreachable!()
        }
    }

    /// Send EOF to a channel
    pub fn eof(&mut self, channel: ChannelId) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.eof(channel)
        } else {
            unreachable!()
        }
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn data(&mut self, channel: ChannelId, data: impl Into<bytes::Bytes>) -> Result<(), Error> {
        let is_rekeying = self.kex.active();
        let common = &mut self.common;
        if let Some(enc) = common.encrypted.as_mut() {
            enc.data_with_writer(&mut common.packet_writer, channel, data, is_rekeying)
        } else {
            unreachable!()
        }
    }

    /// Send data to a channel. On session channels, `extended` can be
    /// used to encode standard error by passing `Some(1)`, and stdout
    /// by passing `None`.
    ///
    /// The number of bytes added to the "sending pipeline" (to be
    /// processed by the event loop) is returned.
    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        extended: u32,
        data: impl Into<bytes::Bytes>,
    ) -> Result<(), Error> {
        let is_rekeying = self.kex.active();
        let common = &mut self.common;
        if let Some(enc) = common.encrypted.as_mut() {
            enc.extended_data_with_writer(
                &mut common.packet_writer,
                channel,
                extended,
                data,
                is_rekeying,
            )
        } else {
            unreachable!()
        }
    }

    /// Inform the client of whether they may perform
    /// control-S/control-Q flow control. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.8).
    pub fn xon_xoff_request(
        &mut self,
        channel: ChannelId,
        client_can_do: bool,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get(&channel)
        {
            assert!(channel.confirmed);
            push_packet!(enc.write, {
                msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                channel.recipient_channel.encode(&mut enc.write)?;
                "xon-xoff".encode(&mut enc.write)?;
                0u8.encode(&mut enc.write)?;
                (client_can_do as u8).encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Ping the client to verify there is still connectivity.
    pub fn keepalive_request(&mut self) -> Result<(), Error> {
        let want_reply = u8::from(true);
        if let Some(ref mut enc) = self.common.encrypted {
            self.open_global_requests
                .push_back(GlobalRequestResponse::Keepalive);
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "keepalive@openssh.com".encode(&mut enc.write)?;
                want_reply.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Ping the client with a Keepalive and get a notification when the client responds.
    pub fn send_ping(&mut self, reply_channel: oneshot::Sender<()>) -> Result<(), Error> {
        let want_reply = u8::from(true);
        if let Some(ref mut enc) = self.common.encrypted {
            self.open_global_requests
                .push_back(GlobalRequestResponse::Ping(reply_channel));
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "keepalive@openssh.com".encode(&mut enc.write)?;
                want_reply.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Send the exit status of a program.
    pub fn exit_status_request(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get(&channel)
        {
            assert!(channel.confirmed);
            push_packet!(enc.write, {
                msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                channel.recipient_channel.encode(&mut enc.write)?;
                "exit-status".encode(&mut enc.write)?;
                0u8.encode(&mut enc.write)?;
                exit_status.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// If the program was killed by a signal, send the details about the signal to the client.
    pub fn exit_signal_request(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        core_dumped: bool,
        error_message: &str,
        language_tag: &str,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted
            && let Some(channel) = enc.channels.get(&channel)
        {
            assert!(channel.confirmed);
            push_packet!(enc.write, {
                msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                channel.recipient_channel.encode(&mut enc.write)?;
                "exit-signal".encode(&mut enc.write)?;
                0u8.encode(&mut enc.write)?;
                signal.name().encode(&mut enc.write)?;
                (core_dumped as u8).encode(&mut enc.write)?;
                error_message.encode(&mut enc.write)?;
                language_tag.encode(&mut enc.write)?;
            })
        }
        Ok(())
    }

    /// Opens a new session channel on the client.
    pub fn channel_open_session(&mut self) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"session", |_| Ok(()))
    }

    /// Opens a direct-tcpip channel on the client (non-standard).
    pub fn channel_open_direct_tcpip(
        &mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"direct-tcpip", |write| {
            host_to_connect.encode(write)?;
            port_to_connect.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    /// Opens a direct-streamlocal channel on the client (non-standard).
    pub fn channel_open_direct_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"direct-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?; // reserved
            0u32.encode(write)?; // reserved
            Ok(())
        })
    }

    /// Open a TCP/IP forwarding channel, when a connection comes to a
    /// local port for which forwarding has been requested. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The
    /// TCP/IP packets can then be tunneled through the channel using
    /// `.data()`.
    pub fn channel_open_forwarded_tcpip(
        &mut self,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"forwarded-tcpip", |write| {
            connected_address.encode(write)?;
            connected_port.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    pub fn channel_open_forwarded_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"forwarded-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?;
            Ok(())
        })
    }

    /// Open a new X11 channel, when a connection comes to a
    /// local port. See [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.2).
    /// TCP/IP packets can then be tunneled through the channel using `.data()`.
    pub fn channel_open_x11(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"x11", |write| {
            originator_address.encode(write)?;
            originator_port.encode(write)?;
            Ok(())
        })
    }

    /// Opens a new agent channel on the client.
    pub fn channel_open_agent(&mut self) -> Result<ChannelId, Error> {
        self.channel_open_generic(b"auth-agent@openssh.com", |_| Ok(()))
    }

    fn channel_open_generic<F>(&mut self, kind: &[u8], write_suffix: F) -> Result<ChannelId, Error>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<(), Error>,
    {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            if !matches!(
                enc.state,
                EncryptedState::Authenticated | EncryptedState::InitCompression
            ) {
                return Err(Error::Inconsistent);
            }

            let sender_channel = enc.new_channel(
                self.common.config.window_size,
                self.common.config.maximum_packet_size,
            );
            push_packet!(enc.write, {
                enc.write.push(msg::CHANNEL_OPEN);
                kind.encode(&mut enc.write)?;

                // sender channel id.
                sender_channel.encode(&mut enc.write)?;

                // window.
                self.common
                    .config
                    .as_ref()
                    .window_size
                    .encode(&mut enc.write)?;

                // max packet size.
                self.common
                    .config
                    .as_ref()
                    .maximum_packet_size
                    .encode(&mut enc.write)?;

                write_suffix(&mut enc.write)?;
            });
            sender_channel
        } else {
            return Err(Error::Inconsistent);
        };
        Ok(result)
    }

    /// Requests that the client forward connections to the given host and port.
    /// See [RFC4254](https://tools.ietf.org/html/rfc4254#section-7). The client
    /// will open forwarded_tcpip channels for each connection.
    pub fn tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::TcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                "tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Cancels a previously tcpip_forward request.
    pub fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        reply_channel: Option<oneshot::Sender<bool>>,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::CancelTcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "cancel-tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Returns the SSH ID (Protocol Version + Software Version) the client sent when connecting
    ///
    /// This should contain only ASCII characters for implementations conforming to RFC4253, Section 4.2:
    ///
    /// > Both the 'protoversion' and 'softwareversion' strings MUST consist of
    /// > printable US-ASCII characters, with the exception of whitespace
    /// > characters and the minus sign (-).
    ///
    /// So it usually is fine to convert it to a [`String`] using [`String::from_utf8_lossy`]
    pub fn remote_sshid(&self) -> &[u8] {
        &self.common.remote_sshid
    }

    pub(crate) fn maybe_send_ext_info(&mut self) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            // If client sent a ext-info-c message in the kex list, it supports RFC 8308 extension negotiation.
            let mut key_extension_client = false;
            if let Some(e) = &enc.exchange {
                let Some(mut r) = e.client_kex_init.get(17..) else {
                    return Ok(());
                };
                if let Ok(kex_list) = NameList::decode(&mut r) {
                    use super::negotiation::Select;
                    key_extension_client = super::negotiation::Server::select(
                        &[EXTENSION_SUPPORT_AS_CLIENT],
                        &kex_list,
                        AlgorithmKind::Kex,
                    )
                    .is_ok();
                }
            }

            if !key_extension_client {
                debug!("RFC 8308 Extension Negotiation not supported by client");
                return Ok(());
            }

            push_packet!(enc.write, {
                msg::EXT_INFO.encode(&mut enc.write)?;
                1u32.encode(&mut enc.write)?;
                "server-sig-algs".encode(&mut enc.write)?;

                NameList(
                    self.common
                        .config
                        .preferred
                        .key
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                )
                .encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    pub(crate) fn begin_rekey(&mut self) -> Result<(), Error> {
        debug!("beginning re-key");
        self.pending_len = 0;
        let mut kex = ServerKex::new(
            self.common.config.clone(),
            &self.common.remote_sshid,
            &self.common.config.server_id,
            match self.common.encrypted {
                None => KexCause::Initial,
                Some(ref enc) => KexCause::Rekey {
                    strict: self.common.strict_kex,
                    session_id: enc.session_id.clone(),
                },
            },
        );

        kex.kexinit(&mut self.common.packet_writer)?;
        self.kex = SessionKexState::InProgress(kex);
        Ok(())
    }
}

#[cfg(all(test, feature = "flate2"))]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::io::Write;
    use std::num::Wrapping;
    use std::sync::Arc;

    use futures::FutureExt;
    use ssh_encoding::Encode;

    use super::*;
    use crate::auth::{AuthRequest, MethodSet};
    use crate::compression::{Compress, Compression, Decompress};
    use crate::kex::{KEXES, NONE, SessionKexState};
    use crate::session::{CommonSession, Encrypted, EncryptedState, Exchange};
    use crate::sshbuffer::{IncomingSshPacket, PacketWriter, SSHBuffer};
    use crate::{CryptoVec, cipher, mac};

    struct TestHandler;

    impl crate::server::Handler for TestHandler {
        type Error = crate::Error;
    }

    struct AcceptNoneHandler;

    impl crate::server::Handler for AcceptNoneHandler {
        type Error = crate::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }
    }

    fn none_auth_request(user: &str) -> Vec<u8> {
        let mut packet = vec![crate::msg::USERAUTH_REQUEST];
        user.encode(&mut packet).unwrap();
        "ssh-connection".encode(&mut packet).unwrap();
        "none".encode(&mut packet).unwrap();
        packet
    }

    fn authenticated_session() -> Session {
        let config = Arc::new(crate::server::Config::default());
        let (priority_sender, priority_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (sender, receiver) = tokio::sync::mpsc::channel(config.event_buffer_size);
        let handle = Handle {
            priority_sender,
            sender,
            channel_buffer_size: config.channel_buffer_size,
        };
        let (receive_credit_sender, receive_credit_receiver) =
            tokio::sync::mpsc::unbounded_channel();

        Session {
            common: CommonSession {
                auth_user: String::new(),
                remote_sshid: b"SSH-2.0-test".to_vec(),
                config: config.clone(),
                encrypted: Some(Encrypted {
                    state: EncryptedState::Authenticated,
                    exchange: Some(Exchange::default()),
                    kex: KEXES.get(&NONE).unwrap().make(),
                    key: 0,
                    client_mac: mac::NONE,
                    server_mac: mac::NONE,
                    session_id: CryptoVec::new(),
                    channels: HashMap::new(),
                    last_channel_id: Wrapping(0),
                    write: Vec::new(),
                    write_cursor: 0,
                    last_rekey: russh_util::time::Instant::now(),
                    server_compression: Compression::None,
                    client_compression: Compression::None,
                    decompress: Decompress::Zlib(flate2::Decompress::new(true)),
                    rekey_wanted: false,
                    received_extensions: Vec::new(),
                    extension_info_awaiters: HashMap::new(),
                }),
                auth_method: None,
                auth_attempts: 0,
                packet_writer: PacketWriter::clear(),
                remote_to_local: Box::new(cipher::clear::Key),
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
            },
            sender: handle,
            priority_receiver,
            receiver,
            receive_credit_sender,
            receive_credit_receiver,
            pending_channel_data: None,
            target_window_size: config.window_size,
            pending_reads: Vec::new(),
            pending_len: 0,
            channels: HashMap::new(),
            open_global_requests: VecDeque::new(),
            kex: SessionKexState::Idle,
        }
    }

    fn manual_open_message() -> (Msg, Receiver<ChannelMsg>, oneshot::Receiver<PendingChannelCredit>) {
        let (sender, receiver) = channel(1);
        let (credit, handoff) = oneshot::channel();
        (Msg::ChannelOpenForwardedTcpIpWithCredit {
            connected_address: "localhost".into(), connected_port: 80,
            originator_address: "localhost".into(), originator_port: 1234,
            channel_ref: ChannelRef::new(sender), credit,
        }, receiver, handoff)
    }

    fn open_reply(id: ChannelId, confirmed: bool) -> Vec<u8> {
        let mut packet = vec![if confirmed { msg::CHANNEL_OPEN_CONFIRMATION } else { msg::CHANNEL_OPEN_FAILURE }];
        id.encode(&mut packet).unwrap();
        if confirmed {
            for value in [42u32, 1024, 128] { value.encode(&mut packet).unwrap(); }
        } else {
            2u32.encode(&mut packet).unwrap();
            "refused".encode(&mut packet).unwrap();
            "".encode(&mut packet).unwrap();
        }
        packet
    }

    #[tokio::test]
    async fn canceled_manual_open_before_dispatch_sends_nothing() {
        for drop_handoff in [false, true] {
            let mut session = authenticated_session();
            let (message, receiver, handoff) = manual_open_message();
            let mut receiver = Some(receiver);
            let mut handoff = Some(handoff);
            if drop_handoff { drop(handoff.take()); } else { drop(receiver.take()); }
            session.dispatch_msg(message).unwrap();
            assert!(session.channels.is_empty());
            let enc = session.common.encrypted.as_ref().unwrap();
            assert!(enc.channels.is_empty());
            assert!(enc.write.is_empty());
        }
    }

    #[tokio::test]
    async fn canceled_manual_open_retains_only_protocol_state_until_reply() {
        for confirmed in [false, true] {
            let mut session = authenticated_session();
            let (message, receiver, handoff) = manual_open_message();
            session.dispatch_msg(message).unwrap();
            let id = *session.channels.keys().next().unwrap();
            drop(receiver);
            drop(handoff);
            let cleanup = session.priority_receiver.try_recv().unwrap();
            session.dispatch_msg(cleanup).unwrap();
            assert!(session.channels.is_empty());
            let enc = session.common.encrypted.as_mut().unwrap();
            assert!(enc.channels[&id].open_abandoned);
            assert!(enc.channels[&id].application_consumed.is_none());
            assert!(enc.channels[&id].pending_data.is_empty());
            enc.write.clear();
            let packet = open_reply(id, confirmed);
            session.process_packet(&mut TestHandler, &packet).await.unwrap();
            let enc = session.common.encrypted.as_ref().unwrap();
            assert!(enc.channels.is_empty());
            if confirmed {
                assert_eq!(enc.write[4], msg::CHANNEL_CLOSE);
                assert_eq!(&enc.write[5..9], &42u32.to_be_bytes());
                assert!(matches!(session.process_packet(&mut TestHandler, &packet).await, Err(Error::Inconsistent)));
            } else {
                assert!(enc.write.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn canceled_confirmed_manual_open_releases_a_parked_packet() {
        let mut session = authenticated_session();
        let (message, receiver, handoff) = manual_open_message();
        session.dispatch_msg(message).unwrap();
        let id = *session.channels.keys().next().unwrap();
        session.process_packet(&mut TestHandler, &open_reply(id, true)).await.unwrap();
        let mut data = vec![msg::CHANNEL_DATA];
        id.encode(&mut data).unwrap();
        b"unread".as_slice().encode(&mut data).unwrap();
        session.process_packet(&mut TestHandler, &data).await.unwrap();
        assert!(session.pending_channel_data.is_some());
        drop(receiver);
        drop(handoff);
        let cleanup = session.priority_receiver.try_recv().unwrap();
        session.dispatch_msg(cleanup).unwrap();
        assert!(session.pending_channel_data.is_none());
        assert!(session.channels.is_empty());
        assert!(session.common.encrypted.as_ref().unwrap().channels.is_empty());
    }

    #[tokio::test]
    async fn callback_only_open_confirmation_keeps_the_channel_live() {
        struct CallbackOnly { confirmed: bool, received: Vec<u8> }
        impl Handler for CallbackOnly {
            type Error = Error;
            async fn channel_open_confirmation(
                &mut self, _: ChannelId, _: u32, _: u32, _: &mut Session,
            ) -> Result<(), Error> {
                self.confirmed = true;
                Ok(())
            }
            async fn data(&mut self, _: ChannelId, data: &[u8], _: &mut Session) -> Result<(), Error> {
                self.received.extend_from_slice(data);
                Ok(())
            }
        }
        let mut session = authenticated_session();
        let id = session.channel_open_forwarded_tcpip("localhost", 80, "localhost", 1234).unwrap();
        assert!(session.channels.is_empty());
        session.common.encrypted.as_mut().unwrap().write.clear();
        let mut handler = CallbackOnly { confirmed: false, received: Vec::new() };
        session.process_packet(&mut handler, &open_reply(id, true)).await.unwrap();
        assert!(handler.confirmed);
        let mut data = vec![msg::CHANNEL_DATA];
        id.encode(&mut data).unwrap();
        b"payload".as_slice().encode(&mut data).unwrap();
        session.process_packet(&mut handler, &data).await.unwrap();
        assert_eq!(handler.received, b"payload");
        let enc = session.common.encrypted.as_ref().unwrap();
        assert!(enc.channels[&id].confirmed);
        assert!(enc.write.is_empty());
    }

    #[tokio::test]
    async fn refusal_of_a_dropped_channel_receiver_keeps_the_transport_alive() {
        let mut session = authenticated_session();
        let (id, channel) = close_test_channel(&mut session, false);
        drop(channel);
        session.process_packet(&mut TestHandler, &open_reply(id, false)).await.unwrap();
        assert!(session.channels.is_empty());
        assert!(session.common.encrypted.as_ref().unwrap().channels.is_empty());
        assert!(!session.common.disconnected);
    }

    fn manual_window_channel(session: &mut Session) -> (ChannelId, ReceiveCredit) {
        session.target_window_size = 1024;
        let encrypted = session.common.encrypted.as_mut().unwrap();
        let channel = encrypted.new_channel(1024, 128);
        let params = encrypted.channels.get_mut(&channel).unwrap();
        params.recipient_channel = 17;
        params.confirmed = true;
        let credit = session.receive_credit(channel).unwrap();
        (channel, credit)
    }

    fn close_test_channel(session: &mut Session, confirmed: bool) -> (ChannelId, Channel<Msg>) {
        let enc = session.common.encrypted.as_mut().unwrap();
        let id = enc.new_channel(1024, 128);
        let params = enc.channels.get_mut(&id).unwrap();
        params.recipient_channel = 42;
        params.recipient_maximum_packet_size = 128;
        params.confirmed = confirmed;
        let (channel, reference) = Channel::new(id, session.sender.sender.clone(), 128, 0, 8);
        session.channels.insert(id, reference);
        (id, channel)
    }

    #[tokio::test]
    async fn peer_close_releases_starved_channel_after_received_data() {
        let mut session = authenticated_session();
        let (id, mut received) = close_test_channel(&mut session, true);
        session
            .data(id, bytes::Bytes::from_static(b"unsent"))
            .unwrap();
        assert!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .has_any_pending_data()
        );
        session.channels[&id]
            .send(ChannelMsg::Data {
                data: bytes::Bytes::from_static(b"received"),
            })
            .await
            .unwrap();
        let mut packet = vec![msg::CHANNEL_CLOSE];
        id.encode(&mut packet).unwrap();

        session
            .process_packet(&mut TestHandler, &packet)
            .await
            .unwrap();
        let enc = session.common.encrypted.as_ref().unwrap();
        assert!(!enc.has_any_pending_data());
        assert!(!enc.channels.contains_key(&id));
        assert!(!session.channels.contains_key(&id));
        assert_eq!(enc.write[4], msg::CHANNEL_CLOSE);
        assert!(
            matches!(received.wait().await, Some(ChannelMsg::Data { data }) if data.as_ref() == b"received")
        );
        assert!(matches!(received.wait().await, Some(ChannelMsg::Close)));
        assert!(received.wait().await.is_none());

        let written = enc.write.clone();
        session
            .process_packet(&mut TestHandler, &packet)
            .await
            .unwrap();
        assert_eq!(session.common.encrypted.as_ref().unwrap().write, written);
    }

    #[tokio::test]
    async fn peer_close_keeps_unconfirmed_open() {
        let mut session = authenticated_session();
        let (id, mut received) = close_test_channel(&mut session, false);
        let mut packet = vec![msg::CHANNEL_CLOSE];
        id.encode(&mut packet).unwrap();

        session
            .process_packet(&mut TestHandler, &packet)
            .await
            .unwrap();
        assert!(session.channels.contains_key(&id));
        let enc = session.common.encrypted.as_ref().unwrap();
        assert!(enc.channels.contains_key(&id));
        assert!(enc.write.is_empty());
        assert!(received.wait().now_or_never().is_none());
    }

    #[tokio::test]
    async fn repeated_closes_release_queues_without_waiting_for_ack() {
        let mut session = authenticated_session();
        for peer_first in [false, true] {
            for _ in 0..256 {
                let (id, mut received) = close_test_channel(&mut session, true);
                let payload = bytes::Bytes::from(vec![42; 256]);
                session.channels[&id]
                    .send(ChannelMsg::Data {
                        data: payload.clone(),
                    })
                    .await
                    .unwrap();
                if peer_first {
                    let mut packet = vec![msg::CHANNEL_CLOSE];
                    id.encode(&mut packet).unwrap();
                    session
                        .process_packet(&mut TestHandler, &packet)
                        .await
                        .unwrap();
                } else {
                    // No peer reply is delivered anywhere in this path.
                    session.close(id).unwrap();
                }
                assert!(session.channels.is_empty());
                let enc = session.common.encrypted.as_mut().unwrap();
                assert!(enc.channels.is_empty());
                enc.write.clear();
                assert!(
                    matches!(received.wait().await, Some(ChannelMsg::Data { data }) if data == payload)
                );
                if peer_first {
                    assert!(matches!(received.wait().await, Some(ChannelMsg::Close)));
                }
                // Check closure independently of this loop's cooperative budget.
                let end = tokio::task::unconstrained(received.wait()).now_or_never();
                assert!(matches!(end, Some(None)));
                assert!(payload.is_unique());
            }
        }
    }

    #[tokio::test]
    async fn local_close_releases_receiver_while_outbound_data_waits() {
        let mut session = authenticated_session();
        let (id, mut received) = close_test_channel(&mut session, true);
        session
            .data(id, bytes::Bytes::from_static(b"unsent"))
            .unwrap();
        session.close(id).unwrap();
        assert!(!session.channels.contains_key(&id));
        assert!(matches!(received.wait().now_or_never(), Some(None)));
        let enc = session.common.encrypted.as_ref().unwrap();
        assert!(enc.channels[&id].pending_close);
        assert!(enc.has_pending_data(id));
        assert!(enc.write.is_empty());

        let mut packet = vec![msg::CHANNEL_CLOSE];
        id.encode(&mut packet).unwrap();
        session
            .process_packet(&mut TestHandler, &packet)
            .await
            .unwrap();
        let enc = session.common.encrypted.as_ref().unwrap();
        assert!(enc.channels.is_empty());
        assert!(!enc.has_any_pending_data());
        assert_eq!(enc.write[4], msg::CHANNEL_CLOSE);
    }

    #[tokio::test]
    async fn local_close_drops_only_its_pending_delivery_and_credit() {
        let mut session = authenticated_session();
        let (id, mut received) = close_test_channel(&mut session, true);
        let (other, mut other_received) = close_test_channel(&mut session, true);
        let credit = session.receive_credit(id).unwrap();
        let sender = std::ops::Deref::deref(&session.channels[&id]).clone();
        for _ in 0..8 {
            sender
                .send(ChannelMsg::Data {
                    data: bytes::Bytes::from_static(b"queued"),
                })
                .await
                .unwrap();
        }
        session.pending_channel_data = Some(PendingChannelData::new(
            id,
            bytes::Bytes::from_static(b"pending"),
            None,
            sender,
        ));

        session.close(other).unwrap();
        assert!(session.pending_channel_data.is_some());
        assert!(matches!(other_received.wait().now_or_never(), Some(None)));
        session.close(id).unwrap();
        assert!(session.pending_channel_data.is_none());
        assert!(session.channels.is_empty());
        credit.consumed(1);
        assert!(!session.flush_receive_credit(id).unwrap());
        for _ in 0..8 {
            assert!(
                matches!(received.wait().await, Some(ChannelMsg::Data { data }) if data.as_ref() == b"queued")
            );
        }
        assert!(matches!(received.wait().now_or_never(), Some(None)));
    }

    #[tokio::test]
    async fn pending_delivery_close_from_drain_resumes_other_channel() {
        pending_delivery_close_resumes_other_channel(true).await;
    }

    #[tokio::test]
    async fn pending_delivery_close_from_select_resumes_other_channel() {
        pending_delivery_close_resumes_other_channel(false).await;
    }

    async fn pending_delivery_close_resumes_other_channel(queued_before_run: bool) {
        let mut session = authenticated_session();
        let config = Arc::get_mut(&mut session.common.config).unwrap();
        config.inactivity_timeout = None;
        config.keepalive_interval = None;
        session.common.encrypted.as_mut().unwrap().decompress = Decompress::None;
        assert_eq!(session.rekey_time_remaining(), None);
        let (parked, _parked_channel) = close_test_channel(&mut session, true);
        let (other_id, mut other) = close_test_channel(&mut session, true);
        let sender = std::ops::Deref::deref(&session.channels[&parked]).clone();
        for _ in 0..8 {
            sender
                .send(ChannelMsg::Data {
                    data: bytes::Bytes::from_static(b"queued"),
                })
                .await
                .unwrap();
        }
        let mut pending =
            PendingChannelData::new(parked, bytes::Bytes::from_static(b"pending"), None, sender);
        // Prove delivery is parked without allowing the consumer to free a slot.
        assert!(pending.permit.as_mut().now_or_never().is_none());
        session.pending_channel_data = Some(pending);

        let (socket, mut peer) = tokio::io::duplex(4096);
        let mut packets = PacketWriter::clear();
        packets
            .write_packet(|buf| {
                msg::CHANNEL_DATA.encode(buf)?;
                other_id.encode(buf)?;
                b"still reading".as_slice().encode(buf)?;
                Ok(())
            })
            .unwrap();
        packets.flush_into(&mut peer).await.unwrap();

        let handle = session.handle();
        let mut running = Box::pin(session.run(crate::ssh_read::SshRead::new(socket), TestHandler));
        if !queued_before_run {
            // With no queued close, enter select while the delivery is parked.
            assert!(running.as_mut().now_or_never().is_none());
        }
        // Otherwise the first pre-select drain must dispatch this queued close.
        handle.close(parked).await.unwrap();

        let message = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                result = &mut running => panic!("session ended before delivery: {result:?}"),
                message = other.wait() => message,
            }
        })
        .await
        .expect("local close left socket reads disabled");
        assert!(
            matches!(message, Some(ChannelMsg::Data { data }) if data.as_ref() == b"still reading")
        );
    }

    fn receive(session: &mut Session, channel: ChannelId, len: usize) {
        let encrypted = session.common.encrypted.as_mut().unwrap();
        let mut remaining = len;
        while remaining != 0 {
            let packet = remaining.min(128);
            assert_eq!(
                encrypted.consume_receive_window(channel, packet, false),
                crate::session::ReceiveWindowState::Accepted
            );
            remaining -= packet;
        }
        assert!(
            !encrypted
                .refill_receive_window(channel, session.target_window_size)
                .unwrap()
        );
    }

    #[test]
    fn manual_window_refills_only_reported_consumption() {
        let mut session = authenticated_session();
        let (channel, credit) = manual_window_channel(&mut session);
        receive(&mut session, channel, 512);

        credit.consumed(256);
        assert!(session.flush_receive_credit(channel).unwrap());
        assert_eq!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .sender_window_size(channel),
            768
        );
    }

    #[test]
    fn receive_credit_clamps_application_overreporting() {
        let mut session = authenticated_session();
        let (channel, credit) = manual_window_channel(&mut session);
        receive(&mut session, channel, 1024);

        credit.consumed(4096);
        assert!(session.flush_receive_credit(channel).unwrap());
        assert_eq!(
            session
                .common
                .encrypted
                .as_ref()
                .unwrap()
                .sender_window_size(channel),
            1024
        );
    }

    #[test]
    fn released_credit_before_confirmation_sends_no_window_adjust() {
        let mut session = authenticated_session();
        // A raised session target would otherwise put a fresh window below
        // the refill threshold and emit WINDOW_ADJUST before the channel's
        // own CHANNEL_OPEN_CONFIRMATION.
        session.target_window_size = 4096;
        let encrypted = session.common.encrypted.as_mut().unwrap();
        let channel = encrypted.new_channel(1024, 128);
        encrypted
            .channels
            .get_mut(&channel)
            .unwrap()
            .recipient_channel = 17;
        let credit = session.receive_credit(channel).unwrap();

        drop(credit);
        assert!(!session.flush_receive_credit(channel).unwrap());
        let encrypted = session.common.encrypted.as_ref().unwrap();
        assert_eq!(encrypted.sender_window_size(channel), 1024);
        assert!(encrypted.channels[&channel].application_consumed.is_none());
    }

    #[test]
    fn dropping_last_credit_restores_an_exhausted_window() {
        let mut session = authenticated_session();
        let (channel, credit) = manual_window_channel(&mut session);
        receive(&mut session, channel, 1024);

        drop(credit);
        assert!(matches!(
            session.receive_credit_receiver.try_recv(),
            Ok(ReceiveWindowEvent::Credit(id)) if id == channel
        ));
        assert!(session.flush_receive_credit(channel).unwrap());
        let encrypted = session.common.encrypted.as_ref().unwrap();
        assert_eq!(encrypted.sender_window_size(channel), 1024);
        assert!(encrypted.channels[&channel].application_consumed.is_none());
    }

    #[test]
    fn dropping_one_credit_clone_keeps_manual_accounting() {
        let mut session = authenticated_session();
        let (channel, credit) = manual_window_channel(&mut session);
        let last_credit = credit.clone();
        receive(&mut session, channel, 1024);

        drop(credit);
        assert!(session.receive_credit_receiver.try_recv().is_err());
        assert!(!session.flush_receive_credit(channel).unwrap());
        drop(last_credit);
        assert!(matches!(
            session.receive_credit_receiver.try_recv(),
            Ok(ReceiveWindowEvent::Credit(id)) if id == channel
        ));
    }

    #[test]
    fn abandoned_channel_open_queues_provisional_cleanup() {
        let mut session = authenticated_session();
        let channel = session
            .common
            .encrypted
            .as_mut()
            .unwrap()
            .new_channel(1024, 128);

        drop(PendingChannelCleanup::new(
            channel,
            session.receive_credit_sender.clone(),
        ));
        assert!(matches!(
            session.receive_credit_receiver.try_recv(),
            Ok(ReceiveWindowEvent::AbandonedOpen(id)) if id == channel
        ));
    }

    fn compressed_debug_payload(payload_len: usize) -> Vec<u8> {
        let mut payload = vec![b'A'; payload_len];
        payload[0] = crate::msg::DEBUG;

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 256 * 1024);
        compressed
    }

    fn incoming_packet(compressed: Vec<u8>) -> SSHBuffer {
        let mut buffer = SSHBuffer::new();
        buffer.buffer.extend_from_slice(&[0; 5]);
        buffer.buffer.extend_from_slice(&compressed);
        buffer
    }

    #[tokio::test]
    async fn compressed_debug_is_ignored_after_server_parses_it() {
        let mut session = authenticated_session();
        let mut handler = TestHandler;
        let buffer = incoming_packet(compressed_debug_payload(200 * 1024));
        let mut pkt: IncomingSshPacket = session.maybe_decompress(&buffer).unwrap();

        super::super::reply(&mut session, &mut handler, &mut pkt)
            .await
            .unwrap();

        assert!(!session.common.disconnected);
    }

    #[test]
    fn oversized_compressed_debug_is_rejected_before_server_ignores_it() {
        let mut session = authenticated_session();
        let buffer = incoming_packet(compressed_debug_payload(
            crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024,
        ));

        let err = session.maybe_decompress(&buffer).unwrap_err();
        assert!(
            matches!(err, crate::Error::PacketSize(len) if len > crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN)
        );
    }

    #[test]
    fn limit_triggered_rekey_waits_for_authentication() {
        let mut session = authenticated_session();
        allow_rekey(
            &mut session,
            crate::Limits::new(0, 0, Duration::from_secs(3600)),
        );
        let enc = session.common.encrypted.as_mut().unwrap();
        enc.state = EncryptedState::WaitingAuthServiceRequest {
            accepted: false,
            sent: false,
        };
        enc.server_compression = Compression::ZlibOpenSSH;

        session.flush().unwrap();
        assert!(
            !session.kex.active(),
            "write limit hit before authentication"
        );
        assert_eq!(session.rekey_time_remaining(), None);

        // USERAUTH_SUCCESS has been flushed; the next peer packet would
        // activate delayed compression, but the rekey comes first.
        session.common.encrypted.as_mut().unwrap().state = EncryptedState::InitCompression;
        assert_eq!(session.rekey_time_remaining(), Some(Duration::ZERO));
        session.flush().unwrap();
        assert!(session.kex.active());
        assert!(matches!(
            session.common.encrypted.as_ref().unwrap().state,
            EncryptedState::Authenticated
        ));
        assert!(matches!(
            session.common.packet_writer.compress(),
            Compress::Zlib(_)
        ));
    }

    #[tokio::test]
    async fn auth_success_arms_the_rekey_deadline_before_the_next_packet() {
        let mut session = authenticated_session();
        allow_rekey(
            &mut session,
            crate::Limits::new(1 << 30, 1 << 30, Duration::ZERO),
        );
        let enc = session.common.encrypted.as_mut().unwrap();
        enc.state =
            EncryptedState::WaitingAuthRequest(AuthRequest::server(MethodSet::server_supported()));
        enc.server_compression = Compression::ZlibOpenSSH;

        session
            .process_packet(&mut AcceptNoneHandler, &none_auth_request("user"))
            .await
            .unwrap();

        assert!(matches!(
            session.common.encrypted.as_ref().unwrap().state,
            EncryptedState::InitCompression
        ));
        assert!(matches!(
            session.common.packet_writer.compress(),
            Compress::None
        ));
        assert_eq!(session.rekey_time_remaining(), Some(Duration::ZERO));

        // What the event loop does once that deadline fires.
        session.flush().unwrap();

        assert!(session.kex.active());
        assert!(matches!(
            session.common.encrypted.as_ref().unwrap().state,
            EncryptedState::Authenticated
        ));
        assert!(matches!(
            session.common.packet_writer.compress(),
            Compress::Zlib(_)
        ));
    }

    /// `authenticated_session` negotiates the `none` kex, which cannot be
    /// repeated, and expects compressed input; undo both and install `limits`.
    fn allow_rekey(session: &mut Session, limits: crate::Limits) {
        Arc::get_mut(&mut session.common.config).unwrap().limits = limits;
        let enc = session.common.encrypted.as_mut().unwrap();
        enc.kex = KEXES.get(&crate::kex::CURVE25519).unwrap().make();
        enc.decompress = Decompress::None;
    }

    #[test]
    fn no_rekey_deadline_when_the_kex_cannot_be_repeated() {
        let mut session = authenticated_session();
        Arc::get_mut(&mut session.common.config).unwrap().limits =
            crate::Limits::new(1 << 30, 1 << 30, Duration::ZERO);
        assert_eq!(session.rekey_time_remaining(), None, "`none` kex");

        allow_rekey(
            &mut session,
            crate::Limits::new(1 << 30, 1 << 30, Duration::ZERO),
        );
        assert_eq!(session.rekey_time_remaining(), Some(Duration::ZERO));
    }

    /// Runs the server event loop on one end of an in-memory stream and
    /// returns the type of the first packet it writes.
    async fn first_packet_from_event_loop(
        session: Session,
        peer: &mut tokio::io::DuplexStream,
        stream: tokio::io::DuplexStream,
    ) -> Option<u8> {
        let event_loop = tokio::spawn(session.run(SshRead::new(stream), TestHandler));
        let mut buffer = SSHBuffer::new();
        let mut opening_key = cipher::clear::Key;
        let packet = cipher::read(peer, &mut buffer, &mut opening_key);
        let result = tokio::time::timeout(Duration::from_secs(5), packet).await;
        event_loop.abort();
        result.ok()?.unwrap();
        buffer.buffer.get(5).copied()
    }

    #[tokio::test]
    async fn read_limit_starts_rekey_from_the_event_loop() {
        let mut session = authenticated_session();
        allow_rekey(
            &mut session,
            crate::Limits::new(1 << 30, 16, Duration::from_secs(3600)),
        );
        let (mut peer, stream) = tokio::io::duplex(64 * 1024);
        let mut ignore = PacketWriter::clear();
        ignore.packet_raw(&[msg::IGNORE; 32]).unwrap();
        peer.write_all(&ignore.buffer().buffer).await.unwrap();

        assert_eq!(
            first_packet_from_event_loop(session, &mut peer, stream).await,
            Some(msg::KEXINIT)
        );
    }

    #[tokio::test]
    async fn time_limit_starts_rekey_from_the_event_loop() {
        let mut session = authenticated_session();
        allow_rekey(
            &mut session,
            crate::Limits::new(1 << 30, 1 << 30, Duration::from_millis(50)),
        );
        let (mut peer, stream) = tokio::io::duplex(64 * 1024);

        assert_eq!(
            first_packet_from_event_loop(session, &mut peer, stream).await,
            Some(msg::KEXINIT)
        );
    }
}
