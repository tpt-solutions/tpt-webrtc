//! Async socket abstraction.
//!
//! The protocol crates talk to the network exclusively through
//! [`WebRtcSocket`], so ICE/DTLS/SCTP can be integration-tested over loopback
//! sockets or driven over any future transport (e.g. TURN relays) without
//! changes.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

/// Packet-oriented transport used by the stack.
///
/// Implementations must be safe to share across tasks (`Send + Sync`); the
/// futures returned by the methods are `Send` so agents can be spawned on a
/// multi-threaded tokio runtime.
pub trait WebRtcSocket: Send + Sync {
    /// Sends one datagram to `addr`, returning the number of bytes queued.
    fn send_to(
        &self,
        buf: &[u8],
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send;

    /// Receives one datagram, returning its length and source address.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    /// The local bound address, when known.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Default [`WebRtcSocket`] implementation over a tokio UDP socket.
#[derive(Debug, Clone)]
pub struct UdpWebRtcSocket {
    inner: Arc<tokio::net::UdpSocket>,
}

impl UdpWebRtcSocket {
    /// Binds a UDP socket to `addr` (`0.0.0.0:0` picks an ephemeral port).
    ///
    /// # Errors
    /// Propagates the OS bind error.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            inner: Arc::new(tokio::net::UdpSocket::bind(addr).await?),
        })
    }
}

impl WebRtcSocket for UdpWebRtcSocket {
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_socket_loopback_echo() {
        let a = UdpWebRtcSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = UdpWebRtcSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();

        a.send_to(b"hello", b_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, src) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(src, a.local_addr().unwrap());
    }
}
