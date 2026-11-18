use std::io;
use std::net::{Shutdown, TcpStream as StdTcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use tokio::net::TcpStream;

/// Control remains usable through split IO, TLS and duplicated recovery handles.
#[derive(Debug, Clone)]
pub struct ConnectionControl(Arc<StdTcpStream>);

impl ConnectionControl {
    pub fn new(stream: &TcpStream) -> io::Result<Self> {
        Ok(Self(Arc::new(StdTcpStream::from(
            stream.as_fd().try_clone_to_owned()?,
        ))))
    }
    pub fn shutdown_write(&self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }

    pub fn clone_stream(&self) -> io::Result<TcpStream> {
        TcpStream::from_std(self.0.try_clone()?)
    }

    /// SO_LINGER alone cannot reset until every duplicated descriptor is closed.
    pub fn reset(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let address = libc::sockaddr {
                sa_family: libc::AF_UNSPEC as libc::sa_family_t,
                sa_data: [0; 14],
            };
            // SAFETY: descriptor is owned for this call and the address has the
            // advertised sockaddr size. AF_UNSPEC disconnects an existing socket.
            let result = unsafe {
                libc::connect(
                    self.0.as_raw_fd(),
                    &address,
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "immediate TCP reset requires Linux",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reset_reaches_peer_while_other_descriptors_are_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap());
        let (peer, accepted) = tokio::join!(peer, listener.accept());
        let mut peer = peer.unwrap();
        let stream = accepted.unwrap().0;
        let control = ConnectionControl::new(&stream).unwrap();
        let _other = ConnectionControl::new(&stream).unwrap();
        control.reset().unwrap();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), peer.read(&mut [0]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }
}
