use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut};
use core::mem::MaybeUninit;
use futures::stream::{self, FuturesUnordered};
use native_tls::Identity;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    stream::{Stream, StreamExt},
};
use tokio_tls::{TlsAcceptor, TlsStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tcp = Transport::new_tcp("127.0.0.1:8881").await?;
    let incoming_tcp = tcp.incoming();

    let mut tls = Transport::new_tls("127.0.0.1:8882").await?;
    let incoming_tls = tls.incoming();

    let mut incoming = stream::select(incoming_tcp, incoming_tls);

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(stream) => {
                tokio::spawn(async move {
                    if let Err(e) = process(stream).await {
                        eprintln!("failed to process connection: {}", e);
                    }
                });
            }
            Err(e) => println!("Error: {}", e),
        }
    }
    Ok(())
}

async fn process<I>(mut stream: I) -> std::io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0; 1024];

    loop {
        let n = stream.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        println!("{}", std::str::from_utf8(&buf).unwrap());
    }
}

enum Transport {
    Tcp(TcpListener),
    Tls(TcpListener, TlsAcceptor),
}

impl Transport {
    async fn new_tcp(addr: impl ToSocketAddrs) -> tokio::io::Result<Self> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Transport::Tcp(tcp))
    }

    async fn new_tls(addr: impl ToSocketAddrs) -> Result<Self, Box<dyn std::error::Error>> {
        let der = include_bytes!("identity.p12");
        let cert = Identity::from_pkcs12(der, "mypass")?;
        let acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build()?);
        let tcp = TcpListener::bind(addr).await?;
        Ok(Transport::Tls(tcp, acceptor))
    }

    fn incoming(&mut self) -> Incoming<'_> {
        match self {
            Self::Tcp(listener) => Incoming::Tcp(listener),
            Self::Tls(listener, acceptor) => Incoming::Tls(listener, acceptor, Default::default()),
        }
    }
}

type HandshakeFuture =
    Pin<Box<dyn Future<Output = Result<TlsStream<TcpStream>, native_tls::Error>>>>;

enum Incoming<'a> {
    Tcp(&'a mut TcpListener),
    Tls(
        &'a mut TcpListener,
        &'a TlsAcceptor,
        FuturesUnordered<HandshakeFuture>,
    ),
}
impl Stream for Incoming<'_> {
    type Item = tokio::io::Result<StreamSelector>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            Self::Tcp(listener) => match listener.poll_accept(cx) {
                Poll::Ready(Ok((tcp, _))) => {
                    println!("TCP: Accepted connection from client");
                    Poll::Ready(Some(Ok(StreamSelector::Tcp(tcp))))
                }
                Poll::Ready(Err(err)) => {
                    eprintln!(
                        "TCP: Dropping client that failed to completely establish a TCP connection: {}",
                        err
                    );
                    Poll::Ready(Some(Err(err)))
                }
                Poll::Pending => Poll::Pending,
            },
            Self::Tls(listener, acceptor, connections) => {
                loop {
                    match listener.poll_accept(cx) {
                        Poll::Ready(Ok((stream, _))) => {
                            let acceptor = acceptor.clone();
                            connections.push(Box::pin(async move {
                                acceptor.accept(stream).await
                            }));
                        },
                        Poll::Ready(Err(err)) =>
                            eprintln!("TCP: Dropping client that failed to completely establish a TCP connection: {}", err),
                        Poll::Pending => break,
                    }
                }

                loop {
                    if connections.is_empty() {
                        return Poll::Pending;
                    }

                    match Pin::new(&mut *connections).poll_next(cx) {
                        Poll::Ready(Some(Ok(stream))) => {
                            println!("TLS: Accepted connection from client");
                            return Poll::Ready(Some(Ok(StreamSelector::Tls(stream))));
                        }

                        Poll::Ready(Some(Err(err))) => eprintln!(
                            "TLS: Dropping client that failed to complete a TLS handshake: {}",
                            err
                        ),

                        Poll::Ready(None) => {
                            println!("TLS: Shutting down web server");
                            return Poll::Ready(None);
                        }

                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

pub enum StreamSelector {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for StreamSelector {
    #[inline]
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        match *self {
            StreamSelector::Tcp(ref stream) => stream.prepare_uninitialized_buffer(buf),
            StreamSelector::Tls(ref stream) => stream.prepare_uninitialized_buffer(buf),
        }
    }

    #[inline]
    fn poll_read_buf<B: BufMut>(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut B,
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            StreamSelector::Tcp(stream) => Pin::new(stream).poll_read_buf(cx, buf),
            StreamSelector::Tls(stream) => Pin::new(stream).poll_read_buf(cx, buf),
        }
    }

    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        match self.get_mut() {
            StreamSelector::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            StreamSelector::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StreamSelector {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            StreamSelector::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            StreamSelector::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_write_buf<B: Buf>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            StreamSelector::Tcp(stream) => Pin::new(stream).poll_write_buf(cx, buf),
            StreamSelector::Tls(stream) => Pin::new(stream).poll_write_buf(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamSelector::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            StreamSelector::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamSelector::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            StreamSelector::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
