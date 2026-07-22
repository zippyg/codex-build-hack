#![forbid(unsafe_code)]

use std::io::{Read, Write as _};
use std::net::{Shutdown, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

const PROXY_ADDRESS: &str = "proxy:8080";
const MAX_RESPONSE_BYTES: usize = 4096;
const ALLOWED_HOSTS: [&str; 5] = [
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
    "github.com",
    "gitlab.com",
];

fn main() -> ExitCode {
    match execute(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

fn execute(mut arguments: impl Iterator<Item = String>) -> Result<(), ()> {
    let destination = std::env::var("PROMPTECTOMY_SSH_DESTINATION").map_err(|_| ())?;
    let host = validate_destination(&mut arguments, &destination)?;
    let mut tunnel = TcpStream::connect(PROXY_ADDRESS).map_err(|_| ())?;
    tunnel
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;
    tunnel
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;
    let request = format!("CONNECT {host}:22 HTTP/1.1\r\nHost: {host}:22\r\n\r\n");
    tunnel.write_all(request.as_bytes()).map_err(|_| ())?;
    read_success(&mut tunnel)?;
    tunnel.set_read_timeout(None).map_err(|_| ())?;
    tunnel.set_write_timeout(None).map_err(|_| ())?;
    bridge(std::io::stdin(), &mut std::io::stdout().lock(), tunnel)
}

fn bridge(
    mut input: impl Read + Send + 'static,
    output: &mut impl std::io::Write,
    mut tunnel: TcpStream,
) -> Result<(), ()> {
    let mut outbound = tunnel.try_clone().map_err(|_| ())?;
    let to_server = std::thread::Builder::new()
        .name("ssh-connect-stdin".to_owned())
        .spawn(move || {
            let copied = std::io::copy(&mut input, &mut outbound).map_err(|_| ());
            let shutdown = outbound.shutdown(Shutdown::Write).map_err(|_| ());
            copied?;
            shutdown
        })
        .map_err(|_| ())?;
    copy_from_server(&mut tunnel, output)?;
    if to_server.is_finished() {
        to_server.join().map_err(|_| ())??;
    } else {
        drop(to_server);
    }
    Ok(())
}

fn copy_from_server(input: &mut impl Read, output: &mut impl std::io::Write) -> Result<(), ()> {
    let mut chunk = [0_u8; 8192];
    loop {
        let count = input.read(&mut chunk).map_err(|_| ())?;
        if count == 0 {
            return Ok(());
        }
        output.write_all(&chunk[..count]).map_err(|_| ())?;
        output.flush().map_err(|_| ())?;
    }
}

fn validate_destination(
    arguments: &mut impl Iterator<Item = String>,
    destination: &str,
) -> Result<String, ()> {
    let host = arguments.next().ok_or(())?;
    let port = arguments.next().ok_or(())?;
    if arguments.next().is_some()
        || port != "22"
        || !ALLOWED_HOSTS.contains(&host.as_str())
        || destination != format!("{host}:22")
    {
        return Err(());
    }
    Ok(host)
}

fn read_success(stream: &mut impl Read) -> Result<(), ()> {
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_RESPONSE_BYTES {
            return Err(());
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).map_err(|_| ())?;
        response.push(byte[0]);
    }
    if response != b"HTTP/1.1 200 Connection Established\r\n\r\n" {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex, mpsc};

    #[test]
    fn response_parser_accepts_only_the_exact_success_response() {
        read_success(&mut b"HTTP/1.1 200 Connection Established\r\n\r\n".as_slice())
            .expect("exact response");
        for mut denied in [
            b"HTTP/1.0 200 Connection Established\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 Connection Established\r\nHeader: value\r\n\r\n".as_slice(),
        ] {
            assert!(read_success(&mut denied).is_err());
        }
    }

    #[test]
    fn oversized_or_incomplete_response_is_denied() {
        assert!(read_success(&mut vec![b'a'; MAX_RESPONSE_BYTES].as_slice()).is_err());
        assert!(read_success(&mut b"HTTP/1.1 200".as_slice()).is_err());
    }

    #[test]
    fn destination_is_exactly_bound_to_the_fixed_allowlist_and_port() {
        assert_eq!(
            validate_destination(
                &mut ["github.com".to_owned(), "22".to_owned()].into_iter(),
                "github.com:22"
            ),
            Ok("github.com".to_owned())
        );
        for (arguments, destination) in [
            (vec!["attacker.example", "22"], "attacker.example:22"),
            (vec!["github.com", "443"], "github.com:443"),
            (vec!["github.com", "22"], "gitlab.com:22"),
            (vec!["github.com", "22", "extra"], "github.com:22"),
            (vec!["github.com"], "github.com:22"),
        ] {
            assert!(
                validate_destination(
                    &mut arguments.into_iter().map(ToOwned::to_owned),
                    destination
                )
                .is_err()
            );
        }
    }

    #[test]
    fn upstream_first_eof_does_not_wait_for_blocked_input() {
        struct BlockingInput(mpsc::Receiver<()>);

        impl Read for BlockingInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.0.recv().map_or(Ok(0), |()| Ok(0))
            }
        }

        #[derive(Clone)]
        struct SharedOutput(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for SharedOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("output lock").extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client = TcpStream::connect(listener.local_addr().expect("address")).expect("client");
        let (mut server, _) = listener.accept().expect("accept");
        let server = std::thread::spawn(move || {
            server.write_all(b"upstream-closed").expect("server write");
        });
        let (release_tx, release_rx) = mpsc::channel();
        let output = SharedOutput(Arc::new(Mutex::new(Vec::new())));
        let observed = Arc::clone(&output.0);
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            done_tx
                .send(bridge(
                    BlockingInput(release_rx),
                    &mut output.clone(),
                    client,
                ))
                .expect("result receiver");
        });

        let result = done_rx.recv_timeout(Duration::from_secs(1));
        drop(release_tx);
        server.join().expect("server thread");
        assert_eq!(result.expect("bridge must not join blocked input"), Ok(()));
        assert_eq!(
            &*observed.lock().expect("observed output"),
            b"upstream-closed"
        );
    }

    #[test]
    fn server_bytes_are_flushed_before_upstream_eof() {
        struct BlockingInput(mpsc::Receiver<()>);

        impl Read for BlockingInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.0.recv().map_or(Ok(0), |()| Ok(0))
            }
        }

        struct FlushObserved {
            pending: Vec<u8>,
            flushed: mpsc::Sender<Vec<u8>>,
        }

        impl std::io::Write for FlushObserved {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.pending.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.flushed
                    .send(std::mem::take(&mut self.pending))
                    .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client = TcpStream::connect(listener.local_addr().expect("address")).expect("client");
        let (mut server, _) = listener.accept().expect("accept");
        let (close_tx, close_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            server
                .write_all(b"SSH-2.0-test\r\n\0kex")
                .expect("server bytes");
            close_rx.recv().expect("close signal");
        });
        let (input_tx, input_rx) = mpsc::channel();
        let (flushed_tx, flushed_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            done_tx
                .send(bridge(
                    BlockingInput(input_rx),
                    &mut FlushObserved {
                        pending: Vec::new(),
                        flushed: flushed_tx,
                    },
                    client,
                ))
                .expect("result receiver");
        });

        assert_eq!(
            flushed_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("bytes before upstream EOF"),
            b"SSH-2.0-test\r\n\0kex"
        );
        close_tx.send(()).expect("close upstream");
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("bridge completion"),
            Ok(())
        );
        drop(input_tx);
        server.join().expect("server thread");
    }

    #[test]
    fn input_first_eof_half_closes_then_drains_upstream() {
        #[derive(Clone)]
        struct SharedOutput(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for SharedOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("output lock").extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client = TcpStream::connect(listener.local_addr().expect("address")).expect("client");
        let (mut server, _) = listener.accept().expect("accept");
        let server = std::thread::spawn(move || {
            let mut received = Vec::new();
            server.read_to_end(&mut received).expect("read half-close");
            assert_eq!(received, b"client-finished");
            server.write_all(b"server-drained").expect("server reply");
        });
        let mut output = SharedOutput(Arc::new(Mutex::new(Vec::new())));
        let observed = Arc::clone(&output.0);

        bridge(Cursor::new(b"client-finished"), &mut output, client).expect("bridge");
        server.join().expect("server thread");
        assert_eq!(
            &*observed.lock().expect("observed output"),
            b"server-drained"
        );
    }
}
