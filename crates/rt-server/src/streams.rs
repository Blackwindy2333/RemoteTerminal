//! Bridges axum's asynchronous body streams into the blocking `std::io::Read`
//! that `rt_core::fsops::write_stream` expects.
//!
//! Uploads must never be buffered whole in memory, so a small bounded channel
//! carries chunks from the async producer to the blocking writer running on the
//! blocking pool. Backpressure comes from the bounded channel plus an
//! await-friendly retry loop on the producer side.

use std::io::{self, Read};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use bytes::Bytes;

/// How many chunks may queue up between the socket and the disk writer.
const CHANNEL_CAPACITY: usize = 8;

/// How long the blocking writer waits for the next chunk before giving up.
const READ_WAIT: Duration = Duration::from_secs(300);

/// Producer half: hands body chunks to the blocking writer.
pub(crate) struct ChannelWriter {
    tx: Option<SyncSender<io::Result<Bytes>>>,
}

impl ChannelWriter {
    /// Queues one chunk, waiting politely while the writer catches up.
    ///
    /// Returns `false` when the writer has already failed or finished, meaning
    /// the caller should stop reading the request body.
    pub(crate) async fn send(&mut self, chunk: Bytes) -> bool {
        loop {
            let Some(tx) = self.tx.as_ref() else {
                return false;
            };
            match tx.try_send(Ok(chunk.clone())) {
                Ok(()) => return true,
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    self.tx = None;
                    return false;
                }
            }
        }
    }

    /// Signals a clean end of stream (the reader sees EOF).
    pub(crate) fn finish(&mut self) {
        self.tx = None;
    }

    /// Signals a transport failure to the writer.
    pub(crate) fn fail(&mut self, message: impl Into<String>) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.try_send(Err(io::Error::new(io::ErrorKind::InvalidData, message.into())));
        }
    }
}

/// Consumer half: implements [`Read`] over the queued chunks.
pub(crate) struct ChannelReader {
    rx: Receiver<io::Result<Bytes>>,
    current: Bytes,
    offset: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.current.len() {
            self.current = match self.rx.recv_timeout(READ_WAIT) {
                Ok(Ok(chunk)) => chunk,
                Ok(Err(err)) => return Err(err),
                // Every sender gone: normal end of file.
                Err(RecvTimeoutError::Disconnected) => return Ok(0),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upload stalled: no data received",
                    ))
                }
            };
            self.offset = 0;
            if self.current.is_empty() {
                return Ok(0);
            }
        }

        let available = &self.current[self.offset..];
        let count = available.len().min(buf.len());
        buf[..count].copy_from_slice(&available[..count]);
        self.offset += count;
        Ok(count)
    }
}

/// Creates a connected (writer, reader) pair for one streaming upload.
pub(crate) fn channel() -> (ChannelWriter, ChannelReader) {
    let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
    (
        ChannelWriter { tx: Some(tx) },
        ChannelReader {
            rx,
            current: Bytes::new(),
            offset: 0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_sees_chunks_then_eof() {
        let (mut writer, mut reader) = channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                assert!(writer.send(Bytes::from_static(b"hello ")).await);
                assert!(writer.send(Bytes::from_static(b"world")).await);
                writer.finish();
            });
        });

        let mut collected = Vec::new();
        reader.read_to_end(&mut collected).expect("read");
        assert_eq!(collected, b"hello world");
    }
}
