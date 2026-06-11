// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Streaming, ZIP64-capable archive writer for building archives incrementally
//! into an async sink without buffering whole entries in memory.

use crate::{Result, ZipError};
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};
use futures::io::AsyncWriteExt as _;
use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Compression method for a streamed ZIP entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipStreamMethod {
    /// No compression. CPU-free; archive size ~= sum of object sizes.
    Stored,
    /// DEFLATE compression.
    Deflate,
}

impl From<ZipStreamMethod> for Compression {
    fn from(method: ZipStreamMethod) -> Self {
        match method {
            ZipStreamMethod::Stored => Compression::Stored,
            ZipStreamMethod::Deflate => Compression::Deflate,
        }
    }
}

/// A streaming, ZIP64-capable archive writer.
///
/// Entries are written via data descriptors, so every entry carries a ZIP64
/// extended-information field and the archive always closes with a ZIP64
/// end-of-central-directory record. Archives may therefore exceed 4 GiB and
/// 65535 entries.
pub struct ZipStreamWriter<W: tokio::io::AsyncWrite + Unpin> {
    inner: ZipFileWriter<W>,
}

impl<W: tokio::io::AsyncWrite + Unpin> ZipStreamWriter<W> {
    /// Create a new streaming writer over `sink`.
    pub fn new(sink: W) -> Self {
        Self {
            inner: ZipFileWriter::with_tokio(sink).force_zip64(),
        }
    }

    /// Append one entry named `name`, streaming all bytes from `reader`.
    pub async fn add<R: AsyncRead + Unpin>(&mut self, name: &str, mut reader: R, method: ZipStreamMethod) -> Result<()> {
        let builder = ZipEntryBuilder::new(name.to_owned().into(), method.into());
        let mut entry = self.inner.write_entry_stream(builder).await?;
        let mut buf = vec![0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            entry.write_all(&buf[..read]).await.map_err(ZipError::Io)?;
        }
        entry.close().await?;
        Ok(())
    }

    /// Finish the archive (writes the central directory) and return the sink.
    pub async fn finish(self) -> Result<W> {
        let compat = self.inner.close().await?;
        Ok(compat.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_zip_simple;
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    async fn collect_stream_zip(entries: Vec<(String, Vec<u8>, ZipStreamMethod)>) -> Vec<u8> {
        let (sink, mut read_half) = tokio::io::duplex(64 * 1024);
        let producer = tokio::spawn(async move {
            let mut writer = ZipStreamWriter::new(sink);
            for (name, data, method) in &entries {
                writer.add(name, &data[..], *method).await.expect("add entry");
            }
            writer.finish().await.expect("finish archive");
        });
        let mut bytes = Vec::new();
        read_half.read_to_end(&mut bytes).await.expect("drain archive");
        producer.await.expect("producer task");
        bytes
    }

    #[tokio::test]
    async fn zip_stream_writer_round_trips_through_extractor() {
        let bytes = collect_stream_zip(vec![
            ("root/a.txt".to_string(), b"hello".to_vec(), ZipStreamMethod::Stored),
            ("root/sub/b.txt".to_string(), b"world".to_vec(), ZipStreamMethod::Deflate),
        ])
        .await;

        let dir = tempfile::tempdir().expect("tempdir");
        let zip_path = dir.path().join("archive.zip");
        let out = dir.path().join("out");
        tokio::fs::write(&zip_path, &bytes).await.expect("write zip");

        let entries = extract_zip_simple(&zip_path, &out).await.expect("extract");
        assert_eq!(entries.len(), 2);
        assert_eq!(tokio::fs::read(out.join("root/a.txt")).await.unwrap(), b"hello");
        assert_eq!(tokio::fs::read(out.join("root/sub/b.txt")).await.unwrap(), b"world");

        // Reads back through the `zip` crate's central directory parser too.
        let archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip crate reads archive");
        assert_eq!(archive.len(), 2);
    }

    #[tokio::test]
    async fn zip_stream_writer_emits_zip64_for_many_entries() {
        // More than NON_ZIP64_MAX_NUM_FILES (65535) forces the ZIP64 EOCD path.
        let count = 70_000_u32;
        let entries = (0..count)
            .map(|i| (format!("f/{i}"), Vec::new(), ZipStreamMethod::Stored))
            .collect::<Vec<_>>();
        let bytes = collect_stream_zip(entries).await;

        let archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip crate reads zip64 archive");
        assert_eq!(archive.len() as u32, count);
    }

    #[tokio::test]
    async fn zip_stream_writer_errors_when_sink_closes() {
        // Simulates a client disconnecting mid-download: the duplex read half is
        // dropped, so writes to the sink fail and the writer surfaces an error
        // instead of hanging. Deterministic and free of any global state.
        let (sink, read_half) = tokio::io::duplex(1024);
        drop(read_half);
        let mut writer = ZipStreamWriter::new(sink);
        let big = vec![0_u8; 1024 * 1024];
        let result = async {
            writer.add("a.bin", &big[..], ZipStreamMethod::Stored).await?;
            writer.finish().await?;
            Ok::<_, crate::ZipError>(())
        }
        .await;
        assert!(result.is_err(), "writer should error once the sink is closed");
    }
}
