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

//! Admin handler that streams a ZIP archive of every object under a prefix.

use crate::admin::auth::{validate_admin_request_with_bucket, validate_admin_request_with_bucket_object, AdminResourceScope};
use crate::admin::router::{AdminOperation, Operation, S3Router};
use crate::auth::{check_key_valid, get_session_token};
use crate::server::ADMIN_PREFIX;
use bytes::Bytes;
use futures::stream::StreamExt;
use http::{header, HeaderMap, HeaderValue};
use hyper::{Method, StatusCode};
use matchit::Params;
use rustfs_ecstore::new_object_layer_fn;
use rustfs_ecstore::store::ECStore;
use rustfs_ecstore::store_api::{ListOperations, ObjectIO, ObjectOptions};
use rustfs_policy::policy::action::{Action, S3Action};
use rustfs_zip::{ZipStreamMethod, ZipStreamWriter};
use s3s::stream::{ByteStream, DynByteStream};
use s3s::{s3_error, Body, S3Request, S3Response, S3Result, StdError};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_util::io::ReaderStream;
use url::form_urlencoded;

/// Maps an object key to its archive entry name: the last segment of the prefix
/// becomes the archive's root folder, with the object's path below it.
fn entry_name_for(prefix: &str, key: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    let root = trimmed.rsplit('/').next().unwrap_or("");
    let rel = key.strip_prefix(trimmed).unwrap_or(key).trim_start_matches('/');
    if root.is_empty() {
        rel.to_string()
    } else {
        format!("{root}/{rel}")
    }
}

/// Derives the download filename (without extension) from the prefix's last segment.
fn download_filename(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    let segment = trimmed.rsplit('/').next().unwrap_or("");
    let base = if segment.is_empty() { "download" } else { segment };
    base.chars().filter(|c| !c.is_control() && *c != '"' && *c != '\\').collect()
}

/// Lists every object under `prefix` and streams each into a ZIP written to `sink`.
/// Errors are returned as strings for the caller to log; the partial stream is
/// truncated by dropping `sink`.
pub(crate) async fn produce_zip<W>(
    store: Arc<ECStore>,
    bucket: String,
    prefix: String,
    method: ZipStreamMethod,
    sink: W,
) -> std::result::Result<(), String>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut zip = ZipStreamWriter::new(sink);
    let mut continuation: Option<String> = None;

    loop {
        let page = store
            .clone()
            .list_objects_v2(&bucket, &prefix, continuation.clone(), None, 1000, false, None, false)
            .await
            .map_err(|e| format!("list_objects_v2 failed: {e}"))?;

        for object in page.objects {
            if object.is_dir {
                continue;
            }
            let reader = store
                .get_object_reader(&bucket, &object.name, None, HeaderMap::new(), &ObjectOptions::default())
                .await
                .map_err(|e| format!("get_object_reader({}) failed: {e}", object.name))?;
            let name = entry_name_for(&prefix, &object.name);
            zip.add(&name, reader.stream, method)
                .await
                .map_err(|e| format!("zip add({name}) failed: {e}"))?;
        }

        match (page.is_truncated, page.next_continuation_token) {
            (true, Some(token)) => continuation = Some(token),
            _ => break,
        }
    }

    zip.finish().await.map_err(|e| format!("zip finish failed: {e}"))?;
    Ok(())
}

struct DownloadZipQuery {
    bucket: String,
    prefix: String,
    method: ZipStreamMethod,
}

impl DownloadZipQuery {
    fn from_uri(uri: &hyper::Uri) -> S3Result<Self> {
        let mut bucket = String::new();
        let mut prefix = String::new();
        let mut method = ZipStreamMethod::Stored;
        if let Some(query) = uri.query() {
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                match key.as_ref() {
                    "bucket" => bucket = value.into_owned(),
                    "prefix" => prefix = value.into_owned(),
                    "compression" => {
                        method = match value.as_ref() {
                            "deflate" => ZipStreamMethod::Deflate,
                            "stored" | "" => ZipStreamMethod::Stored,
                            other => return Err(s3_error!(InvalidArgument, "unsupported compression: {other}")),
                        }
                    }
                    _ => {}
                }
            }
        }
        if bucket.is_empty() {
            return Err(s3_error!(InvalidArgument, "bucket is required"));
        }
        Ok(Self { bucket, prefix, method })
    }
}

/// Adapts the duplex read half into an s3s response body stream.
struct ZipReaderStream {
    inner: ReaderStream<tokio::io::DuplexStream>,
}

impl futures::Stream for ZipReaderStream {
    type Item = std::result::Result<Bytes, StdError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err) as StdError))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl ByteStream for ZipReaderStream {}

pub struct DownloadZipHandler;

#[async_trait::async_trait]
impl Operation for DownloadZipHandler {
    #[tracing::instrument(skip_all)]
    async fn call(&self, req: S3Request<Body>, _params: Params<'_, '_>) -> S3Result<S3Response<(StatusCode, Body)>> {
        let Some(ref cred_in) = req.credentials else {
            return Err(s3_error!(InvalidRequest, "authentication required"));
        };
        let (cred, owner) =
            check_key_valid(get_session_token(&req.uri, &req.headers).unwrap_or_default(), &cred_in.access_key).await?;

        let query = DownloadZipQuery::from_uri(&req.uri)?;

        validate_admin_request_with_bucket(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::S3Action(S3Action::ListBucketAction)],
            None,
            &query.bucket,
        )
        .await?;
        validate_admin_request_with_bucket_object(
            &req.headers,
            &cred,
            owner,
            false,
            vec![Action::S3Action(S3Action::GetObjectAction)],
            None,
            AdminResourceScope::bucket_object(&query.bucket, &query.prefix),
        )
        .await?;

        let Some(store) = new_object_layer_fn() else {
            return Err(s3_error!(InternalError, "storage not initialized"));
        };

        let (zip_sink, zip_read) = tokio::io::duplex(256 * 1024);
        let stream: DynByteStream = Box::pin(ZipReaderStream { inner: ReaderStream::new(zip_read) });

        let bucket = query.bucket.clone();
        let prefix = query.prefix.clone();
        let method = query.method;
        tokio::spawn(async move {
            if let Err(err) = produce_zip(store, bucket, prefix, method, zip_sink).await {
                tracing::error!(target: "rustfs::admin::download_zip", error = %err, "zip production failed");
            }
        });

        let mut resp = S3Response::new((StatusCode::OK, Body::from(stream)));
        resp.headers
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
        let disposition = format!("attachment; filename=\"{}.zip\"", download_filename(&query.prefix));
        resp.headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&disposition).map_err(|e| s3_error!(InternalError, "invalid filename: {e}"))?,
        );
        resp.headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
        Ok(resp)
    }
}

/// Registers the download-zip route.
pub fn register_download_zip_route(r: &mut S3Router<AdminOperation>) -> std::io::Result<()> {
    r.insert(
        Method::GET,
        format!("{}{}", ADMIN_PREFIX, "/v3/download-zip").as_str(),
        AdminOperation(&DownloadZipHandler {}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_name_uses_last_prefix_segment_as_root() {
        assert_eq!(entry_name_for("p/", "p/a.txt"), "p/a.txt");
        assert_eq!(entry_name_for("p/", "p/sub/b.txt"), "p/sub/b.txt");
        assert_eq!(entry_name_for("a/b/c/", "a/b/c/d.txt"), "c/d.txt");
        assert_eq!(entry_name_for("p", "p/a.txt"), "p/a.txt");
        assert_eq!(entry_name_for("", "x.txt"), "x.txt");
    }

    #[test]
    fn download_filename_strips_unsafe_chars() {
        assert_eq!(download_filename("a/b/c/"), "c");
        assert_eq!(download_filename(""), "download");
        assert_eq!(download_filename("we\"ird/"), "weird");
    }

    use rustfs_ecstore::bucket::metadata_sys;
    use rustfs_ecstore::disk::endpoint::Endpoint;
    use rustfs_ecstore::endpoints::{EndpointServerPools, Endpoints, PoolEndpoints};
    use rustfs_ecstore::store::ECStore;
    use rustfs_ecstore::store_api::{BucketOperations, ObjectIO, ObjectOptions, PutObjReader};
    use rustfs_storage_api::{BucketOptions, MakeBucketOptions};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;
    use rustfs_zip::ZipStreamMethod;

    async fn fresh_store() -> Arc<ECStore> {
        let base = PathBuf::from(format!("/tmp/rustfs_download_zip_test_{}", Uuid::new_v4()));
        let disks: Vec<PathBuf> = (1..=4).map(|i| base.join(format!("disk{i}"))).collect();
        for disk in &disks {
            tokio::fs::create_dir_all(disk).await.unwrap();
        }
        let mut endpoints = Vec::new();
        for (i, disk) in disks.iter().enumerate() {
            let mut ep = Endpoint::try_from(disk.to_str().unwrap()).unwrap();
            ep.set_pool_index(0);
            ep.set_set_index(0);
            ep.set_disk_index(i);
            endpoints.push(ep);
        }
        let pool = PoolEndpoints {
            legacy: false,
            set_count: 1,
            drives_per_set: 4,
            endpoints: Endpoints::from(endpoints),
            cmd_line: "test".to_string(),
            platform: format!("OS: {} | Arch: {}", std::env::consts::OS, std::env::consts::ARCH),
        };
        let pools = EndpointServerPools(vec![pool]);
        rustfs_ecstore::store::init_local_disks(pools.clone()).await.unwrap();
        let addr: std::net::SocketAddr = "127.0.0.1:9004".parse().unwrap();
        let store = ECStore::new(addr, pools, CancellationToken::new()).await.unwrap();
        let buckets = store
            .list_bucket(&BucketOptions { no_metadata: true, ..Default::default() })
            .await
            .unwrap()
            .into_iter()
            .map(|b| b.name)
            .collect();
        metadata_sys::init_bucket_metadata_sys(store.clone(), buckets).await;
        store
    }

    // `#[ignore]`: spins up a global ECStore (`init_local_disks` mutates process-global
    // disk state), which would race the other global-disk test in this binary
    // (`app/lifecycle_transition_api_test.rs`). Run it in isolation:
    //   cargo test -p rustfs produce_zip_archives_only_the_prefix -- --ignored --test-threads=1
    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "requires isolated global disk state; run with --ignored --test-threads=1"]
    async fn produce_zip_archives_only_the_prefix() {
        let store = fresh_store().await;
        store
            .make_bucket("dltest", &MakeBucketOptions::default())
            .await
            .unwrap();
        for (key, data) in [("p/a.txt", b"alpha".as_slice()), ("p/sub/b.txt", b"bravo"), ("other/c.txt", b"charlie")] {
            let mut reader = PutObjReader::from_vec(data.to_vec());
            store.put_object("dltest", key, &mut reader, &ObjectOptions::default()).await.unwrap();
        }

        let (sink, mut read_half) = tokio::io::duplex(64 * 1024);
        let producer = tokio::spawn(produce_zip(
            store.clone(),
            "dltest".to_string(),
            "p/".to_string(),
            ZipStreamMethod::Stored,
            sink,
        ));
        let mut bytes = Vec::new();
        read_half.read_to_end(&mut bytes).await.unwrap();
        producer.await.unwrap().expect("produce_zip ok");

        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("a.zip");
        let out = dir.path().join("out");
        tokio::fs::write(&zip_path, &bytes).await.unwrap();
        let entries = rustfs_zip::extract_zip_simple(&zip_path, &out).await.unwrap();

        let names: Vec<String> = entries.iter().map(|e| e.name.trim_end_matches('/').to_string()).collect();
        assert!(names.contains(&"p/a.txt".to_string()), "names: {names:?}");
        assert!(names.contains(&"p/sub/b.txt".to_string()), "names: {names:?}");
        assert!(!names.iter().any(|n| n.contains("other")), "prefix leak: {names:?}");
        assert_eq!(tokio::fs::read(out.join("p/a.txt")).await.unwrap(), b"alpha");
    }
}
