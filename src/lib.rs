//! Node.js NAPI bindings for rust-oci-client
//!
//! Provides a JS-adapted API over the native `oci-client` crate via NAPI-RS.
//! Types are translated to JS-friendly equivalents (e.g. Rust enums become
//! discriminated structs, `bytes::Bytes` becomes `Buffer`).

mod error;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use oci_client::client::{
    Certificate as NativeCertificate, CertificateEncoding as NativeCertificateEncoding,
    ClientConfig as NativeClientConfig, ClientProtocol as NativeClientProtocol,
    Config as NativeConfig, ImageData as NativeImageData, ImageLayer as NativeImageLayer,
    PushResponse as NativePushResponse,
};
use oci_client::errors::OciDistributionError;
use oci_client::manifest::{
    ImageIndexEntry, OciDescriptor, OciImageIndex, OciImageManifest, OciManifest, Platform,
};
use oci_client::secrets::RegistryAuth as NativeRegistryAuth;
use oci_client::{Client, Reference};
use oci_spec::image::{Arch, Os};

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

use error::oci_error;
use futures_util::TryStreamExt;
use tokio_util::io::ReaderStream;

fn parse_reference(env: Env, value: &str) -> Result<Reference> {
    Reference::from_str(value).map_err(|e| oci_error(&env, e))
}

// ============================================================================
// Authentication Types
// ============================================================================

/// Authentication method for registry access.
/// Wraps native `RegistryAuth`.
#[napi(string_enum)]
pub enum RegistryAuthType {
    /// Access the registry anonymously
    Anonymous,
    /// Access the registry using HTTP Basic authentication
    Basic,
    /// Access the registry using Bearer token authentication
    Bearer,
}

/// Registry authentication configuration.
/// Use `auth_type` to specify the authentication method.
#[napi(object)]
pub struct RegistryAuth {
    /// The type of authentication to use
    pub auth_type: RegistryAuthType,
    /// Username for Basic auth (required when auth_type is Basic)
    pub username: Option<String>,
    /// Password for Basic auth (required when auth_type is Basic)
    pub password: Option<String>,
    /// Token for Bearer auth (required when auth_type is Bearer)
    pub token: Option<String>,
}

impl RegistryAuth {
    fn to_native(&self) -> Result<NativeRegistryAuth> {
        match self.auth_type {
            RegistryAuthType::Anonymous => Ok(NativeRegistryAuth::Anonymous),
            RegistryAuthType::Basic => {
                let username = self
                    .username
                    .clone()
                    .ok_or_else(|| Error::from_reason("username required for Basic auth"))?;
                let password = self
                    .password
                    .clone()
                    .ok_or_else(|| Error::from_reason("password required for Basic auth"))?;
                Ok(NativeRegistryAuth::Basic(username, password))
            }
            RegistryAuthType::Bearer => {
                let token = self
                    .token
                    .clone()
                    .ok_or_else(|| Error::from_reason("token required for Bearer auth"))?;
                Ok(NativeRegistryAuth::Bearer(token))
            }
        }
    }
}

// ============================================================================
// Client Configuration Types
// ============================================================================

/// Protocol configuration for the client.
/// Wraps native `ClientProtocol`.
#[napi(string_enum)]
pub enum ClientProtocol {
    /// Use HTTP (insecure)
    Http,
    /// Use HTTPS (secure, default)
    Https,
    /// Use HTTPS except for specified registries
    HttpsExcept,
}

/// Certificate encoding format.
/// Wraps native `CertificateEncoding`.
#[napi(string_enum)]
pub enum CertificateEncoding {
    /// DER encoded certificate
    Der,
    /// PEM encoded certificate
    Pem,
}

/// A x509 certificate for TLS.
/// Wraps native `Certificate`.
#[napi(object)]
pub struct Certificate {
    /// Which encoding is used by the certificate
    pub encoding: CertificateEncoding,
    /// Certificate data as bytes
    pub data: Buffer,
}

impl Certificate {
    fn to_native(&self) -> NativeCertificate {
        NativeCertificate {
            encoding: match self.encoding {
                CertificateEncoding::Der => NativeCertificateEncoding::Der,
                CertificateEncoding::Pem => NativeCertificateEncoding::Pem,
            },
            data: self.data.to_vec(),
        }
    }
}

/// Platform filter for selecting a specific platform from multi-platform images.
/// When set, the client will automatically select the matching platform from Image Index manifests.
#[napi(object)]
pub struct PlatformFilter {
    /// Operating system (e.g., "linux", "windows", "darwin")
    pub os: String,
    /// CPU architecture (e.g., "amd64", "arm64", "arm")
    pub architecture: String,
    /// Optional variant (e.g., "v7" for arm/v7)
    pub variant: Option<String>,
}

/// Client configuration options.
/// Wraps native `ClientConfig`.
#[napi(object)]
pub struct ClientConfig {
    /// Which protocol the client should use (default: Https)
    pub protocol: Option<ClientProtocol>,
    /// List of registries to exclude from HTTPS (used with HttpsExcept protocol)
    pub https_except_registries: Option<Vec<String>>,
    /// **DANGER**: Accept invalid TLS certificates (default: false).
    /// Setting this to `true` disables all certificate verification, making
    /// connections vulnerable to man-in-the-middle attacks. Only use for
    /// local development or testing with self-signed certificates.
    /// Prefer `extraRootCertificates` for production self-signed setups.
    pub accept_invalid_certificates: Option<bool>,
    /// Use monolithic push for pushing blobs (default: false)
    pub use_monolithic_push: Option<bool>,
    /// Extra root certificates to trust (for self-signed certificates)
    pub extra_root_certificates: Option<Vec<Certificate>>,
    /// Exclusive root certificates -- disables system roots and only uses these
    pub tls_certs_only: Option<Vec<Certificate>>,
    /// Maximum number of concurrent uploads during push (default: 16)
    pub max_concurrent_upload: Option<u32>,
    /// Maximum number of concurrent downloads during pull (default: 16)
    pub max_concurrent_download: Option<u32>,
    /// Default token expiration in seconds (default: 60)
    pub default_token_expiration_secs: Option<u32>,
    /// Read timeout in milliseconds
    pub read_timeout_ms: Option<u32>,
    /// Connect timeout in milliseconds
    pub connect_timeout_ms: Option<u32>,
    /// HTTPS proxy URL
    pub https_proxy: Option<String>,
    /// HTTP proxy URL
    pub http_proxy: Option<String>,
    /// No proxy list (comma-separated)
    pub no_proxy: Option<String>,
    /// Platform filter for multi-platform image selection.
    /// When set, automatically selects the matching platform from Image Index manifests.
    pub platform: Option<PlatformFilter>,
}

impl ClientConfig {
    fn to_native(&self) -> NativeClientConfig {
        let mut config = NativeClientConfig::default();

        if let Some(protocol) = &self.protocol {
            config.protocol = match protocol {
                ClientProtocol::Http => NativeClientProtocol::Http,
                ClientProtocol::Https => NativeClientProtocol::Https,
                ClientProtocol::HttpsExcept => {
                    let registries = self.https_except_registries.clone().unwrap_or_default();
                    NativeClientProtocol::HttpsExcept(registries)
                }
            };
        }

        if let Some(accept) = self.accept_invalid_certificates {
            config.accept_invalid_certificates = accept;
        }

        if let Some(monolithic) = self.use_monolithic_push {
            config.use_monolithic_push = monolithic;
        }

        if let Some(certs) = &self.extra_root_certificates {
            config.extra_root_certificates = certs.iter().map(|c| c.to_native()).collect();
        }

        if let Some(certs) = &self.tls_certs_only {
            config.tls_certs_only = certs.iter().map(|c| c.to_native()).collect();
        }

        if let Some(max) = self.max_concurrent_upload {
            config.max_concurrent_upload = max as usize;
        }

        if let Some(max) = self.max_concurrent_download {
            config.max_concurrent_download = max as usize;
        }

        if let Some(secs) = self.default_token_expiration_secs {
            config.default_token_expiration_secs = secs as usize;
        }

        if let Some(ms) = self.read_timeout_ms {
            config.read_timeout = Some(Duration::from_millis(ms as u64));
        }

        if let Some(ms) = self.connect_timeout_ms {
            config.connect_timeout = Some(Duration::from_millis(ms as u64));
        }

        if let Some(proxy) = &self.https_proxy {
            config.https_proxy = Some(proxy.clone());
        }

        if let Some(proxy) = &self.http_proxy {
            config.http_proxy = Some(proxy.clone());
        }

        if let Some(no_proxy) = &self.no_proxy {
            config.no_proxy = Some(no_proxy.clone());
        }

        if let Some(p) = &self.platform {
            let os = Os::from(p.os.as_str());
            let arch = Arch::from(p.architecture.as_str());
            let variant = p.variant.clone();
            config.platform_resolver = Some(Box::new(move |manifests| {
                manifests
                    .iter()
                    .find(|e| {
                        e.platform.as_ref().is_some_and(|plat| {
                            plat.os == os
                                && plat.architecture == arch
                                && (variant.is_none() || plat.variant == variant)
                        })
                    })
                    .map(|e| e.digest.clone())
            }));
        }

        config
    }
}

// ============================================================================
// Data Types
// ============================================================================

/// An image layer with data and metadata.
/// Wraps native `ImageLayer`.
#[napi(object)]
pub struct ImageLayer {
    /// The layer data as raw bytes
    pub data: Buffer,
    /// The media type of this layer
    pub media_type: String,
    /// Optional annotations for this layer
    pub annotations: Option<BTreeMap<String, String>>,
}

impl ImageLayer {
    fn from_native(layer: NativeImageLayer) -> Self {
        ImageLayer {
            data: Buffer::from(Vec::<u8>::from(layer.data)),
            media_type: layer.media_type,
            annotations: layer.annotations,
        }
    }

    /// Moves the NAPI `Buffer` into a native layer without copying.
    ///
    /// The JS `Buffer` must not be mutated until the owning `push` Promise settles
    /// (same contract as `fs.write` / `socket.write`).
    fn into_native(self) -> NativeImageLayer {
        NativeImageLayer::new(
            bytes::Bytes::from_owner(self.data),
            self.media_type,
            self.annotations,
        )
    }
}

/// Configuration object for an image.
/// Wraps native `Config`.
#[napi(object)]
pub struct Config {
    /// The config data as raw bytes
    pub data: Buffer,
    /// The media type of this config
    pub media_type: String,
    /// Optional annotations for this config
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Config {
    fn from_native(config: NativeConfig) -> Self {
        Config {
            data: Buffer::from(Vec::<u8>::from(config.data)),
            media_type: config.media_type,
            annotations: config.annotations,
        }
    }

    /// Moves the NAPI `Buffer` into a native config without copying.
    ///
    /// The JS `Buffer` must not be mutated until the owning `push` Promise settles
    /// (same contract as `fs.write` / `socket.write`).
    fn into_native(self) -> NativeConfig {
        NativeConfig::new(
            bytes::Bytes::from_owner(self.data),
            self.media_type,
            self.annotations,
        )
    }
}

/// Data returned from pulling an image.
/// Wraps native `ImageData`.
#[napi(object)]
pub struct ImageData {
    /// The layers of the image
    pub layers: Vec<ImageLayer>,
    /// The digest of the image (if available)
    pub digest: Option<String>,
    /// The configuration object of the image
    pub config: Config,
    /// The manifest (if available)
    pub manifest: Option<ImageManifest>,
}

impl ImageData {
    fn from_native(data: NativeImageData) -> Self {
        ImageData {
            layers: data
                .layers
                .into_iter()
                .map(ImageLayer::from_native)
                .collect(),
            digest: data.digest,
            config: Config::from_native(data.config),
            manifest: data.manifest.map(|m| m.into()),
        }
    }
}

/// Response from pushing an image.
/// Wraps native `PushResponse`.
#[napi(object)]
pub struct PushResponse {
    /// Pullable URL for the config
    pub config_url: String,
    /// Pullable URL for the manifest
    pub manifest_url: String,
}

impl From<NativePushResponse> for PushResponse {
    fn from(resp: NativePushResponse) -> Self {
        PushResponse {
            config_url: resp.config_url,
            manifest_url: resp.manifest_url,
        }
    }
}

// ============================================================================
// Manifest Types - For structured manifest handling
// ============================================================================

/// OCI Descriptor - describes a content addressable resource.
#[napi(object)]
pub struct Descriptor {
    /// The media type of the referenced content
    pub media_type: String,
    /// The digest of the targeted content
    pub digest: String,
    /// The size in bytes of the targeted content
    pub size: i64,
    /// Optional list of URLs from which this object may be downloaded
    pub urls: Option<Vec<String>>,
    /// Optional annotations for this descriptor
    pub annotations: Option<BTreeMap<String, String>>,
    /// Optional artifact type when the descriptor points to an artifact
    pub artifact_type: Option<String>,
}

impl From<OciDescriptor> for Descriptor {
    fn from(d: OciDescriptor) -> Self {
        Descriptor {
            media_type: d.media_type,
            digest: d.digest,
            size: d.size,
            urls: d.urls,
            annotations: d.annotations,
            artifact_type: d.artifact_type,
        }
    }
}

impl From<Descriptor> for OciDescriptor {
    fn from(d: Descriptor) -> Self {
        OciDescriptor {
            media_type: d.media_type,
            digest: d.digest,
            size: d.size,
            urls: d.urls,
            annotations: d.annotations,
            artifact_type: d.artifact_type,
        }
    }
}

/// Platform specification for an image.
#[napi(object)]
pub struct PlatformSpec {
    /// CPU architecture
    pub architecture: String,
    /// Operating system
    pub os: String,
    /// OS version
    pub os_version: Option<String>,
    /// OS features
    pub os_features: Option<Vec<String>>,
    /// CPU variant
    pub variant: Option<String>,
    /// Additional features
    pub features: Option<Vec<String>>,
}

impl From<Platform> for PlatformSpec {
    fn from(p: Platform) -> Self {
        PlatformSpec {
            architecture: p.architecture.to_string(),
            os: p.os.to_string(),
            os_version: p.os_version,
            os_features: p.os_features,
            variant: p.variant,
            features: p.features,
        }
    }
}

impl From<PlatformSpec> for Platform {
    fn from(p: PlatformSpec) -> Self {
        Platform {
            architecture: Arch::from(p.architecture.as_str()),
            os: Os::from(p.os.as_str()),
            os_version: p.os_version,
            os_features: p.os_features,
            variant: p.variant,
            features: p.features,
        }
    }
}

/// An entry in an image index manifest.
#[napi(object)]
pub struct ManifestEntry {
    /// Media type of the manifest
    pub media_type: String,
    /// Digest of the manifest
    pub digest: String,
    /// Size in bytes
    pub size: i64,
    /// Platform specification
    pub platform: Option<PlatformSpec>,
    /// Annotations
    pub annotations: Option<BTreeMap<String, String>>,
    /// Optional artifact type for referrers
    pub artifact_type: Option<String>,
}

impl From<ImageIndexEntry> for ManifestEntry {
    fn from(e: ImageIndexEntry) -> Self {
        ManifestEntry {
            media_type: e.media_type,
            digest: e.digest,
            size: e.size,
            platform: e.platform.map(|p| p.into()),
            annotations: e.annotations,
            artifact_type: e.artifact_type,
        }
    }
}

impl From<ManifestEntry> for ImageIndexEntry {
    fn from(e: ManifestEntry) -> Self {
        ImageIndexEntry {
            media_type: e.media_type,
            digest: e.digest,
            size: e.size,
            platform: e.platform.map(|p| p.into()),
            annotations: e.annotations,
            artifact_type: e.artifact_type,
        }
    }
}

/// OCI Image Index (manifest list).
#[napi(object)]
pub struct ImageIndex {
    /// Schema version (always 2)
    pub schema_version: u8,
    /// Media type of this manifest
    pub media_type: Option<String>,
    /// List of manifests for specific platforms
    pub manifests: Vec<ManifestEntry>,
    /// Artifact type
    pub artifact_type: Option<String>,
    /// Annotations
    pub annotations: Option<BTreeMap<String, String>>,
}

impl From<OciImageIndex> for ImageIndex {
    fn from(idx: OciImageIndex) -> Self {
        ImageIndex {
            schema_version: idx.schema_version,
            media_type: idx.media_type,
            manifests: idx.manifests.into_iter().map(|m| m.into()).collect(),
            artifact_type: idx.artifact_type,
            annotations: idx.annotations,
        }
    }
}

impl From<ImageIndex> for OciImageIndex {
    fn from(idx: ImageIndex) -> Self {
        OciImageIndex {
            schema_version: idx.schema_version,
            media_type: idx.media_type,
            manifests: idx.manifests.into_iter().map(|m| m.into()).collect(),
            artifact_type: idx.artifact_type,
            annotations: idx.annotations,
        }
    }
}

/// OCI Image Manifest.
#[napi(object)]
pub struct ImageManifest {
    /// Schema version (always 2)
    pub schema_version: u8,
    /// Media type of this manifest
    pub media_type: Option<String>,
    /// The image configuration descriptor
    pub config: Descriptor,
    /// The image layers
    pub layers: Vec<Descriptor>,
    /// Subject descriptor (for referrers)
    pub subject: Option<Descriptor>,
    /// Artifact type
    pub artifact_type: Option<String>,
    /// Annotations
    pub annotations: Option<BTreeMap<String, String>>,
}

impl From<OciImageManifest> for ImageManifest {
    fn from(m: OciImageManifest) -> Self {
        ImageManifest {
            schema_version: m.schema_version,
            media_type: m.media_type,
            config: m.config.into(),
            layers: m.layers.into_iter().map(|l| l.into()).collect(),
            subject: m.subject.map(|s| s.into()),
            artifact_type: m.artifact_type,
            annotations: m.annotations,
        }
    }
}

impl From<ImageManifest> for OciImageManifest {
    fn from(m: ImageManifest) -> Self {
        OciImageManifest {
            schema_version: m.schema_version,
            media_type: m.media_type,
            config: m.config.into(),
            layers: m.layers.into_iter().map(|l| l.into()).collect(),
            subject: m.subject.map(|s| s.into()),
            artifact_type: m.artifact_type,
            annotations: m.annotations,
        }
    }
}

// ============================================================================
// Union type for OciManifest (can be Image or ImageIndex)
// ============================================================================

/// Manifest type discriminator.
#[napi(string_enum)]
pub enum ManifestType {
    /// An OCI image manifest
    Image,
    /// An OCI image index (manifest list)
    ImageIndex,
}

/// OCI Manifest - can be either an Image manifest or an ImageIndex.
/// Check `manifest_type` to determine which field is populated.
#[napi(object)]
pub struct Manifest {
    /// The type of manifest
    pub manifest_type: ManifestType,
    /// The image manifest (populated when manifest_type is Image)
    pub image: Option<ImageManifest>,
    /// The image index (populated when manifest_type is ImageIndex)
    pub image_index: Option<ImageIndex>,
}

impl From<OciManifest> for Manifest {
    fn from(m: OciManifest) -> Self {
        match m {
            OciManifest::Image(img) => Manifest {
                manifest_type: ManifestType::Image,
                image: Some(img.into()),
                image_index: None,
            },
            OciManifest::ImageIndex(idx) => Manifest {
                manifest_type: ManifestType::ImageIndex,
                image: None,
                image_index: Some(idx.into()),
            },
        }
    }
}

impl TryFrom<Manifest> for OciManifest {
    type Error = OciDistributionError;

    fn try_from(m: Manifest) -> std::result::Result<Self, Self::Error> {
        match m.manifest_type {
            ManifestType::Image => {
                let img = m.image.ok_or_else(|| {
                    OciDistributionError::ManifestParsingError(
                        "image field required for Image manifest type".to_string(),
                    )
                })?;
                Ok(OciManifest::Image(img.into()))
            }
            ManifestType::ImageIndex => {
                let idx = m.image_index.ok_or_else(|| {
                    OciDistributionError::ManifestParsingError(
                        "image_index field required for ImageIndex manifest type".to_string(),
                    )
                })?;
                Ok(OciManifest::ImageIndex(idx.into()))
            }
        }
    }
}

/// Result from pull_manifest containing both manifest and digest.
#[napi(object)]
pub struct PullManifestResult {
    /// The pulled manifest
    pub manifest: Manifest,
    /// The digest of the manifest
    pub digest: String,
}

// ============================================================================
// Result Types for functions that return tuples
// ============================================================================

/// Result from pull_image_manifest containing both manifest and digest.
#[napi(object)]
pub struct PullImageManifestResult {
    /// The pulled image manifest
    pub manifest: ImageManifest,
    /// The digest of the manifest
    pub digest: String,
}

/// Result from pull_image_manifest_and_list_digest.
#[napi(object)]
pub struct PullImageManifestAndListDigestResult {
    /// The pulled image manifest
    pub manifest: ImageManifest,
    /// The digest of the manifest
    pub digest: String,
    /// The digest of the parent manifest list/image index, if the manifest was resolved from one
    pub list_digest: Option<String>,
}

/// Result from pull_manifest_and_config_and_list_digest.
#[napi(object)]
pub struct PullManifestAndConfigAndListDigestResult {
    /// The pulled image manifest
    pub manifest: ImageManifest,
    /// The digest of the manifest
    pub digest: String,
    /// The config JSON as a string
    pub config: String,
    /// The digest of the parent manifest list/image index, if the manifest was resolved from one
    pub list_digest: Option<String>,
}

// ============================================================================
// Main Client
// ============================================================================

/// OCI Distribution client for interacting with OCI registries.
/// Provides pull, push, and manifest operations.
///
/// # Authentication
///
/// Methods that accept an `auth` parameter (`pull`, `push`, `pull_image_manifest`,
/// `pull_manifest`, `pull_manifest_raw`, `push_manifest_list`, `list_tags`,
/// `fetch_manifest_digest`, `catalog`, `pull_image_manifest_and_list_digest`,
/// `pull_manifest_and_config_and_list_digest`) store credentials internally via
/// the native `store_auth_if_needed` and then use them for the request.
///
/// Methods without an `auth` parameter (`pull_blob`, `pull_blob_to_file`,
/// `push_blob`, `push_blob_from_file`, `push_manifest`, `blob_exists`,
/// `mount_blob`, `pull_referrers`) rely on credentials already stored by
/// a prior explicit-auth call or by [`store_auth`](OciClient::store_auth).
#[napi]
pub struct OciClient {
    inner: parking_lot::Mutex<Option<Client>>,
}

impl Default for OciClient {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl OciClient {
    fn client(&self) -> Result<Client> {
        self.inner
            .lock()
            .clone()
            .ok_or_else(|| Error::from_reason("Client is closed"))
    }

    /// Create a new OCI client with default configuration.
    #[napi(constructor)]
    pub fn new() -> Self {
        OciClient {
            inner: parking_lot::Mutex::new(Some(Client::default())),
        }
    }

    /// Create a new OCI client with custom configuration.
    ///
    /// Throws if the configuration is invalid (e.g. malformed CA certificate,
    /// bad proxy URL). This differs from the parent crate's `Client::new` which
    /// silently falls back to defaults — in Node.js there is no `tracing`
    /// subscriber to surface those warnings, so we fail explicitly instead.
    #[napi(factory)]
    pub fn with_config(env: Env, config: ClientConfig) -> Result<Self> {
        let native_config = config.to_native();
        let client = Client::try_from(native_config).map_err(|e| oci_error(&env, e))?;
        Ok(OciClient {
            inner: parking_lot::Mutex::new(Some(client)),
        })
    }

    /// Explicitly release the underlying connection pool.
    ///
    /// This is **idempotent** — calling `close()` on an already-closed client
    /// is a safe no-op that returns `false`.
    ///
    /// **In-flight operations are not cancelled.** Any async method that already
    /// cloned the inner client will run to completion; only the shared pool
    /// reference held by the `OciClient` is dropped. The connection pool is
    /// fully reclaimed when the last in-flight clone finishes.
    ///
    /// After `close()`, all subsequent method calls will throw `"Client is closed"`.
    #[napi]
    pub fn close(&self) -> bool {
        self.inner.lock().take().is_some()
    }

    /// Pull an image from the registry.
    ///
    /// Wraps native `Client::pull`.
    ///
    /// Returns ImageData containing layers (as Buffers), config, and manifest.
    #[napi]
    pub fn pull(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
        accepted_media_types: Vec<String>,
    ) -> Result<AsyncBlock<ImageData>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;
        let media_types: Vec<String> = accepted_media_types;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                let refs: Vec<&str> = media_types.iter().map(|s| s.as_str()).collect();
                Ok(client.pull(&reference, &native_auth, refs).await)
            },
            move |env, result| match result {
                Ok(image_data) => Ok(ImageData::from_native(image_data)),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Push an image to the registry.
    ///
    /// Wraps native `Client::push`.
    ///
    /// Do not mutate `layers[].data` or `config.data` until this Promise settles.
    /// The Buffers are borrowed for the duration of the upload (same contract as
    /// Node `fs.write` / `socket.write`).
    ///
    /// Returns PushResponse with config and manifest URLs.
    #[napi]
    pub fn push(
        &self,
        env: Env,
        image_ref: String,
        layers: Vec<ImageLayer>,
        config: Config,
        auth: RegistryAuth,
        manifest: Option<ImageManifest>,
    ) -> Result<AsyncBlock<PushResponse>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image_ref)?;
        let native_auth = auth.to_native()?;
        let native_layers: Vec<NativeImageLayer> =
            layers.into_iter().map(ImageLayer::into_native).collect();
        let native_config = config.into_native();
        let native_manifest: Option<OciImageManifest> = manifest.map(|m| m.into());

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .push(
                        &reference,
                        &native_layers,
                        native_config,
                        &native_auth,
                        native_manifest,
                    )
                    .await)
            },
            move |env, result| match result {
                Ok(response) => Ok(response.into()),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull referrers for an artifact (OCI 1.1 Referrers API).
    ///
    /// Wraps native `Client::pull_referrers`.
    ///
    /// Returns an ImageIndex containing the referrers.
    #[napi]
    pub fn pull_referrers(
        &self,
        env: Env,
        image: String,
        artifact_type: Option<String>,
    ) -> Result<AsyncBlock<ImageIndex>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .pull_referrers(&reference, artifact_type.as_deref())
                    .await)
            },
            move |env, result| match result {
                Ok(referrers) => Ok(referrers.into()),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Push a manifest list (image index) to the registry.
    ///
    /// Wraps native `Client::push_manifest_list`.
    ///
    /// Returns the manifest URL.
    #[napi]
    pub fn push_manifest_list(
        &self,
        env: Env,
        reference: String,
        auth: RegistryAuth,
        manifest: ImageIndex,
    ) -> Result<AsyncBlock<String>> {
        let client = self.client()?;
        let ref_parsed = parse_reference(env, &reference)?;
        let native_auth = auth.to_native()?;
        let native_manifest: OciImageIndex = manifest.into();

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .push_manifest_list(&ref_parsed, &native_auth, native_manifest)
                    .await)
            },
            move |env, result| match result {
                Ok(url) => Ok(url),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull an image manifest from the registry.
    ///
    /// Wraps native `Client::pull_image_manifest`.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    ///
    /// Returns both the manifest and its digest.
    #[napi]
    pub fn pull_image_manifest(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
    ) -> Result<AsyncBlock<PullImageManifestResult>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.pull_image_manifest(&reference, &native_auth).await) },
            move |env, result| match result {
                Ok((manifest, digest)) => Ok(PullImageManifestResult {
                    manifest: manifest.into(),
                    digest,
                }),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    // ========================================================================
    // Additional utility methods for complete API coverage
    // ========================================================================

    /// Store authentication credentials for a registry.
    ///
    /// Wraps native `Client::store_auth_if_needed`: credentials are stored only
    /// if the registry does not already have stored auth. Once stored, all
    /// subsequent operations against the same registry (`pull_blob`, `push_blob`,
    /// `push_manifest`, etc.) will use them automatically.
    #[napi]
    pub async fn store_auth(&self, registry: String, auth: RegistryAuth) -> Result<()> {
        let client = self.client()?;
        let native_auth = auth.to_native()?;
        client.store_auth_if_needed(&registry, &native_auth).await;
        Ok(())
    }

    /// Pull a manifest (either image or index) from the registry.
    /// Returns the manifest and its digest.
    #[napi]
    pub fn pull_manifest(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
    ) -> Result<AsyncBlock<PullManifestResult>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.pull_manifest(&reference, &native_auth).await) },
            move |env, result| match result {
                Ok((manifest, digest)) => Ok(PullManifestResult {
                    manifest: manifest.into(),
                    digest,
                }),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull a manifest as raw bytes.
    #[napi]
    pub fn pull_manifest_raw(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
        accepted_media_types: Vec<String>,
    ) -> Result<AsyncBlock<Buffer>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;
        let media_types: Vec<String> = accepted_media_types;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                let refs: Vec<&str> = media_types.iter().map(|s| s.as_str()).collect();
                Ok(client
                    .pull_manifest_raw(&reference, &native_auth, &refs)
                    .await)
            },
            move |env, result| match result {
                Ok((bytes, _digest)) => Ok(Buffer::from(Vec::<u8>::from(bytes))),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Push a manifest to the registry.
    /// Returns the manifest URL.
    #[napi]
    pub fn push_manifest(
        &self,
        env: Env,
        image: String,
        manifest: Manifest,
    ) -> Result<AsyncBlock<String>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;

        let native_manifest: OciManifest = manifest.try_into().map_err(|e| oci_error(&env, e))?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.push_manifest(&reference, &native_manifest).await) },
            move |env, result| match result {
                Ok(url) => Ok(url),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Push a blob to the registry.
    /// Returns the blob digest.
    ///
    /// Do not mutate `data` until this Promise settles. The Buffer is borrowed
    /// for the duration of the upload (same contract as Node `fs.write` /
    /// `socket.write`).
    #[napi]
    pub fn push_blob(
        &self,
        env: Env,
        image: String,
        data: Buffer,
        digest: String,
    ) -> Result<AsyncBlock<String>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let blob_data = bytes::Bytes::from_owner(data);

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.push_blob(&reference, blob_data, &digest).await) },
            move |env, result| match result {
                Ok(url) => Ok(url),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull a blob from the registry.
    /// Returns the blob data.
    #[napi]
    pub fn pull_blob(&self, env: Env, image: String, digest: String) -> Result<AsyncBlock<Buffer>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                let mut data = Vec::new();
                Ok(client
                    .pull_blob(&reference, digest.as_str(), &mut data)
                    .await
                    .map(|_| data))
            },
            move |env, result| match result {
                Ok(data) => Ok(Buffer::from(data)),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull a blob from the registry and write it to `path`.
    ///
    /// The destination file is created or truncated. Bytes are copied from the
    /// registry socket to disk and never enter a JavaScript `Buffer`. The
    /// digest is verified when the write completes.
    #[napi]
    pub fn pull_blob_to_file(
        &self,
        env: Env,
        image: String,
        digest: String,
        path: String,
    ) -> Result<AsyncBlock<()>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(match tokio::fs::File::create(&path).await {
                    Ok(file) => client.pull_blob(&reference, digest.as_str(), file).await,
                    Err(err) => Err(err.into()),
                })
            },
            move |env, result| match result {
                Ok(()) => Ok(()),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Push a blob from a file at `path`.
    ///
    /// The file is streamed to the registry. `digest` must be the SHA-256
    /// digest of the file contents (`sha256:<hex>`).
    #[napi]
    pub fn push_blob_from_file(
        &self,
        env: Env,
        image: String,
        path: String,
        digest: String,
    ) -> Result<AsyncBlock<String>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(match tokio::fs::File::open(&path).await {
                    Ok(file) => {
                        let stream = ReaderStream::new(file).map_err(OciDistributionError::from);
                        client
                            .push_blob_stream(&reference, stream, &digest, None)
                            .await
                    }
                    Err(err) => Err(err.into()),
                })
            },
            move |env, result| match result {
                Ok(url) => Ok(url),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Check if a blob exists in the registry.
    #[napi]
    pub fn blob_exists(&self, env: Env, image: String, digest: String) -> Result<AsyncBlock<bool>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.blob_exists(&reference, &digest).await) },
            move |env, result| match result {
                Ok(exists) => Ok(exists),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Mount a blob from another repository.
    #[napi]
    pub fn mount_blob(
        &self,
        env: Env,
        target: String,
        source: String,
        digest: String,
    ) -> Result<AsyncBlock<()>> {
        let client = self.client()?;
        let target_ref = parse_reference(env, &target)?;
        let source_ref = parse_reference(env, &source)?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.mount_blob(&target_ref, &source_ref, &digest).await) },
            move |env, result| match result {
                Ok(()) => Ok(()),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// List tags for a repository.
    #[napi]
    pub fn list_tags(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<AsyncBlock<Vec<String>>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .list_tags(
                        &reference,
                        &native_auth,
                        n.map(|v| v as usize),
                        last.as_deref(),
                    )
                    .await)
            },
            move |env, result| match result {
                Ok(tags) => Ok(tags.tags),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Fetch manifest digest without downloading the full manifest.
    #[napi]
    pub fn fetch_manifest_digest(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
    ) -> Result<AsyncBlock<String>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move { Ok(client.fetch_manifest_digest(&reference, &native_auth).await) },
            move |env, result| match result {
                Ok(digest) => Ok(digest),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// List available repositories in the registry.
    /// Implements the OCI Distribution Spec catalog endpoint (`/v2/_catalog`).
    /// Supports pagination via `n` (page size) and `last` (last repo from previous page).
    #[napi]
    pub fn catalog(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
        n: Option<u32>,
        last: Option<String>,
    ) -> Result<AsyncBlock<Vec<String>>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .catalog(
                        &reference,
                        &native_auth,
                        n.map(|v| v as usize),
                        last.as_deref(),
                    )
                    .await)
            },
            move |env, result| match result {
                Ok(catalog) => Ok(catalog.repositories),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull an image manifest and the parent manifest list digest from the registry.
    ///
    /// Like `pullImageManifest`, but also returns the digest of the parent
    /// manifest list/image index when the resolved manifest came from one.
    /// This is needed for signature verification on multi-arch images.
    #[napi]
    pub fn pull_image_manifest_and_list_digest(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
    ) -> Result<AsyncBlock<PullImageManifestAndListDigestResult>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .pull_image_manifest_and_list_digest(&reference, &native_auth)
                    .await)
            },
            move |env, result| match result {
                Ok((manifest, digest, list_digest)) => Ok(PullImageManifestAndListDigestResult {
                    manifest: manifest.into(),
                    digest,
                    list_digest,
                }),
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }

    /// Pull a manifest, its config, and the parent manifest list digest from the registry.
    ///
    /// Returns the image manifest, its digest, the config JSON as a string,
    /// and the parent manifest list/image index digest when applicable.
    #[napi]
    pub fn pull_manifest_and_config_and_list_digest(
        &self,
        env: Env,
        image: String,
        auth: RegistryAuth,
    ) -> Result<AsyncBlock<PullManifestAndConfigAndListDigestResult>> {
        let client = self.client()?;
        let reference = parse_reference(env, &image)?;
        let native_auth = auth.to_native()?;

        AsyncBlockBuilder::build_with_map(
            &env,
            async move {
                Ok(client
                    .pull_manifest_and_config_and_list_digest(&reference, &native_auth)
                    .await)
            },
            move |env, result| match result {
                Ok((manifest, digest, config, list_digest)) => {
                    Ok(PullManifestAndConfigAndListDigestResult {
                        manifest: manifest.into(),
                        digest,
                        config,
                        list_digest,
                    })
                }
                Err(err) => Err(oci_error(&env, err)),
            },
        )
    }
}

// ============================================================================
// OCI Annotation Constants
// ============================================================================

/// Date and time on which the image was built (string, date-time as defined by RFC 3339)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_CREATED: &str = "org.opencontainers.image.created";

/// Contact details of the people or organization responsible for the image (freeform string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_AUTHORS: &str = "org.opencontainers.image.authors";

/// URL to find more information on the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_URL: &str = "org.opencontainers.image.url";

/// URL to get documentation on the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_DOCUMENTATION: &str = "org.opencontainers.image.documentation";

/// URL to get source code for building the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_SOURCE: &str = "org.opencontainers.image.source";

/// Version of the packaged software
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_VERSION: &str = "org.opencontainers.image.version";

/// Source control revision identifier for the packaged software
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_REVISION: &str = "org.opencontainers.image.revision";

/// Name of the distributing entity, organization or individual
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_VENDOR: &str = "org.opencontainers.image.vendor";

/// License(s) under which contained software is distributed as an SPDX License Expression
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_LICENSES: &str = "org.opencontainers.image.licenses";

/// Name of the reference for a target (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_REF_NAME: &str = "org.opencontainers.image.ref.name";

/// Human-readable title of the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_TITLE: &str = "org.opencontainers.image.title";

/// Human-readable description of the software packaged in the image (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_DESCRIPTION: &str = "org.opencontainers.image.description";

/// Digest of the image this image is based on (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_BASE_DIGEST: &str = "org.opencontainers.image.base.digest";

/// Image reference of the image this image is based on (string)
#[napi]
pub const ORG_OPENCONTAINERS_IMAGE_BASE_NAME: &str = "org.opencontainers.image.base.name";

// ============================================================================
// OCI Media Type Constants
// ============================================================================

/// The mediatype for WASM layers
#[napi]
pub const WASM_LAYER_MEDIA_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";

/// The mediatype for a WASM image config
#[napi]
pub const WASM_CONFIG_MEDIA_TYPE: &str = "application/vnd.wasm.config.v1+json";

/// The mediatype for a Docker v2 schema 2 manifest
#[napi]
pub const IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The mediatype for a Docker v2 schema 2 manifest list
#[napi]
pub const IMAGE_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// The mediatype for an OCI image index manifest
#[napi]
pub const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// The mediatype for an OCI image manifest
#[napi]
pub const OCI_IMAGE_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// The mediatype for an image config (manifest)
#[napi]
pub const IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// The mediatype that Docker uses for image configs
#[napi]
pub const IMAGE_DOCKER_CONFIG_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";

/// The mediatype for a layer
#[napi]
pub const IMAGE_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

/// The mediatype for a layer that is gzipped
#[napi]
pub const IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// The mediatype that Docker uses for a layer that is tarred
#[napi]
pub const IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.docker.image.rootfs.diff.tar";

/// The mediatype that Docker uses for a layer that is gzipped
#[napi]
pub const IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE: &str =
    "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// The mediatype for a layer that is nondistributable
#[napi]
pub const IMAGE_LAYER_NONDISTRIBUTABLE_MEDIA_TYPE: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar";

/// The mediatype for a layer that is nondistributable and gzipped
#[napi]
pub const IMAGE_LAYER_NONDISTRIBUTABLE_GZIP_MEDIA_TYPE: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";

// ============================================================================
// Helper functions
// ============================================================================

/// Create an anonymous authentication object.
#[napi]
pub fn anonymous_auth() -> RegistryAuth {
    RegistryAuth {
        auth_type: RegistryAuthType::Anonymous,
        username: None,
        password: None,
        token: None,
    }
}

/// Create a basic authentication object.
#[napi]
pub fn basic_auth(username: String, password: String) -> RegistryAuth {
    RegistryAuth {
        auth_type: RegistryAuthType::Basic,
        username: Some(username),
        password: Some(password),
        token: None,
    }
}

/// Create a bearer token authentication object.
#[napi]
pub fn bearer_auth(token: String) -> RegistryAuth {
    RegistryAuth {
        auth_type: RegistryAuthType::Bearer,
        username: None,
        password: None,
        token: Some(token),
    }
}
