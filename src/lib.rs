use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use serde_json::{Map, Number, Value};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

pub const TRUSTMEE_COLLECTION_TYPE: &str = "https://trustmee.invalid/cmw/verification-input";
pub const TRUSTMEE_EAT_PROFILE: &str = "https://trustmee.invalid/eat/component-evidence";
pub const WASM_MEDIA_TYPE: &str = "application/wasm";
pub const CMW_INDICATOR_ENDORSEMENT: u64 = 2;
pub const CMW_INDICATOR_EVIDENCE: u64 = 4;

const COMPONENT_ID_PREFIX: &str = "component-";
const CMW_COLLECTION_TYPE_KEY: &str = "__cmwc_t";
const EVIDENCE_LABEL: &str = "evidence";
const VERIFIER_LABEL: &str = "verifier";
const TRUSTMEE_EAT_JSON_MEDIA_TYPE: &str = "application/eat-ucs+json";

#[derive(Debug, Error)]
pub enum Error {
    #[error("evidence must not be empty")]
    EmptyEvidence,
    #[error("evidence_media_type must not be empty")]
    EmptyEvidenceMediaType,
    #[error("component bytes must not be empty")]
    EmptyComponentBytes,
    #[error("component_id must start with `component-` followed by 64 lowercase hex characters")]
    MalformedComponentId,
    #[error("endorsement label must not be empty")]
    EmptyEndorsementLabel,
    #[error("endorsement media_type must not be empty for label `{0}`")]
    EmptyEndorsementMediaType(String),
    #[error("duplicate or reserved endorsement label `{0}`")]
    DuplicateEndorsementLabel(String),
    #[error("nonce must not be empty")]
    EmptyNonce,
    #[error("unsupported hash algorithm `{0}`; only sha256 is accepted")]
    UnsupportedHashAlgorithm(String),
    #[error("no component source set; call component(), component_id(), or component_id_from_bytes() on the builder")]
    MissingComponentSource,
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// How the verifier component is identified or included in the CMW output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentSource {
    /// Include the component bytes in the output (stapled); ID is derived via SHA-256.
    Bytes(Vec<u8>),
    /// Reference the component by its pre-computed ID; no bytes included in output.
    Id(String),
    /// Compute the component ID from bytes via SHA-256 but do not include the bytes in output.
    BytesForId(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildInput {
    pub evidence: Vec<u8>,
    pub evidence_media_type: String,
    pub component_source: ComponentSource,
    pub endorsements: Vec<Endorsement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    pub label: String,
    pub media_type: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RestRequestOptions {
    pub policy_ids: Vec<String>,
    pub runtime_data: Option<RuntimeData>,
    pub init_data: Option<InitDataInput>,
    pub runtime_data_hash_algorithm: Option<String>,
}

impl Default for RestRequestOptions {
    fn default() -> Self {
        Self {
            policy_ids: vec!["default".to_string()],
            runtime_data: None,
            init_data: None,
            runtime_data_hash_algorithm: None,
        }
    }
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeData {
    Raw(#[serde_as(as = "Base64<UrlSafe, Unpadded>")] Vec<u8>),
    Structured(Value),
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InitDataInput {
    InitDataDigest(#[serde_as(as = "Base64<UrlSafe, Unpadded>")] Vec<u8>),
    InitDataToml(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BuiltTrustMeeInput {
    pub component_id: String,
    pub cmw_json_bytes: Vec<u8>,
    pub cmw_json_value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RestAttestationBody {
    pub verification_requests: Vec<RestVerificationRequest>,
    pub policy_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RestVerificationRequest {
    pub tee: String,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<RuntimeData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_data: Option<InitDataInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_data_hash_algorithm: Option<String>,
}

pub fn component_id_from_bytes(bytes: &[u8]) -> String {
    format!(
        "{COMPONENT_ID_PREFIX}{}",
        hex::encode(Sha256::digest(bytes))
    )
}

pub fn build_trustmee_json_cmw(input: &BuildInput) -> Result<BuiltTrustMeeInput> {
    validate_build_input(input)?;

    let component_id = resolve_component_id(&input.component_source);
    let eat_media_type =
        format!("{TRUSTMEE_EAT_JSON_MEDIA_TYPE}; eat_profile=\"{TRUSTMEE_EAT_PROFILE}\"");

    let eat_json = build_trustmee_eat_json(&component_id, input);
    let eat_bytes = serde_json::to_vec(&eat_json)?;

    let mut cmw = Map::new();
    cmw.insert(
        CMW_COLLECTION_TYPE_KEY.to_string(),
        Value::String(TRUSTMEE_COLLECTION_TYPE.to_string()),
    );
    cmw.insert(
        EVIDENCE_LABEL.to_string(),
        Value::Array(vec![
            Value::String(eat_media_type),
            Value::String(encode_base64url(&eat_bytes)),
            Value::Number(Number::from(CMW_INDICATOR_EVIDENCE)),
        ]),
    );

    if let ComponentSource::Bytes(component) = &input.component_source {
        cmw.insert(
            VERIFIER_LABEL.to_string(),
            Value::Array(vec![
                Value::String(WASM_MEDIA_TYPE.to_string()),
                Value::String(encode_base64url(component)),
                Value::Number(Number::from(CMW_INDICATOR_ENDORSEMENT)),
            ]),
        );
    }

    for endorsement in &input.endorsements {
        cmw.insert(
            endorsement.label.clone(),
            Value::Array(vec![
                Value::String(endorsement.media_type.clone()),
                Value::String(encode_base64url(&endorsement.payload)),
                Value::Number(Number::from(CMW_INDICATOR_ENDORSEMENT)),
            ]),
        );
    }

    let cmw_json_value = Value::Object(cmw);
    let cmw_json_bytes = serde_json::to_vec(&cmw_json_value)?;

    Ok(BuiltTrustMeeInput {
        component_id,
        cmw_json_bytes,
        cmw_json_value,
    })
}

pub fn build_rest_attestation_body(
    input: &BuildInput,
    options: &RestRequestOptions,
) -> Result<RestAttestationBody> {
    if let Some(algorithm) = options.runtime_data_hash_algorithm.as_deref() {
        validate_hash_algorithm(algorithm)?;
    }

    let built = build_trustmee_json_cmw(input)?;
    let request = RestVerificationRequest {
        tee: "sample".to_string(),
        evidence: encode_base64url(&built.cmw_json_bytes),
        runtime_data: options.runtime_data.clone(),
        init_data: options.init_data.clone(),
        runtime_data_hash_algorithm: options.runtime_data_hash_algorithm.clone(),
    };

    let policy_ids = if options.policy_ids.is_empty() {
        vec!["default".to_string()]
    } else {
        options.policy_ids.clone()
    };

    Ok(RestAttestationBody {
        verification_requests: vec![request],
        policy_ids,
    })
}

fn build_trustmee_eat_json(component_id: &str, input: &BuildInput) -> Value {
    let mut eat = Map::new();
    eat.insert(
        "eat_profile".to_string(),
        Value::String(TRUSTMEE_EAT_PROFILE.to_string()),
    );
    eat.insert(
        "component_id".to_string(),
        Value::String(component_id.to_string()),
    );
    eat.insert(
        "evidence_type".to_string(),
        Value::String(input.evidence_media_type.clone()),
    );
    eat.insert(
        "evidence".to_string(),
        Value::String(encode_base64url(&input.evidence)),
    );
    Value::Object(eat)
}

fn validate_build_input(input: &BuildInput) -> Result<()> {
    if input.evidence.is_empty() {
        return Err(Error::EmptyEvidence);
    }
    if input.evidence_media_type.trim().is_empty() {
        return Err(Error::EmptyEvidenceMediaType);
    }
    match &input.component_source {
        ComponentSource::Bytes(bytes) | ComponentSource::BytesForId(bytes) => {
            if bytes.is_empty() {
                return Err(Error::EmptyComponentBytes);
            }
        }
        ComponentSource::Id(id) => validate_component_id(id)?,
    }
    validate_endorsements(input)?;
    Ok(())
}

fn validate_endorsements(input: &BuildInput) -> Result<()> {
    let mut seen = HashSet::new();
    seen.insert(CMW_COLLECTION_TYPE_KEY);
    seen.insert(EVIDENCE_LABEL);
    if matches!(input.component_source, ComponentSource::Bytes(_)) {
        seen.insert(VERIFIER_LABEL);
    }

    for endorsement in &input.endorsements {
        if endorsement.label.trim().is_empty() {
            return Err(Error::EmptyEndorsementLabel);
        }
        if endorsement.media_type.trim().is_empty() {
            return Err(Error::EmptyEndorsementMediaType(endorsement.label.clone()));
        }
        if !seen.insert(endorsement.label.as_str()) {
            return Err(Error::DuplicateEndorsementLabel(endorsement.label.clone()));
        }
    }
    Ok(())
}

fn resolve_component_id(source: &ComponentSource) -> String {
    match source {
        ComponentSource::Bytes(bytes) | ComponentSource::BytesForId(bytes) => {
            component_id_from_bytes(bytes)
        }
        ComponentSource::Id(id) => id.clone(),
    }
}

fn validate_component_id(component_id: &str) -> Result<()> {
    let valid = component_id
        .strip_prefix(COMPONENT_ID_PREFIX)
        .map(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .unwrap_or(false);

    if valid {
        Ok(())
    } else {
        Err(Error::MalformedComponentId)
    }
}

fn validate_hash_algorithm(algorithm: &str) -> Result<()> {
    if algorithm == "sha256" {
        Ok(())
    } else {
        Err(Error::UnsupportedHashAlgorithm(algorithm.to_string()))
    }
}

fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// ── Builders ──────────────────────────────────────────────────────────────────

impl Endorsement {
    /// Construct an [`Endorsement`] directly from its three required fields.
    pub fn new(
        label: impl Into<String>,
        media_type: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            label: label.into(),
            media_type: media_type.into(),
            payload: payload.into(),
        }
    }
}

/// Builder for [`BuildInput`].
pub struct BuildInputBuilder {
    evidence: Vec<u8>,
    evidence_media_type: String,
    component_source: Option<ComponentSource>,
    endorsements: Vec<Endorsement>,
}

impl BuildInput {
    pub fn builder(evidence: impl Into<Vec<u8>>) -> BuildInputBuilder {
        BuildInputBuilder {
            evidence: evidence.into(),
            evidence_media_type: "application/octet-stream".to_string(),
            component_source: None,
            endorsements: Vec::new(),
        }
    }
}

impl BuildInputBuilder {
    /// Override the default evidence media type (`application/octet-stream`).
    pub fn evidence_media_type(mut self, media_type: impl Into<String>) -> Self {
        self.evidence_media_type = media_type.into();
        self
    }

    /// Staple the component bytes in the output; ID is derived via SHA-256.
    pub fn component(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.component_source = Some(ComponentSource::Bytes(bytes.into()));
        self
    }

    /// Reference the component by a pre-computed ID; no bytes are included in the output.
    pub fn component_id(mut self, id: impl Into<String>) -> Self {
        self.component_source = Some(ComponentSource::Id(id.into()));
        self
    }

    /// Derive the component ID from bytes via SHA-256 without stapling the bytes in the output.
    pub fn component_id_from_bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.component_source = Some(ComponentSource::BytesForId(bytes.into()));
        self
    }

    /// Add an [`Endorsement`] to the input.
    pub fn endorsement(mut self, endorsement: Endorsement) -> Self {
        self.endorsements.push(endorsement);
        self
    }

    pub fn build(self) -> Result<BuildInput> {
        let component_source = self
            .component_source
            .ok_or(Error::MissingComponentSource)?;
        Ok(BuildInput {
            evidence: self.evidence,
            evidence_media_type: self.evidence_media_type,
            component_source,
            endorsements: self.endorsements,
        })
    }
}

/// Builder for [`RestRequestOptions`].
pub struct RestRequestOptionsBuilder {
    policy_ids: Vec<String>,
    runtime_data: Option<RuntimeData>,
    init_data: Option<InitDataInput>,
    runtime_data_hash_algorithm: Option<String>,
}

impl RestRequestOptions {
    pub fn builder() -> RestRequestOptionsBuilder {
        RestRequestOptionsBuilder {
            policy_ids: Vec::new(),
            runtime_data: None,
            init_data: None,
            runtime_data_hash_algorithm: None,
        }
    }
}

impl RestRequestOptionsBuilder {
    /// Append a single policy ID. Without this call, `"default"` is used.
    pub fn policy_id(mut self, id: impl Into<String>) -> Self {
        self.policy_ids.push(id.into());
        self
    }

    /// Replace the policy IDs list in full.
    pub fn policy_ids(mut self, ids: impl Into<Vec<String>>) -> Self {
        self.policy_ids = ids.into();
        self
    }

    pub fn runtime_data(mut self, data: RuntimeData) -> Self {
        self.runtime_data = Some(data);
        self
    }

    pub fn init_data(mut self, data: InitDataInput) -> Self {
        self.init_data = Some(data);
        self
    }

    pub fn runtime_data_hash_algorithm(mut self, algo: impl Into<String>) -> Self {
        self.runtime_data_hash_algorithm = Some(algo.into());
        self
    }

    pub fn build(self) -> RestRequestOptions {
        RestRequestOptions {
            policy_ids: self.policy_ids,
            runtime_data: self.runtime_data,
            init_data: self.init_data,
            runtime_data_hash_algorithm: self.runtime_data_hash_algorithm,
        }
    }
}

// ── KBS types ─────────────────────────────────────────────────────────────────

/// Request body for POST `/kbs/v0/auth` (step 1 of the RCAR protocol).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct KbsAuthRequest {
    pub version: String,
    pub tee: String,
    #[serde(rename = "extra-params")]
    pub extra_params: Value,
}

/// Init-data section of a KBS attest request.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct KbsInitData {
    /// `"json"` or `"toml"`.
    pub format: String,
    /// Plaintext body of the init data.
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct KbsRuntimeData {
    pub nonce: String,
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct KbsTeeEvidence {
    /// The TrustMee CMW JSON placed verbatim (not base64-encoded).
    pub primary_evidence: Value,
    /// JSON-string mapping of secondary TEE evidence; empty for simple guests.
    pub additional_evidence: String,
}

/// Request body for POST `/kbs/v0/attest` (step 3 of the RCAR protocol).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct KbsAttestRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_data: Option<KbsInitData>,
    pub runtime_data: KbsRuntimeData,
    pub tee_evidence: KbsTeeEvidence,
}

/// Options required to build a KBS attest request.
#[derive(Clone, Debug, PartialEq)]
pub struct KbsRequestOptions {
    /// Nonce received from the KBS challenge (POST `/kbs/v0/auth` response).
    pub nonce: String,
    /// JWK-formatted TEE public key as a raw JSON value.
    pub tee_pubkey: Value,
    pub init_data: Option<KbsInitData>,
}

/// Build the body for POST `/kbs/v0/auth`.
///
/// The TEE type is always `"sample"` as required by TrustMee WASM verifiers.
pub fn build_kbs_auth_request() -> KbsAuthRequest {
    KbsAuthRequest {
        version: "0.1.1".to_string(),
        tee: "sample".to_string(),
        extra_params: Value::Object(Map::new()),
    }
}

/// Build the body for POST `/kbs/v0/attest`.
///
/// The TrustMee CMW is built from `input` and placed verbatim (not
/// base64-encoded) in `tee-evidence.primary_evidence`.
pub fn build_kbs_attest_request(
    input: &BuildInput,
    options: &KbsRequestOptions,
) -> Result<KbsAttestRequest> {
    if options.nonce.trim().is_empty() {
        return Err(Error::EmptyNonce);
    }

    let built = build_trustmee_json_cmw(input)?;

    Ok(KbsAttestRequest {
        init_data: options.init_data.clone(),
        runtime_data: KbsRuntimeData {
            nonce: options.nonce.clone(),
            tee_pubkey: options.tee_pubkey.clone(),
        },
        tee_evidence: KbsTeeEvidence {
            primary_evidence: built.cmw_json_value,
            additional_evidence: String::new(),
        },
    })
}

// ── KbsRequestOptions builder ─────────────────────────────────────────────────

pub struct KbsRequestOptionsBuilder {
    nonce: String,
    tee_pubkey: Value,
    init_data: Option<KbsInitData>,
}

impl KbsRequestOptions {
    /// Start building with the required nonce and TEE public key.
    pub fn builder(nonce: impl Into<String>, tee_pubkey: Value) -> KbsRequestOptionsBuilder {
        KbsRequestOptionsBuilder {
            nonce: nonce.into(),
            tee_pubkey,
            init_data: None,
        }
    }
}

impl KbsRequestOptionsBuilder {
    pub fn init_data(mut self, data: KbsInitData) -> Self {
        self.init_data = Some(data);
        self
    }

    pub fn build(self) -> KbsRequestOptions {
        KbsRequestOptions {
            nonce: self.nonce,
            tee_pubkey: self.tee_pubkey,
            init_data: self.init_data,
        }
    }
}

#[cfg(feature = "confidential-containers")]
pub mod trustmee_coco_client {
    use anyhow::{Context, Result};
    use reqwest::Client;
    use std::time::Duration;

    use crate::{BuildInput, BuiltTrustMeeInput, Endorsement, build_trustmee_json_cmw};

    const DEFAULT_COCO_EVIDENCE_URL: &str = "http://127.0.0.1:8006/aa/evidence";
    const DUMMY_COMPONENT_ID: &str = "component-0000000000000000000000000000000000000000000000000000000000000000";

    // -------------------------------------------------------------------------
    // 1. The Builder
    // -------------------------------------------------------------------------

    pub struct CocoClientBuilder {
        url: String,
        timeout: Duration,
    }

    impl CocoClientBuilder {
        pub fn new() -> Self {
            Self {
                url: DEFAULT_COCO_EVIDENCE_URL.to_string(),
                timeout: Duration::from_secs(30),
            }
        }

        /// Overrides the default Attestation Agent URL
        pub fn url(mut self, url: impl Into<String>) -> Self {
            self.url = url.into();
            self
        }

        /// Overrides the default HTTP request timeout
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }

        /// Builds and returns the stateful CocoClient, initializing the connection pool
        pub fn build(self) -> Result<CocoClient> {
            let http_client = Client::builder()
                .timeout(self.timeout)
                .build()
                .context("failed to build async reqwest client")?;

            Ok(CocoClient {
                http_client,
                aa_url: self.url,
            })
        }
    }

    // -------------------------------------------------------------------------
    // 2. The Stateful Client
    // -------------------------------------------------------------------------

    #[derive(Clone)]
    pub struct CocoClient {
        http_client: Client, // Automatically shares the internal connection pool when cloned
        aa_url: String,
    }

    impl CocoClient {
        /// Starts the builder pattern
        pub fn builder() -> CocoClientBuilder {
            CocoClientBuilder::new()
        }

        /// The underlying method to fetch raw evidence bytes
        async fn fetch_evidence(&self, runtime_data_bytes: Option<&[u8]>) -> Result<Vec<u8>> {
            let mut url = self.aa_url.clone();
            
            // Append the runtime data exactly as a UTF-8 string to satisfy the AA/TDX hardware
            if let Some(bytes) = runtime_data_bytes {
                let runtime_data_str = std::str::from_utf8(bytes)
                    .context("runtime_data is not a valid UTF-8 string")?;
                    
                if !url.contains("runtime_data=") {
                    url.push_str("?runtime_data=");
                } 
                url.push_str(runtime_data_str);
            }

            let response = self.http_client
                .get(&url)
                .send()
                .await
                .context("failed to send async request to CoCo API")?;

            if !response.status().is_success() {
                anyhow::bail!(
                    "AA API returned error status: {} - {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
            }

            response
                .bytes()
                .await
                .context("failed to read CoCo API response bytes")
                .map(|b| b.to_vec())
        }

        /// Fetches the evidence and formats it into the TrustMee CMW JSON structure
        pub async fn build_trustmee_json_cmw_coco(
                    &self,
                    runtime_data: Option<&[u8]>,
                    verifier_component_id: Option<String>,
                    verifier_component: Option<Vec<u8>>,
                    evidence_media_type: Option<String>,
                    endorsements: Option<Vec<Endorsement>>,
                ) -> Result<BuiltTrustMeeInput> {
                    // 1. Fetch the hardware evidence
                    let evidence = self.fetch_evidence(runtime_data).await?;

                    let media_type = evidence_media_type.unwrap_or_else(|| "application/octet-stream".into());

                    let component_id =
                        verifier_component_id.or_else(|| Some(DUMMY_COMPONENT_ID.into()));

                    // 2. Construct the BildInput
                    let input = BuildInput {
                        evidence,
                        evidence_media_type: media_type,
                        component: verifier_component,
                        component_id,
                        endorsements: endorsements.unwrap_or_default(),
                    };

                    // 3. Pass both the input and the build options to the core CMW builder
                    build_trustmee_json_cmw(&input)
        }
    }
}
