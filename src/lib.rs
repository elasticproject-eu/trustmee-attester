use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

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
const WASM_VERIFIER_NAME: &str = "wasm-verification-component";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildInput {
    pub evidence: Vec<u8>,
    pub evidence_media_type: String,
    pub component: Option<Vec<u8>>,
    pub component_id: Option<String>,
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
    pub tee: String,
    pub policy_ids: Vec<String>,
    pub runtime_data: Option<RuntimeData>,
    pub init_data: Option<InitDataInput>,
    pub runtime_data_hash_algorithm: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RuntimeData {
    Raw(Vec<u8>),
    Structured(Value),
}

impl Serialize for RuntimeData {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Raw(bytes) => map.serialize_entry("raw", &encode_base64url(bytes))?,
            Self::Structured(value) => map.serialize_entry("structured", value)?,
        }
        map.end()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum InitDataInput {
    InitDataDigest(Vec<u8>),
    InitDataToml(String),
}

impl Serialize for InitDataInput {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::InitDataDigest(bytes) => {
                map.serialize_entry("init_data_digest", &encode_base64url(bytes))?
            }
            Self::InitDataToml(toml) => map.serialize_entry("init_data_toml", toml)?,
        }
        map.end()
    }
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
    pub verifier: String,
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

    let component_id = resolve_component_id(input)?;
    let eat_media_type =
        format!("{TRUSTMEE_EAT_JSON_MEDIA_TYPE}; eat_profile=\"{TRUSTMEE_EAT_PROFILE}\"");

    let eat_json = build_trustmee_eat_json(&component_id, input);
    let eat_bytes = serde_json::to_vec(&eat_json).context("serialize TrustMee EAT JSON")?;

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

    if let Some(component) = &input.component {
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
    let cmw_json_bytes =
        serde_json::to_vec(&cmw_json_value).context("serialize TrustMee JSON CMW")?;

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
    if options.tee.trim().is_empty() {
        bail!("tee must not be empty for REST output");
    }

    if let Some(algorithm) = options.runtime_data_hash_algorithm.as_deref() {
        validate_hash_algorithm(algorithm)?;
    }

    let built = build_trustmee_json_cmw(input)?;
    let request = RestVerificationRequest {
        tee: options.tee.clone(),
        evidence: encode_base64url(&built.cmw_json_bytes),
        verifier: WASM_VERIFIER_NAME.to_string(),
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
        bail!("evidence must not be empty");
    }

    if input.evidence_media_type.trim().is_empty() {
        bail!("evidence_media_type must not be empty");
    }

    if let Some(component) = &input.component {
        if component.is_empty() {
            bail!("component must not be empty when provided");
        }
    }

    if let Some(component_id) = input.component_id.as_deref() {
        validate_component_id(component_id)?;
    }

    if input.component.is_none() && input.component_id.is_none() {
        bail!("either component or component_id must be provided");
    }

    validate_endorsements(input)?;
    Ok(())
}

fn validate_endorsements(input: &BuildInput) -> Result<()> {
    let mut seen = HashSet::new();
    seen.insert(CMW_COLLECTION_TYPE_KEY);
    seen.insert(EVIDENCE_LABEL);
    if input.component.is_some() {
        seen.insert(VERIFIER_LABEL);
    }

    for endorsement in &input.endorsements {
        if endorsement.label.trim().is_empty() {
            bail!("endorsement label must not be empty");
        }

        if endorsement.media_type.trim().is_empty() {
            bail!(
                "endorsement media_type must not be empty for label `{}`",
                endorsement.label
            );
        }

        if !seen.insert(endorsement.label.as_str()) {
            bail!(
                "duplicate or reserved endorsement label `{}`",
                endorsement.label
            );
        }
    }

    Ok(())
}

fn resolve_component_id(input: &BuildInput) -> Result<String> {
    match (&input.component, input.component_id.as_deref()) {
        (Some(component), Some(component_id)) => {
            let derived = component_id_from_bytes(component);
            if component_id != derived {
                bail!(
                    "component_id `{component_id}` does not match the provided component bytes; expected `{derived}`"
                );
            }
            Ok(derived)
        }
        (Some(component), None) => Ok(component_id_from_bytes(component)),
        (None, Some(component_id)) => Ok(component_id.to_string()),
        (None, None) => bail!("either component or component_id must be provided"),
    }
}

fn validate_component_id(component_id: &str) -> Result<()> {
    let digest = component_id
        .strip_prefix(COMPONENT_ID_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("component_id must start with `{COMPONENT_ID_PREFIX}`"))?;

    if digest.len() != 64 {
        bail!("component_id digest must be 64 lowercase hex characters");
    }

    if !digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("component_id digest must be lowercase hex");
    }

    Ok(())
}

fn validate_hash_algorithm(algorithm: &str) -> Result<()> {
    match algorithm {
        "sha256" | "sha384" | "sha512" => Ok(()),
        other => bail!(
            "unsupported runtime_data_hash_algorithm `{other}`; expected sha256, sha384, or sha512"
        ),
    }
}

fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
