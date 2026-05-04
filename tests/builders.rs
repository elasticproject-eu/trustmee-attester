use trustmee_attester::{
    build_kbs_auth_request, build_kbs_attest_request, build_rest_attestation_body,
    build_trustmee_json_cmw, component_id_from_bytes, BuildInput, Endorsement, Error,
    InitDataInput, KbsInitData, KbsRequestOptions, RestRequestOptions, RuntimeData,
    CMW_INDICATOR_ENDORSEMENT, CMW_INDICATOR_EVIDENCE, TRUSTMEE_COLLECTION_TYPE,
    TRUSTMEE_EAT_PROFILE, WASM_MEDIA_TYPE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

#[test]
fn component_id_from_bytes_uses_sha256_prefix_format() {
    let bytes = b"\0asmstandalone-test-component";
    let expected = format!("component-{}", hex::encode(Sha256::digest(bytes)));
    assert_eq!(component_id_from_bytes(bytes), expected);
}

#[test]
fn trustmee_json_cmw_contains_expected_records_and_encodings() {
    let component = b"\0asmcomponent".to_vec();
    let evidence = b"sample evidence".to_vec();
    let endorsement_payload = b"collateral".to_vec();

    let built = build_trustmee_json_cmw(
        &BuildInput::builder(evidence.clone())
            .component(component.clone())
            .endorsement(Endorsement::new(
                "snp-collateral",
                "application/vnd.example.collateral",
                endorsement_payload.clone(),
            ))
            .build()
            .expect("construct BuildInput"),
    )
    .expect("build trustmee json cmw");

    let cmw = built.cmw_json_value.as_object().expect("cmw object");
    assert_eq!(
        cmw.get("__cmwc_t").and_then(Value::as_str),
        Some(TRUSTMEE_COLLECTION_TYPE)
    );

    let evidence_record = cmw
        .get("evidence")
        .and_then(Value::as_array)
        .expect("evidence record");
    let expected_eat_media_type =
        format!("application/eat-ucs+json; eat_profile=\"{TRUSTMEE_EAT_PROFILE}\"");
    assert_eq!(
        evidence_record[0].as_str(),
        Some(expected_eat_media_type.as_str())
    );
    assert_eq!(evidence_record[2].as_u64(), Some(CMW_INDICATOR_EVIDENCE));

    let eat_bytes = URL_SAFE_NO_PAD
        .decode(evidence_record[1].as_str().expect("eat payload"))
        .expect("decode eat payload");
    let eat_json: Value = serde_json::from_slice(&eat_bytes).expect("parse eat json");
    assert_eq!(eat_json["eat_profile"], TRUSTMEE_EAT_PROFILE);
    assert_eq!(
        eat_json["component_id"],
        component_id_from_bytes(&component)
    );
    assert_eq!(eat_json["evidence_type"], "application/octet-stream");
    assert_eq!(
        eat_json["evidence"],
        Value::String(URL_SAFE_NO_PAD.encode(&evidence))
    );

    let component_record = cmw
        .get("verifier")
        .and_then(Value::as_array)
        .expect("verifier record");
    assert_eq!(component_record[0].as_str(), Some(WASM_MEDIA_TYPE));
    assert_eq!(
        component_record[2].as_u64(),
        Some(CMW_INDICATOR_ENDORSEMENT)
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(component_record[1].as_str().expect("component payload"))
            .expect("decode component payload"),
        component
    );

    let endorsement_record = cmw
        .get("snp-collateral")
        .and_then(Value::as_array)
        .expect("endorsement record");
    assert_eq!(
        endorsement_record[0].as_str(),
        Some("application/vnd.example.collateral")
    );
    assert_eq!(
        endorsement_record[2].as_u64(),
        Some(CMW_INDICATOR_ENDORSEMENT)
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(endorsement_record[1].as_str().expect("endorsement payload"))
            .expect("decode endorsement payload"),
        endorsement_payload
    );

    assert_eq!(
        built.cmw_json_bytes,
        serde_json::to_vec(&built.cmw_json_value).expect("serialize cmw"),
    );
}

#[test]
fn trustmee_json_cmw_supports_component_id_only_mode() {
    let component_id = component_id_from_bytes(b"\0asmunstapled");
    let built = build_trustmee_json_cmw(
        &BuildInput::builder(b"evidence")
            .component_id(component_id.clone())
            .build()
            .expect("construct BuildInput"),
    )
    .expect("build component id only cmw");

    let cmw = built.cmw_json_value.as_object().expect("cmw object");
    assert!(
        cmw.get("verifier").is_none(),
        "component should not be stapled"
    );
    assert_eq!(built.component_id, component_id);
}

#[test]
fn trustmee_json_cmw_supports_bytes_for_id_mode() {
    let component = b"\0asmcomponent".to_vec();
    let expected_id = component_id_from_bytes(&component);

    let built = build_trustmee_json_cmw(
        &BuildInput::builder(b"evidence")
            .component_id_from_bytes(component)
            .build()
            .expect("construct BuildInput"),
    )
    .expect("build bytes-for-id cmw");

    let cmw = built.cmw_json_value.as_object().expect("cmw object");
    assert!(
        cmw.get("verifier").is_none(),
        "component should not be stapled in BytesForId mode"
    );
    assert_eq!(built.component_id, expected_id);
}

#[test]
fn builder_requires_component_source() {
    let err = BuildInput::builder(b"evidence")
        .build()
        .expect_err("missing component source should fail");

    assert!(matches!(err, Error::MissingComponentSource));
}

#[test]
fn empty_component_bytes_is_rejected() {
    let err = build_trustmee_json_cmw(
        &BuildInput::builder(b"evidence")
            .component(vec![])
            .build()
            .expect("construct BuildInput"),
    )
    .expect_err("empty component should fail");

    assert!(matches!(err, Error::EmptyComponentBytes));
}

#[test]
fn malformed_component_id_is_rejected() {
    let err = build_trustmee_json_cmw(
        &BuildInput::builder(b"evidence")
            .component_id("component-not-lowercase-hex")
            .build()
            .expect("construct BuildInput"),
    )
    .expect_err("malformed component id should fail");

    assert!(matches!(err, Error::MalformedComponentId));
}

#[test]
fn duplicate_endorsement_labels_are_rejected() {
    let err = build_trustmee_json_cmw(
        &BuildInput::builder(b"evidence")
            .component(b"\0asmcomponent")
            .endorsement(Endorsement::new("dup", "application/test", vec![1]))
            .endorsement(Endorsement::new("dup", "application/test", vec![2]))
            .build()
            .expect("construct BuildInput"),
    )
    .expect_err("duplicate labels should fail");

    assert!(matches!(err, Error::DuplicateEndorsementLabel(label) if label == "dup"));
}

#[test]
fn reserved_labels_are_rejected() {
    let err = build_trustmee_json_cmw(
        &BuildInput::builder(b"evidence")
            .component(b"\0asmcomponent")
            .endorsement(Endorsement::new("evidence", "application/test", vec![1]))
            .build()
            .expect("construct BuildInput"),
    )
    .expect_err("reserved label should fail");

    assert!(matches!(err, Error::DuplicateEndorsementLabel(label) if label == "evidence"));
}

#[test]
fn rest_body_wraps_cmw_and_defaults_policy_ids() {
    let input = BuildInput::builder(b"evidence")
        .component(b"\0asmcomponent")
        .endorsement(Endorsement::new("collateral", "application/test", vec![1, 2, 3]))
        .build()
        .expect("construct BuildInput");

    let trustmee = build_trustmee_json_cmw(&input).expect("build cmw");
    let rest = build_rest_attestation_body(&input, &RestRequestOptions::builder().build())
        .expect("build rest body");

    assert_eq!(rest.policy_ids, vec!["default"]);
    assert_eq!(rest.verification_requests.len(), 1);

    let request = &rest.verification_requests[0];
    assert_eq!(request.tee, "sample");
    assert_eq!(
        request.evidence,
        URL_SAFE_NO_PAD.encode(&trustmee.cmw_json_bytes)
    );
}

#[test]
fn rest_request_options_default_has_default_policy_id() {
    let options = RestRequestOptions::default();
    assert_eq!(options.policy_ids, vec!["default"]);
    assert!(options.runtime_data.is_none());
    assert!(options.init_data.is_none());
    assert!(options.runtime_data_hash_algorithm.is_none());
}

#[test]
fn rest_options_builder_policy_ids_replace() {
    let options = RestRequestOptions::builder()
        .policy_id("custom-a")
        .policy_id("custom-b")
        .build();

    assert_eq!(options.policy_ids, vec!["custom-a", "custom-b"]);
}

#[test]
fn runtime_data_and_init_data_serialize_in_rest_shape() {
    let input = BuildInput::builder(b"evidence")
        .component(b"\0asmcomponent")
        .build()
        .expect("construct BuildInput");

    let rest = build_rest_attestation_body(
        &input,
        &RestRequestOptions::builder()
            .policy_id("custom")
            .runtime_data(RuntimeData::Raw(b"runtime-data".to_vec()))
            .init_data(InitDataInput::InitDataToml("algorithm = \"sha256\"".to_string()))
            .runtime_data_hash_algorithm("sha256")
            .build(),
    )
    .expect("build rest body with optional fields");

    let as_json = serde_json::to_value(&rest).expect("serialize rest body");
    assert_eq!(as_json["policy_ids"], json!(["custom"]));
    assert_eq!(as_json["verification_requests"][0]["tee"], "sample");
    assert_eq!(
        as_json["verification_requests"][0]["runtime_data"]["raw"],
        Value::String(URL_SAFE_NO_PAD.encode(b"runtime-data"))
    );
    assert_eq!(
        as_json["verification_requests"][0]["init_data"]["init_data_toml"],
        Value::String("algorithm = \"sha256\"".to_string())
    );
    assert_eq!(
        as_json["verification_requests"][0]["runtime_data_hash_algorithm"],
        Value::String("sha256".to_string())
    );
}

#[test]
fn runtime_and_init_variants_serialize_as_expected() {
    assert_eq!(
        serde_json::to_value(RuntimeData::Structured(json!({"k": "v"}))).expect("serialize"),
        json!({"structured": {"k": "v"}})
    );
    assert_eq!(
        serde_json::to_value(RuntimeData::Raw(vec![0x01, 0x02])).expect("serialize"),
        json!({"raw": URL_SAFE_NO_PAD.encode([0x01, 0x02])})
    );
    assert_eq!(
        serde_json::to_value(InitDataInput::InitDataDigest(vec![0x03, 0x04])).expect("serialize"),
        json!({"init_data_digest": URL_SAFE_NO_PAD.encode([0x03, 0x04])})
    );
    assert_eq!(
        serde_json::to_value(InitDataInput::InitDataToml("key = \"value\"".to_string()))
            .expect("serialize"),
        json!({"init_data_toml": "key = \"value\""})
    );
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn vendored_sample_files_can_build_trustmee_cmw() {
    let root = crate_root();
    let evidence =
        fs::read(root.join("test_data/snp_evidence.json")).expect("read sample evidence");
    let component = fs::read(root.join("test_data/snp_verifier_component.wasm"))
        .expect("read sample component");

    let built = build_trustmee_json_cmw(
        &BuildInput::builder(evidence)
            .component(component.clone())
            .build()
            .expect("construct BuildInput"),
    )
    .expect("build trustmee cmw from vendored sample files");

    assert_eq!(built.component_id, component_id_from_bytes(&component));
    assert_eq!(built.cmw_json_value["__cmwc_t"], TRUSTMEE_COLLECTION_TYPE);
}

#[test]
fn cli_can_generate_trustmee_output_from_vendored_sample_files() {
    let root = crate_root();
    let output = Command::new(env!("CARGO_BIN_EXE_trustmee-attester"))
        .current_dir(&root)
        .args([
            "--mode",
            "trustmee",
            "--evidence",
            "test_data/snp_evidence.json",
            "--component",
            "test_data/snp_verifier_component.wasm",
            "--compact",
        ])
        .output()
        .expect("run trustmee-attester binary");

    assert!(
        output.status.success(),
        "binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout: Value = serde_json::from_slice(&output.stdout).expect("parse CLI JSON output");
    assert_eq!(stdout["__cmwc_t"], TRUSTMEE_COLLECTION_TYPE);
    assert!(
        stdout.get("verifier").is_some(),
        "CLI output should staple component"
    );
}

// ── KBS tests ─────────────────────────────────────────────────────────────────

fn sample_tee_pubkey() -> Value {
    let root = crate_root();
    let bytes = fs::read(root.join("test_data/sample_tee_pubkey.json")).expect("read tee pubkey");
    serde_json::from_slice(&bytes).expect("parse tee pubkey json")
}

#[test]
fn kbs_auth_request_has_correct_shape() {
    let auth = build_kbs_auth_request();

    assert_eq!(auth.version, "0.1.1");
    assert_eq!(auth.tee, "sample");

    let as_json = serde_json::to_value(&auth).expect("serialize auth request");
    assert!(as_json.get("extra-params").is_some(), "extra-params field must be present");
}

#[test]
fn kbs_attest_request_places_cmw_as_primary_evidence() {
    let component = b"\0asmcomponent".to_vec();
    let evidence = b"sample evidence".to_vec();

    let input = BuildInput::builder(evidence)
        .component(component.clone())
        .build()
        .expect("construct BuildInput");

    let attest = build_kbs_attest_request(
        &input,
        &KbsRequestOptions::builder("test-nonce-abc", sample_tee_pubkey()).build(),
    )
    .expect("build kbs attest request");

    let as_json = serde_json::to_value(&attest).expect("serialize attest request");

    // Top-level fields use kebab-case
    assert!(as_json.get("runtime-data").is_some());
    assert!(as_json.get("tee-evidence").is_some());
    assert!(as_json.get("init-data").is_none(), "init-data must be absent when not set");

    // runtime-data
    assert_eq!(as_json["runtime-data"]["nonce"], "test-nonce-abc");
    assert_eq!(as_json["runtime-data"]["tee-pubkey"]["kty"], "EC");

    // primary_evidence is the raw CMW JSON value (not base64)
    let primary = &as_json["tee-evidence"]["primary_evidence"];
    assert_eq!(primary["__cmwc_t"], TRUSTMEE_COLLECTION_TYPE);
    assert!(primary.get("verifier").is_some(), "CMW should be stapled in primary_evidence");

    // additional_evidence is an empty string for simple guests
    assert_eq!(as_json["tee-evidence"]["additional_evidence"], "");
}

#[test]
fn kbs_attest_request_rejects_empty_nonce() {
    let input = BuildInput::builder(b"ev")
        .component(b"\0asmcomponent")
        .build()
        .expect("construct BuildInput");

    let err = build_kbs_attest_request(
        &input,
        &KbsRequestOptions::builder("  ", sample_tee_pubkey()).build(),
    )
    .expect_err("empty nonce should fail");

    assert!(matches!(err, Error::EmptyNonce));
}

#[test]
fn kbs_attest_request_includes_init_data_when_set() {
    let input = BuildInput::builder(b"ev")
        .component(b"\0asmcomponent")
        .build()
        .expect("construct BuildInput");

    let attest = build_kbs_attest_request(
        &input,
        &KbsRequestOptions::builder("nonce", sample_tee_pubkey())
            .init_data(KbsInitData {
                format: "toml".to_string(),
                body: "algorithm = \"sha256\"".to_string(),
            })
            .build(),
    )
    .expect("build kbs attest request with init data");

    let as_json = serde_json::to_value(&attest).expect("serialize");
    assert_eq!(as_json["init-data"]["format"], "toml");
    assert_eq!(as_json["init-data"]["body"], "algorithm = \"sha256\"");
}

#[test]
fn cli_kbs_auth_produces_correct_output() {
    let root = crate_root();
    let output = Command::new(env!("CARGO_BIN_EXE_trustmee-attester"))
        .current_dir(&root)
        .args(["--mode", "kbs-auth", "--compact"])
        .output()
        .expect("run trustmee-attester binary");

    assert!(
        output.status.success(),
        "binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout: Value = serde_json::from_slice(&output.stdout).expect("parse CLI JSON output");
    assert_eq!(stdout["version"], "0.1.1");
    assert_eq!(stdout["tee"], "sample");
    assert!(stdout.get("extra-params").is_some());
}

#[test]
fn cli_kbs_attest_produces_correct_output() {
    let root = crate_root();
    let output = Command::new(env!("CARGO_BIN_EXE_trustmee-attester"))
        .current_dir(&root)
        .args([
            "--mode",
            "kbs-attest",
            "--evidence",
            "test_data/snp_evidence.json",
            "--component",
            "test_data/snp_verifier_component.wasm",
            "--nonce",
            "test-cli-nonce",
            "--tee-pubkey-json",
            "test_data/sample_tee_pubkey.json",
            "--compact",
        ])
        .output()
        .expect("run trustmee-attester binary");

    assert!(
        output.status.success(),
        "binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout: Value = serde_json::from_slice(&output.stdout).expect("parse CLI JSON output");
    assert_eq!(stdout["runtime-data"]["nonce"], "test-cli-nonce");
    assert_eq!(stdout["tee-evidence"]["primary_evidence"]["__cmwc_t"], TRUSTMEE_COLLECTION_TYPE);
}
