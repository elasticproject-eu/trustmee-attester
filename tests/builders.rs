use attestation_input_format::{
    build_rest_attestation_body, build_trustmee_json_cmw, component_id_from_bytes, BuildInput,
    Endorsement, InitDataInput, RestRequestOptions, RuntimeData, CMW_INDICATOR_ENDORSEMENT,
    CMW_INDICATOR_EVIDENCE, TRUSTMEE_COLLECTION_TYPE, TRUSTMEE_EAT_PROFILE, WASM_MEDIA_TYPE,
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

    let built = build_trustmee_json_cmw(&BuildInput {
        evidence: evidence.clone(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(component.clone()),
        component_id: None,
        endorsements: vec![Endorsement {
            label: "snp-collateral".to_string(),
            media_type: "application/vnd.example.collateral".to_string(),
            payload: endorsement_payload.clone(),
        }],
    })
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
    let built = build_trustmee_json_cmw(&BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: None,
        component_id: Some(component_id.clone()),
        endorsements: vec![],
    })
    .expect("build component id only cmw");

    let cmw = built.cmw_json_value.as_object().expect("cmw object");
    assert!(
        cmw.get("verifier").is_none(),
        "component should not be stapled"
    );
    assert_eq!(built.component_id, component_id);
}

#[test]
fn missing_component_and_component_id_is_rejected() {
    let error = build_trustmee_json_cmw(&BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: None,
        component_id: None,
        endorsements: vec![],
    })
    .expect_err("missing component info should fail");

    assert!(error
        .to_string()
        .contains("either component or component_id"));
}

#[test]
fn mismatched_component_and_component_id_is_rejected() {
    let error = build_trustmee_json_cmw(&BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(b"\0asmcomponent-a".to_vec()),
        component_id: Some(component_id_from_bytes(b"\0asmcomponent-b")),
        endorsements: vec![],
    })
    .expect_err("mismatch should fail");

    assert!(error.to_string().contains("does not match"));
}

#[test]
fn duplicate_endorsement_labels_are_rejected() {
    let error = build_trustmee_json_cmw(&BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(b"\0asmcomponent".to_vec()),
        component_id: None,
        endorsements: vec![
            Endorsement {
                label: "dup".to_string(),
                media_type: "application/test".to_string(),
                payload: vec![1],
            },
            Endorsement {
                label: "dup".to_string(),
                media_type: "application/test".to_string(),
                payload: vec![2],
            },
        ],
    })
    .expect_err("duplicate labels should fail");

    assert!(error.to_string().contains("duplicate or reserved"));
}

#[test]
fn reserved_labels_are_rejected() {
    let error = build_trustmee_json_cmw(&BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(b"\0asmcomponent".to_vec()),
        component_id: None,
        endorsements: vec![Endorsement {
            label: "evidence".to_string(),
            media_type: "application/test".to_string(),
            payload: vec![1],
        }],
    })
    .expect_err("reserved label should fail");

    assert!(error.to_string().contains("duplicate or reserved"));
}

#[test]
fn malformed_component_id_is_rejected() {
    let error = build_trustmee_json_cmw(&BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: None,
        component_id: Some("component-not-lowercase-hex".to_string()),
        endorsements: vec![],
    })
    .expect_err("malformed component id should fail");

    assert!(error.to_string().contains("64 lowercase hex"));
}

#[test]
fn rest_body_wraps_cmw_and_defaults_policy_ids() {
    let input = BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(b"\0asmcomponent".to_vec()),
        component_id: None,
        endorsements: vec![Endorsement {
            label: "collateral".to_string(),
            media_type: "application/test".to_string(),
            payload: vec![1, 2, 3],
        }],
    };

    let trustmee = build_trustmee_json_cmw(&input).expect("build cmw");
    let rest = build_rest_attestation_body(
        &input,
        &RestRequestOptions {
            tee: "snp".to_string(),
            policy_ids: vec![],
            runtime_data: None,
            init_data: None,
            runtime_data_hash_algorithm: None,
        },
    )
    .expect("build rest body");

    assert_eq!(rest.policy_ids, vec!["default"]);
    assert_eq!(rest.verification_requests.len(), 1);

    let request = &rest.verification_requests[0];
    assert_eq!(request.tee, "snp");
    assert_eq!(request.verifier, "wasm-verification-component");
    assert_eq!(
        request.evidence,
        URL_SAFE_NO_PAD.encode(&trustmee.cmw_json_bytes)
    );
}

#[test]
fn runtime_data_and_init_data_serialize_in_rest_shape() {
    let input = BuildInput {
        evidence: b"evidence".to_vec(),
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(b"\0asmcomponent".to_vec()),
        component_id: None,
        endorsements: vec![],
    };

    let rest = build_rest_attestation_body(
        &input,
        &RestRequestOptions {
            tee: "tdx".to_string(),
            policy_ids: vec!["custom".to_string()],
            runtime_data: Some(RuntimeData::Raw(b"runtime-data".to_vec())),
            init_data: Some(InitDataInput::InitDataToml(
                "algorithm = \"sha384\"".to_string(),
            )),
            runtime_data_hash_algorithm: Some("sha384".to_string()),
        },
    )
    .expect("build rest body with optional fields");

    let as_json = serde_json::to_value(&rest).expect("serialize rest body");
    assert_eq!(as_json["policy_ids"], json!(["custom"]));
    assert_eq!(
        as_json["verification_requests"][0]["runtime_data"]["raw"],
        Value::String(URL_SAFE_NO_PAD.encode(b"runtime-data"))
    );
    assert_eq!(
        as_json["verification_requests"][0]["init_data"]["init_data_toml"],
        Value::String("algorithm = \"sha384\"".to_string())
    );
    assert_eq!(
        as_json["verification_requests"][0]["runtime_data_hash_algorithm"],
        Value::String("sha384".to_string())
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

    let built = build_trustmee_json_cmw(&BuildInput {
        evidence,
        evidence_media_type: "application/octet-stream".to_string(),
        component: Some(component.clone()),
        component_id: None,
        endorsements: vec![],
    })
    .expect("build trustmee cmw from vendored sample files");

    assert_eq!(built.component_id, component_id_from_bytes(&component));
    assert_eq!(built.cmw_json_value["__cmwc_t"], TRUSTMEE_COLLECTION_TYPE);
}

#[test]
fn cli_can_generate_trustmee_output_from_vendored_sample_files() {
    let root = crate_root();
    let output = Command::new(env!("CARGO_BIN_EXE_attestation-input-format"))
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
        .expect("run attestation-input-format binary");

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
