# trustmee-attester

Standalone Rust crate and CLI for turning raw attestation evidence into:

- TrustMee JSON CMW for `trustmee-verification-library`
- a request body for TrustMee's `/attestation` API for wasm-backed verifier flow


## Library

```rust
use trustmee_attester::{
    build_trustmee_json_cmw, BuildInput, Endorsement,
};

let input = BuildInput {
    evidence: std::fs::read("test_data/snp_evidence.json")?,
    evidence_media_type: "application/octet-stream".to_string(),
    component: Some(std::fs::read("test_data/snp_verifier_component.wasm")?),
    component_id: None,
    endorsements: vec![],
};

let built = build_trustmee_json_cmw(&input)?;
std::fs::write("input.cmw.json", built.cmw_json_bytes)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Obtaining attestation evidence in Confidential Containers

In your main project's `Cargo.toml` set `attestation-input-format = { ... features = ["confidential-containers"] }` under `[dependencies]`

Call the function with

```rust
let trustmee_builder_client = trustmee_coco_client::CocoClient::builder().build()?; // can .url() and .timeout() options can be specified if not using default

let trustmee_evidence = trustmee_builder_client.build_trustmee_json_cmw_coco(Some(runtime_data.as_bytes()), verifier_component_id, verifier_component, evidence_media_type, edorsements).await?;?; //all parameters are optional
```



## CLI

Build TrustMee JSON CMW (trustmee-lib expected input):

```bash
cd trustmee-attester
cargo run -- \
  --mode trustmee \
  --evidence ./test_data/snp_evidence.json \
  --component ./test_data/snp_verifier_component.wasm
```

Build a REST `/attestation` body for the Wasm-backed verifier flow (TrustMee expected input):

```bash
cd trustmee-attester
cargo run -- \
  --mode rest \
  --tee snp \
  --evidence ./test_data/snp_evidence.json \
  --component ./test_data/snp_verifier_component.wasm \
  --policy-id default
```

The generated REST request uses `tee: "sample"` to select Wasm verification;
the verifier component reports the real TEE type in its output claims.

Use `--output-file` to write the generated JSON to disk and `--compact` for one-line JSON.
