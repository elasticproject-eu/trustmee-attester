# attestation-input-format

Standalone Rust crate and CLI for turning raw attestation evidence into:

- TrustMee JSON CMW for `trustmee-verification-library`
- a request body for TrustMee's `/attestation` API for wasm-backed verifier flow


## Library

```rust
use attestation_input_format::{
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

## CLI

Build TrustMee JSON CMW (trustmee-lib expected input):

```bash
cd attestation-input-for-trustmee
cargo run -- \
  --mode trustmee \
  --evidence ./test_data/snp_evidence.json \
  --component ./test_data/snp_verifier_component.wasm
```

Build a REST `/attestation` body for the Wasm-backed verifier flow (TrustMee expected input):

```bash
cd attestation-input-for-trustmee
cargo run -- \
  --mode rest \
  --tee snp \
  --evidence ./test_data/snp_evidence.json \
  --component ./test_data/snp_verifier_component.wasm \
  --policy-id default
```

Use `--output-file` to write the generated JSON to disk and `--compact` for one-line JSON.

