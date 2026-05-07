# trustmee-attester

Standalone Rust crate and CLI for turning raw attestation evidence into:

- TrustMee JSON CMW for `trustmee-verification-library`
- a request body for TrustMee's `/attestation` API for wasm-backed verifier flow


## Library

```rust
use trustmee_attester::{
    build_trustmee_json_cmw, BuildInput, Endorsement,
};

let input = BuildInput::builder(std::fs::read("test_data/snp_evidence.json")?)
    .component(std::fs::read("test_data/snp_verifier_component.wasm")?)
    .endorsement(Endorsement::new(
        "example-collateral",
        "application/octet-stream",
        b"optional collateral".to_vec(),
    ))
    .build()?;

let built = build_trustmee_json_cmw(&input)?;
std::fs::write("input.cmw.json", built.cmw_json_bytes)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Obtaining attestation evidence in Confidential Containers

In your main project's `Cargo.toml` enable the `confidential-containers` feature for this crate under `[dependencies]`.

The CoCo client has defaults for the local Attestation Agent URL and timeout:

```rust
use trustmee_attester::trustmee_coco_client::{CocoBuildOptions, CocoClient};

let client = CocoClient::builder()
    // Optional; defaults to http://127.0.0.1:8006/aa/evidence
    // .url("http://127.0.0.1:8006/aa/evidence")
    // Optional; defaults to 30 seconds
    // .timeout(std::time::Duration::from_secs(30))
    .build()?;

let trustmee_evidence = client
    .build_trustmee_json_cmw_coco(
        CocoBuildOptions::new()
            // Optional; omitted by default.
            .runtime_data(runtime_data.as_bytes())
            // Required: component bytes are stapled and the component ID is
            // derived automatically from these bytes.
            .component(verifier_component_bytes),
    )
    .await?;
```

`CocoBuildOptions` defaults to no runtime data, `application/octet-stream` evidence media type, and no additional endorsements. The component source is required because it identifies the verifier component. Use `.component(bytes)` when you have the component bytes; the component ID/hash is then calculated automatically. Use `.component_id(id_or_url)`, `.component_oci_url(url)`, or `.component_id_from_bytes(bytes)` only for unstapled/out-of-band component resolution.

When both `confidential-containers` and `fetch-collateral` are enabled, use the collateral builder:

```rust
use trustmee_attester::trustmee_coco_client::{
    CocoBuildWithCollateralOptions, CocoClient,
};

let client = CocoClient::builder().build()?;

let trustmee_evidence = client
    .build_trustmee_json_cmw_coco_with_collateral(
        CocoBuildWithCollateralOptions::new()
            .runtime_data(runtime_data.as_bytes())
            .component(verifier_component_bytes)
            // Pick the TEE collateral source. Defaults for each source use the
            // crate's built-in vendor service URLs.
            .snp_collateral(),
    )
    .await?;
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
