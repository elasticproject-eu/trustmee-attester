use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "confidential-containers")]
use trustmee_attester::trustmee_coco_client::fetch_evidence_from_aa;
use trustmee_attester::{
    build_kbs_attest_request, build_kbs_auth_request, build_rest_attestation_body,
    build_trustmee_json_cmw,
    collateral::{
        CollateralSource, SgxCollateralOptions, SnpCollateralOptions, TdxCollateralOptions,
    },
    fetch_collateral, BuildInput, Endorsement, InitDataInput, KbsInitData, KbsRequestOptions,
    RestRequestOptions, RuntimeData,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputMode {
    Trustmee,
    Rest,
    KbsAuth,
    KbsAttest,
}

/// TEE type for `--fetch-collateral`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum TeeKind {
    Snp,
    Tdx,
    Sgx,
}

#[derive(Debug, Parser)]
#[command(name = "trustmee_attester")]
#[command(about = "Build TrustMee CMW or attestation-service REST payloads from raw evidence")]
struct Args {
    #[arg(long, value_enum)]
    mode: OutputMode,

    /// Evidence file (required for trustmee, rest, kbs-attest).
    #[arg(long)]
    evidence: Option<PathBuf>,

    #[arg(long, default_value = "application/octet-stream")]
    evidence_media_type: String,

    /// Staple the component bytes in the output; component ID is derived via SHA-256.
    #[arg(long, conflicts_with_all = ["component_id", "component_id_from"])]
    component: Option<PathBuf>,

    /// Pre-computed component ID (no bytes stapled in output).
    #[arg(long, conflicts_with_all = ["component", "component_id_from"])]
    component_id: Option<String>,

    /// Derive the component ID from the file's SHA-256 hash without stapling the bytes.
    #[arg(long, conflicts_with_all = ["component", "component_id"])]
    component_id_from: Option<PathBuf>,

    #[arg(long, value_name = "LABEL:MEDIA_TYPE:PATH")]
    endorsement: Vec<String>,

    /// Fetch collateral (certificates + TCB metadata) for the given TEE type
    /// and attach it as endorsements inside the CMW.  Requires network access
    /// to AMD KDS (SNP) or Intel PCS (TDX/SGX).
    #[arg(long, value_enum)]
    fetch_collateral: Option<TeeKind>,

    /// Override the AMD KDS base URL used when --fetch-collateral snp is set.
    #[arg(long, default_value = trustmee_attester::collateral::AMD_KDS_BASE_URL)]
    kds_url: String,

    /// Override the SNP product name sent to AMD KDS (e.g. "Milan", "Genoa").
    /// Auto-detected from the evidence CPUID fields when not specified.
    #[arg(long)]
    snp_product: Option<String>,

    /// PCS/PCCS base URL used when --fetch-collateral tdx is set.
    /// Defaults to Intel PCS.
    #[arg(long, default_value = trustmee_attester::collateral::INTEL_PCS_TDX_BASE_URL)]
    tdx_pccs_url: String,

    /// PCS/PCCS base URL used when --fetch-collateral sgx is set.
    /// Defaults to Phala PCCS, which serves the `pckcert` endpoint without an
    /// Intel subscription key (required for quotes whose certification data
    /// holds an encrypted PPID instead of an inline PCK chain).
    #[arg(long, default_value = trustmee_attester::collateral::PHALA_PCCS_BASE_URL)]
    sgx_pccs_url: String,

    #[arg(long)]
    compact: bool,

    #[arg(long)]
    output_file: Option<PathBuf>,

    // ── attestation-service REST options ──────────────────────────────────────
    #[arg(long = "policy-id")]
    policy_ids: Vec<String>,

    #[arg(long, conflicts_with = "runtime_data_json")]
    runtime_data_raw: Option<PathBuf>,

    #[arg(long, conflicts_with = "runtime_data_raw")]
    runtime_data_json: Option<PathBuf>,

    #[arg(long, conflicts_with = "init_data_toml")]
    init_data_digest: Option<PathBuf>,

    #[arg(long, conflicts_with = "init_data_digest")]
    init_data_toml: Option<PathBuf>,

    #[arg(long, value_parser = ["sha256"])]
    runtime_data_hash_algorithm: Option<String>,

    // ── KBS-specific options ──────────────────────────────────────────────────
    /// Nonce from the KBS challenge response (required for kbs-attest).
    #[arg(long)]
    nonce: Option<String>,

    /// Path to a JSON file containing the JWK-formatted TEE public key (required for kbs-attest).
    #[arg(long)]
    tee_pubkey_json: Option<PathBuf>,

    /// KBS init-data: a JSON file whose contents become the `body` (format = json).
    #[arg(long, conflicts_with = "kbs_init_data_toml")]
    kbs_init_data_json: Option<PathBuf>,

    /// KBS init-data: a TOML file whose contents become the `body` (format = toml).
    #[arg(long, conflicts_with = "kbs_init_data_json")]
    kbs_init_data_toml: Option<PathBuf>,

    // ── Confidential Containers Attestation Agent ─────────────────────────────
    /// Fetch evidence from the Confidential Containers Attestation Agent
    /// instead of reading it from --evidence.
    #[cfg(feature = "confidential-containers")]
    #[arg(long, conflicts_with = "evidence")]
    fetch_from_aa: bool,

    /// Attestation Agent endpoint URL.
    #[cfg(feature = "confidential-containers")]
    #[arg(
        long,
        default_value = trustmee_attester::trustmee_coco_client::DEFAULT_COCO_EVIDENCE_URL,
        requires = "fetch_from_aa"
    )]
    aa_url: String,

    /// Write the raw evidence bytes fetched from the AA to this file.
    /// Useful for debugging or caching evidence for later use with --evidence.
    #[cfg(feature = "confidential-containers")]
    #[arg(long, requires = "fetch_from_aa")]
    save_evidence: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.mode {
        OutputMode::Trustmee => {
            let input = build_input(&args)?;
            let built = build_trustmee_json_cmw(&input)?;
            write_json_output(
                &built.cmw_json_value,
                args.compact,
                args.output_file.as_deref(),
            )?;
        }
        OutputMode::Rest => {
            let input = build_input(&args)?;
            let options = build_rest_options(&args);
            let body = build_rest_attestation_body(&input, &options)?;
            write_json_output(&body, args.compact, args.output_file.as_deref())?;
        }
        OutputMode::KbsAuth => {
            let auth = build_kbs_auth_request();
            write_json_output(&auth, args.compact, args.output_file.as_deref())?;
        }
        OutputMode::KbsAttest => {
            let input = build_input(&args)?;
            let options = build_kbs_options(&args)?;
            let attest = build_kbs_attest_request(&input, &options)?;
            write_json_output(&attest, args.compact, args.output_file.as_deref())?;
        }
    }

    Ok(())
}

fn get_evidence(args: &Args) -> Result<Vec<u8>> {
    #[cfg(feature = "confidential-containers")]
    if args.fetch_from_aa {
        // runtime_data_raw is reused as the nonce/runtime-data sent to the AA.
        let runtime_data = args
            .runtime_data_raw
            .as_ref()
            .map(|p| read_bytes(p, "runtime data for AA"))
            .transpose()?;
        let evidence = fetch_evidence_from_aa(&args.aa_url, runtime_data.as_deref())
            .context("fetch evidence from Attestation Agent")?;
        if let Some(path) = &args.save_evidence {
            fs::write(path, &evidence)
                .with_context(|| format!("save evidence to {}", path.display()))?;
        }
        return Ok(evidence);
    }

    let evidence_path = args
        .evidence
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--evidence is required for this mode"))?;
    read_bytes(evidence_path, "evidence")
}

fn build_input(args: &Args) -> Result<BuildInput> {
    let evidence = get_evidence(args)?;

    let mut endorsements = args
        .endorsement
        .iter()
        .map(|value| parse_endorsement_arg(value))
        .collect::<Result<Vec<_>>>()?;

    if let Some(tee) = args.fetch_collateral {
        let source = collateral_source(tee, args);
        let fetched = fetch_collateral(&evidence, &source).context("fetch collateral")?;
        endorsements.extend(fetched);
    }

    let mut builder =
        BuildInput::builder(evidence).evidence_media_type(args.evidence_media_type.clone());
    builder = match (&args.component, &args.component_id, &args.component_id_from) {
        (Some(path), None, None) => builder.component(read_bytes(path, "component")?),
        (None, Some(id), None) => builder.component_id(id.clone()),
        (None, None, Some(path)) => {
            builder.component_id_from_bytes(read_bytes(path, "component-id-from")?)
        }
        (None, None, None) => {
            bail!("one of --component, --component-id, or --component-id-from must be provided")
        }
        _ => bail!("--component, --component-id, and --component-id-from are mutually exclusive"),
    };

    for endorsement in endorsements {
        builder = builder.endorsement(endorsement);
    }

    Ok(builder.build()?)
}

fn collateral_source(tee: TeeKind, args: &Args) -> CollateralSource {
    match tee {
        TeeKind::Snp => CollateralSource::Snp(SnpCollateralOptions {
            kds_base_url: args.kds_url.clone(),
            product_name: args.snp_product.clone(),
        }),
        TeeKind::Tdx => CollateralSource::Tdx(TdxCollateralOptions {
            pccs_base_url: args.tdx_pccs_url.clone(),
        }),
        TeeKind::Sgx => CollateralSource::Sgx(SgxCollateralOptions {
            pccs_base_url: args.sgx_pccs_url.clone(),
        }),
    }
}

fn build_rest_options(args: &Args) -> RestRequestOptions {
    let runtime_data = match (&args.runtime_data_raw, &args.runtime_data_json) {
        (Some(path), None) => read_bytes(path, "runtime data raw")
            .ok()
            .map(RuntimeData::Raw),
        (None, Some(path)) => read_json(path).ok().map(RuntimeData::Structured),
        _ => None,
    };

    let init_data = match (&args.init_data_digest, &args.init_data_toml) {
        (Some(path), None) => read_bytes(path, "init data digest")
            .ok()
            .map(InitDataInput::InitDataDigest),
        (None, Some(path)) => read_string(path, "init data toml")
            .ok()
            .map(InitDataInput::InitDataToml),
        _ => None,
    };

    let mut builder = RestRequestOptions::builder();
    for id in &args.policy_ids {
        builder = builder.policy_id(id.clone());
    }
    if let Some(data) = runtime_data {
        builder = builder.runtime_data(data);
    }
    if let Some(data) = init_data {
        builder = builder.init_data(data);
    }
    if let Some(algo) = &args.runtime_data_hash_algorithm {
        builder = builder.runtime_data_hash_algorithm(algo.clone());
    }
    builder.build()
}

fn build_kbs_options(args: &Args) -> Result<KbsRequestOptions> {
    let nonce = args
        .nonce
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--nonce is required for --mode kbs-attest"))?;
    let tee_pubkey = match &args.tee_pubkey_json {
        Some(path) => read_json(path)?,
        None => bail!("--tee-pubkey-json is required for --mode kbs-attest"),
    };

    let init_data = match (&args.kbs_init_data_json, &args.kbs_init_data_toml) {
        (Some(path), None) => Some(KbsInitData {
            format: "json".to_string(),
            body: read_string(path, "KBS init data JSON")?,
        }),
        (None, Some(path)) => Some(KbsInitData {
            format: "toml".to_string(),
            body: read_string(path, "KBS init data TOML")?,
        }),
        (None, None) => None,
        (Some(_), Some(_)) => bail!("KBS init data flags are mutually exclusive"),
    };

    let mut builder = KbsRequestOptions::builder(nonce, tee_pubkey);
    if let Some(data) = init_data {
        builder = builder.init_data(data);
    }
    Ok(builder.build())
}

fn parse_endorsement_arg(value: &str) -> Result<Endorsement> {
    let mut parts = value.splitn(3, ':');
    let label = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("endorsement must have label"))?;
    let media_type = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("endorsement must have media type"))?;
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("endorsement must have path"))?;

    if label.is_empty() || media_type.is_empty() || path.is_empty() {
        bail!("endorsement must be in LABEL:MEDIA_TYPE:PATH format");
    }

    Ok(Endorsement {
        label: label.to_string(),
        media_type: media_type.to_string(),
        payload: read_bytes(Path::new(path), &format!("endorsement `{label}`"))?,
    })
}

fn read_bytes(path: &Path, purpose: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read {purpose} from {}", path.display()))
}

fn read_string(path: &Path, purpose: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {purpose} from {}", path.display()))
}

fn read_json(path: &Path) -> Result<Value> {
    let bytes = read_bytes(path, "JSON file")?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON from {}", path.display()))
}

fn write_json_output(
    value: &impl Serialize,
    compact: bool,
    output_file: Option<&Path>,
) -> Result<()> {
    let bytes = if compact {
        serde_json::to_vec(value).context("serialize compact JSON output")?
    } else {
        serde_json::to_vec_pretty(value).context("serialize pretty JSON output")?
    };

    if let Some(path) = output_file {
        fs::write(path, bytes).with_context(|| format!("write output to {}", path.display()))?;
    } else {
        println!(
            "{}",
            String::from_utf8(bytes).context("convert JSON output to UTF-8")?
        );
    }

    Ok(())
}
