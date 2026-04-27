use anyhow::{bail, Context, Result};
use trustmee_attester::{
    build_rest_attestation_body, build_trustmee_json_cmw, BuildInput, Endorsement, InitDataInput,
    RestRequestOptions, RuntimeData,
};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputMode {
    Trustmee,
    Rest,
}

#[derive(Debug, Parser)]
#[command(name = "trustmee-attester")]
#[command(about = "Build TrustMee CMW or attestation-service REST payloads from raw evidence")]
struct Args {
    #[arg(long, value_enum)]
    mode: OutputMode,

    #[arg(long)]
    evidence: PathBuf,

    #[arg(long, default_value = "application/octet-stream")]
    evidence_media_type: String,

    #[arg(long)]
    component: Option<PathBuf>,

    #[arg(long)]
    component_id: Option<String>,

    #[arg(long, value_name = "LABEL:MEDIA_TYPE:PATH")]
    endorsement: Vec<String>,

    #[arg(long)]
    compact: bool,

    #[arg(long)]
    output_file: Option<PathBuf>,

    #[arg(long)]
    tee: Option<String>,

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

    #[arg(long, value_parser = ["sha256", "sha384", "sha512"])]
    runtime_data_hash_algorithm: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let input = build_input(&args)?;

    match args.mode {
        OutputMode::Trustmee => {
            let built = build_trustmee_json_cmw(&input)?;
            write_json_output(
                &built.cmw_json_value,
                args.compact,
                args.output_file.as_deref(),
            )?;
        }
        OutputMode::Rest => {
            let options = build_rest_options(&args)?;
            let body = build_rest_attestation_body(&input, &options)?;
            write_json_output(&body, args.compact, args.output_file.as_deref())?;
        }
    }

    Ok(())
}

fn build_input(args: &Args) -> Result<BuildInput> {
    let evidence = read_bytes(&args.evidence, "evidence")?;

    let component = args
        .component
        .as_deref()
        .map(|path| read_bytes(path, "component"))
        .transpose()?;

    let endorsements = args
        .endorsement
        .iter()
        .map(|value| parse_endorsement_arg(value))
        .collect::<Result<Vec<_>>>()?;

    Ok(BuildInput {
        evidence,
        evidence_media_type: args.evidence_media_type.clone(),
        component,
        component_id: args.component_id.clone(),
        endorsements,
    })
}

fn build_rest_options(args: &Args) -> Result<RestRequestOptions> {
    let tee = args
        .tee
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--tee is required when --mode rest is used"))?;

    let runtime_data = match (&args.runtime_data_raw, &args.runtime_data_json) {
        (Some(path), None) => Some(RuntimeData::Raw(read_bytes(path, "runtime data raw")?)),
        (None, Some(path)) => Some(RuntimeData::Structured(read_json(path)?)),
        (None, None) => None,
        (Some(_), Some(_)) => bail!("runtime data flags are mutually exclusive"),
    };

    let init_data = match (&args.init_data_digest, &args.init_data_toml) {
        (Some(path), None) => Some(InitDataInput::InitDataDigest(read_bytes(
            path,
            "init data digest",
        )?)),
        (None, Some(path)) => Some(InitDataInput::InitDataToml(read_string(
            path,
            "init data toml",
        )?)),
        (None, None) => None,
        (Some(_), Some(_)) => bail!("init data flags are mutually exclusive"),
    };

    Ok(RestRequestOptions {
        tee,
        policy_ids: args.policy_ids.clone(),
        runtime_data,
        init_data,
        runtime_data_hash_algorithm: args.runtime_data_hash_algorithm.clone(),
    })
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
    let bytes = read_bytes(path, "runtime data json")?;
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
