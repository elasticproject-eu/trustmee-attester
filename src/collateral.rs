//! Collateral fetching for TDX, SNP, and SGX attestation evidence.
//!
//! Call [`fetch_collateral`] to retrieve the relevant certificates and TCB
//! metadata for a piece of evidence, returned as [`Endorsement`]s ready to
//! attach to a [`BuildInput`](crate::BuildInput).
//!
//! Requires the `fetch-collateral` Cargo feature (enabled by default).

use crate::Endorsement;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::Value;

// ── Media types ───────────────────────────────────────────────────────────────

pub const MEDIA_PKIX_CERT: &str = "application/pkix-cert";
pub const MEDIA_PEM_CHAIN: &str = "application/pem-certificate-chain";
pub const MEDIA_JSON: &str = "application/json";

// ── Endorsement labels ────────────────────────────────────────────────────────

pub const SNP_VCEK_LABEL: &str = "snp-vcek";
pub const SNP_CERT_CHAIN_LABEL: &str = "snp-cert-chain";
pub const TDX_PCK_CHAIN_LABEL: &str = "tdx-pck-chain";
pub const TDX_TCB_INFO_LABEL: &str = "tdx-tcb-info";
pub const TDX_QE_IDENTITY_LABEL: &str = "tdx-qe-identity";
pub const SGX_PCK_CHAIN_LABEL: &str = "sgx-pck-chain";
pub const SGX_TCB_INFO_LABEL: &str = "sgx-tcb-info";
pub const SGX_QE_IDENTITY_LABEL: &str = "sgx-qe-identity";

// ── Default service URLs ──────────────────────────────────────────────────────

pub const AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com";
pub const INTEL_PCS_TDX_BASE_URL: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4";
pub const INTEL_PCS_SGX_BASE_URL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4";

// ── Options ───────────────────────────────────────────────────────────────────

/// Options for fetching AMD SEV-SNP collateral from the AMD Key Distribution
/// Service (KDS).
#[derive(Clone, Debug)]
pub struct SnpCollateralOptions {
    /// AMD KDS base URL. Defaults to [`AMD_KDS_BASE_URL`].
    pub kds_base_url: String,
    /// Product name (e.g. `"Milan"`, `"Genoa"`). Auto-detected from the
    /// evidence CPUID fields when `None`.
    pub product_name: Option<String>,
}

impl Default for SnpCollateralOptions {
    fn default() -> Self {
        Self {
            kds_base_url: AMD_KDS_BASE_URL.to_string(),
            product_name: None,
        }
    }
}

/// Options for fetching Intel TDX collateral from the Intel Provisioning
/// Certification Service (PCS).
#[derive(Clone, Debug, Default)]
pub struct TdxCollateralOptions;

/// Options for fetching Intel SGX collateral from the Intel PCS.
#[derive(Clone, Debug, Default)]
pub struct SgxCollateralOptions;

/// Specifies the TEE type and service options for collateral fetching.
#[derive(Clone, Debug)]
pub enum CollateralSource {
    /// AMD SEV-SNP. Evidence must be the JSON attestation report format.
    Snp(SnpCollateralOptions),
    /// Intel TDX. Evidence must be a binary DCAP quote (version 4).
    Tdx(TdxCollateralOptions),
    /// Intel SGX. Evidence must be a binary DCAP quote (version 3).
    Sgx(SgxCollateralOptions),
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Fetch collateral for `evidence` and return it as [`Endorsement`]s.
///
/// The returned endorsements can be added to a
/// [`BuildInput`](crate::BuildInput) so that the collateral is embedded inside
/// the CMW alongside the evidence.
///
/// Requires the `fetch-collateral` Cargo feature (enabled by default).
pub fn fetch_collateral(
    evidence: &[u8],
    source: &CollateralSource,
) -> Result<Vec<Endorsement>> {
    match source {
        CollateralSource::Snp(opts) => fetch_snp(evidence, opts),
        CollateralSource::Tdx(opts) => fetch_tdx(evidence, opts),
        CollateralSource::Sgx(opts) => fetch_sgx(evidence, opts),
    }
}

// ── SNP ───────────────────────────────────────────────────────────────────────

struct SnpFields {
    chip_id_hex: String,
    bl_svn: u8,
    tee_svn: u8,
    snp_svn: u8,
    ucode_svn: u8,
    product_name: String,
}

fn parse_snp_evidence(evidence: &[u8]) -> Result<SnpFields> {
    let json: Value =
        serde_json::from_slice(evidence).context("SNP evidence is not valid JSON")?;

    let report = json
        .get("attestation_report")
        .context("missing 'attestation_report' in SNP evidence JSON")?;

    let chip_id_arr = report
        .get("chip_id")
        .and_then(|v| v.as_array())
        .context("missing 'chip_id' array in attestation_report")?;
    let chip_id_bytes: Vec<u8> = chip_id_arr
        .iter()
        .map(|v| v.as_u64().unwrap_or(0) as u8)
        .collect();
    let chip_id_hex = hex::encode(&chip_id_bytes);

    let tcb = report
        .get("reported_tcb")
        .context("missing 'reported_tcb' in attestation_report")?;
    let bl_svn = tcb
        .get("bootloader")
        .and_then(|v| v.as_u64())
        .context("missing 'bootloader' in reported_tcb")? as u8;
    let tee_svn = tcb
        .get("tee")
        .and_then(|v| v.as_u64())
        .context("missing 'tee' in reported_tcb")? as u8;
    let snp_svn = tcb
        .get("snp")
        .and_then(|v| v.as_u64())
        .context("missing 'snp' in reported_tcb")? as u8;
    let ucode_svn = tcb
        .get("microcode")
        .and_then(|v| v.as_u64())
        .context("missing 'microcode' in reported_tcb")? as u8;

    let cpuid_fam = report
        .get("cpuid_fam_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cpuid_mod = report
        .get("cpuid_mod_id")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let product_name = snp_product_name(cpuid_fam, cpuid_mod).to_string();

    Ok(SnpFields {
        chip_id_hex,
        bl_svn,
        tee_svn,
        snp_svn,
        ucode_svn,
        product_name,
    })
}

fn snp_product_name(cpuid_fam: u64, cpuid_mod: u64) -> &'static str {
    match (cpuid_fam, cpuid_mod) {
        (25, 0..=15) => "Milan",
        (25, 160..=175) => "Genoa",
        (25, 176..=191) => "Bergamo",
        _ => "Milan",
    }
}

#[cfg(feature = "fetch-collateral")]
fn fetch_snp(evidence: &[u8], opts: &SnpCollateralOptions) -> Result<Vec<Endorsement>> {
    let fields = parse_snp_evidence(evidence)?;
    let product = opts.product_name.as_deref().unwrap_or(&fields.product_name);
    let kds = &opts.kds_base_url;

    let client = reqwest::blocking::Client::new();

    let vcek_url = format!(
        "{kds}/vcek/v1/{product}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        fields.chip_id_hex, fields.bl_svn, fields.tee_svn, fields.snp_svn, fields.ucode_svn,
    );
    let vcek_bytes = client
        .get(&vcek_url)
        .send()
        .with_context(|| format!("GET {vcek_url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {vcek_url}"))?
        .bytes()
        .context("read VCEK cert body")?
        .to_vec();

    let chain_url = format!("{kds}/vcek/v1/{product}/cert_chain");
    let chain_bytes = client
        .get(&chain_url)
        .send()
        .with_context(|| format!("GET {chain_url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {chain_url}"))?
        .bytes()
        .context("read cert chain body")?
        .to_vec();

    Ok(vec![
        Endorsement::new(SNP_VCEK_LABEL, MEDIA_PKIX_CERT, vcek_bytes),
        Endorsement::new(SNP_CERT_CHAIN_LABEL, MEDIA_PEM_CHAIN, chain_bytes),
    ])
}

#[cfg(not(feature = "fetch-collateral"))]
fn fetch_snp(_evidence: &[u8], _opts: &SnpCollateralOptions) -> Result<Vec<Endorsement>> {
    bail!("collateral fetching requires the `fetch-collateral` Cargo feature")
}

// ── TDX / SGX shared quote parsing ───────────────────────────────────────────

/// Parsed fields extracted from a binary ECDSA DCAP quote (TDX or SGX).
struct QuoteFields {
    /// PEM-encoded PCK cert chain (leaf PCK cert + intermediate + root).
    pck_chain_pem: Vec<u8>,
    /// 6-byte FMSPC extracted from the PCK leaf certificate.
    fmspc_hex: String,
}

fn parse_dcap_quote(evidence: &[u8], report_body_size: usize, tee_type: u32) -> Result<QuoteFields> {
    if evidence.len() < 48 {
        bail!("quote too short for header ({} bytes)", evidence.len());
    }
    let version = u16::from_le_bytes([evidence[0], evidence[1]]);
    let actual_tee =
        u32::from_le_bytes(evidence[4..8].try_into().expect("slice always 4 bytes"));
    if actual_tee != tee_type {
        bail!("expected TEE type 0x{tee_type:08x}, got 0x{actual_tee:08x}");
    }

    let _ = version; // version check left to callers

    let sig_len_offset = 48 + report_body_size;
    if evidence.len() < sig_len_offset + 4 {
        bail!("quote truncated before signature length field");
    }
    let sig_len = u32::from_le_bytes(
        evidence[sig_len_offset..sig_len_offset + 4]
            .try_into()
            .expect("slice always 4 bytes"),
    ) as usize;
    let sig_start = sig_len_offset + 4;
    if evidence.len() < sig_start + sig_len {
        bail!("quote truncated in signature data");
    }
    let sig_data = &evidence[sig_start..sig_start + sig_len];
    extract_pck_chain(sig_data)
}

/// Navigate the ECDSA-256 signature data to locate the PEM PCK cert chain and
/// extract the FMSPC from the leaf certificate.
fn extract_pck_chain(sig_data: &[u8]) -> Result<QuoteFields> {
    // Layout: ECDSA sig (64) + attest pubkey (64) + cert data type (2) +
    //         cert data len (4) + cert data (variable)
    if sig_data.len() < 134 {
        bail!("ECDSA signature data too short ({} bytes)", sig_data.len());
    }

    let cert_type = u16::from_le_bytes([sig_data[128], sig_data[129]]);
    let cert_len =
        u32::from_le_bytes(sig_data[130..134].try_into().expect("slice always 4 bytes")) as usize;
    if sig_data.len() < 134 + cert_len {
        bail!("cert data truncated in signature block");
    }
    let cert_data = &sig_data[134..134 + cert_len];

    let pck_pem = match cert_type {
        // Type 5: PCK cert chain in PEM (leaf + intermediate + root)
        5 => cert_data.to_vec(),
        // Type 6: QE report cert data — PCK chain nested inside as type 5
        6 => extract_pck_chain_from_type6(cert_data)?,
        t => bail!("unsupported ECDSA cert data type {t}; expected 5 or 6"),
    };

    let fmspc_hex = fmspc_from_pck_pem(&pck_pem)?;

    Ok(QuoteFields {
        pck_chain_pem: pck_pem,
        fmspc_hex,
    })
}

/// Extract the nested type-5 PCK chain from type-6 QE Report Certification
/// Data.
///
/// Layout inside type-6 data:
/// - QE Report body (384 bytes)
/// - QE Report signature (64 bytes)
/// - QE auth data: length (2 bytes LE) + data
/// - Inner cert data: type (2 bytes LE) + length (4 bytes LE) + data
fn extract_pck_chain_from_type6(cert_data: &[u8]) -> Result<Vec<u8>> {
    let mut off = 384 + 64; // skip QE report + QE report sig
    if cert_data.len() < off + 2 {
        bail!("type-6 cert data truncated before QE auth length");
    }
    let auth_len = u16::from_le_bytes([cert_data[off], cert_data[off + 1]]) as usize;
    off += 2 + auth_len;

    if cert_data.len() < off + 6 {
        bail!("type-6 cert data truncated before inner cert type/length");
    }
    let inner_type = u16::from_le_bytes([cert_data[off], cert_data[off + 1]]);
    let inner_len = u32::from_le_bytes(
        cert_data[off + 2..off + 6]
            .try_into()
            .expect("slice always 4 bytes"),
    ) as usize;
    off += 6;

    if inner_type != 5 {
        bail!("unexpected inner cert type {inner_type} in type-6 data; expected 5 (PCK chain)");
    }
    if cert_data.len() < off + inner_len {
        bail!("inner PCK cert chain truncated");
    }
    Ok(cert_data[off..off + inner_len].to_vec())
}

/// Extract the FMSPC from the leaf PCK certificate in a PEM cert chain.
///
/// FMSPC lives in the SGX FMSPC extension (OID 1.2.840.113741.1.13.1.4),
/// encoded as a 6-byte OCTET STRING. We locate it with a fast byte-pattern
/// search on the DER-decoded leaf cert.
fn fmspc_from_pck_pem(pem: &[u8]) -> Result<String> {
    let pem_str = std::str::from_utf8(pem).context("PCK chain is not valid UTF-8")?;

    // Extract the first cert block
    let begin = pem_str
        .find("-----BEGIN CERTIFICATE-----")
        .context("no BEGIN CERTIFICATE marker in PCK chain")?;
    let body_start = begin + "-----BEGIN CERTIFICATE-----".len();
    let end = pem_str[body_start..]
        .find("-----END CERTIFICATE-----")
        .context("no END CERTIFICATE marker in PCK chain")?;
    let b64_body: String = pem_str[body_start..body_start + end]
        .lines()
        .map(str::trim)
        .collect();

    let der = BASE64_STANDARD
        .decode(&b64_body)
        .context("base64-decode PCK leaf cert")?;

    // OID 1.2.840.113741.1.13.1.4 in DER: 06 0a 2a 86 48 86 f8 4d 01 0d 01 04
    const FMSPC_OID: &[u8] = &[
        0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04,
    ];
    let idx = der
        .windows(FMSPC_OID.len())
        .position(|w| w == FMSPC_OID)
        .context("FMSPC extension OID not found in PCK leaf certificate")?;

    let after = &der[idx + FMSPC_OID.len()..];
    // Expect: 04 06 <6 bytes FMSPC>
    if after.len() < 8 || after[0] != 0x04 || after[1] != 6 {
        bail!(
            "unexpected DER encoding after FMSPC OID: {:02x?}",
            &after[..after.len().min(8)]
        );
    }
    Ok(hex::encode(&after[2..8]))
}

// ── TDX ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "fetch-collateral")]
fn fetch_tdx(evidence: &[u8], _opts: &TdxCollateralOptions) -> Result<Vec<Endorsement>> {
    let fields = parse_dcap_quote(evidence, 584, 0x00000081)
        .context("parse TDX DCAP quote")?;

    let client = reqwest::blocking::Client::new();

    let tcb_url = format!("{INTEL_PCS_TDX_BASE_URL}/tcb?fmspc={}", fields.fmspc_hex);
    let tcb_bytes = client
        .get(&tcb_url)
        .send()
        .with_context(|| format!("GET {tcb_url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {tcb_url}"))?
        .bytes()
        .context("read TDX TCB info body")?
        .to_vec();

    let qe_url = format!("{INTEL_PCS_TDX_BASE_URL}/qe/identity");
    let qe_bytes = client
        .get(&qe_url)
        .send()
        .with_context(|| format!("GET {qe_url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {qe_url}"))?
        .bytes()
        .context("read TDX QE identity body")?
        .to_vec();

    Ok(vec![
        Endorsement::new(TDX_PCK_CHAIN_LABEL, MEDIA_PEM_CHAIN, fields.pck_chain_pem),
        Endorsement::new(TDX_TCB_INFO_LABEL, MEDIA_JSON, tcb_bytes),
        Endorsement::new(TDX_QE_IDENTITY_LABEL, MEDIA_JSON, qe_bytes),
    ])
}

#[cfg(not(feature = "fetch-collateral"))]
fn fetch_tdx(_evidence: &[u8], _opts: &TdxCollateralOptions) -> Result<Vec<Endorsement>> {
    bail!("collateral fetching requires the `fetch-collateral` Cargo feature")
}

// ── SGX ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "fetch-collateral")]
fn fetch_sgx(evidence: &[u8], _opts: &SgxCollateralOptions) -> Result<Vec<Endorsement>> {
    let fields = parse_dcap_quote(evidence, 384, 0x00000000)
        .context("parse SGX DCAP quote")?;

    let client = reqwest::blocking::Client::new();

    let tcb_url = format!("{INTEL_PCS_SGX_BASE_URL}/tcb?fmspc={}", fields.fmspc_hex);
    let tcb_bytes = client
        .get(&tcb_url)
        .send()
        .with_context(|| format!("GET {tcb_url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {tcb_url}"))?
        .bytes()
        .context("read SGX TCB info body")?
        .to_vec();

    let qe_url = format!("{INTEL_PCS_SGX_BASE_URL}/qe/identity");
    let qe_bytes = client
        .get(&qe_url)
        .send()
        .with_context(|| format!("GET {qe_url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {qe_url}"))?
        .bytes()
        .context("read SGX QE identity body")?
        .to_vec();

    Ok(vec![
        Endorsement::new(SGX_PCK_CHAIN_LABEL, MEDIA_PEM_CHAIN, fields.pck_chain_pem),
        Endorsement::new(SGX_TCB_INFO_LABEL, MEDIA_JSON, tcb_bytes),
        Endorsement::new(SGX_QE_IDENTITY_LABEL, MEDIA_JSON, qe_bytes),
    ])
}

#[cfg(not(feature = "fetch-collateral"))]
fn fetch_sgx(_evidence: &[u8], _opts: &SgxCollateralOptions) -> Result<Vec<Endorsement>> {
    bail!("collateral fetching requires the `fetch-collateral` Cargo feature")
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn snp_evidence_bytes() -> Vec<u8> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        std::fs::read(root.join("test_data/snp_evidence.json")).expect("read snp_evidence.json")
    }

    fn tdx_quote_bytes() -> Vec<u8> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        std::fs::read(root.join("test_data/tdx_quote.bin")).expect("read tdx_quote.bin")
    }

    #[test]
    fn snp_evidence_parses_chip_id_and_tcb() {
        let fields = parse_snp_evidence(&snp_evidence_bytes()).expect("parse SNP evidence");
        assert_eq!(fields.chip_id_hex.len(), 128, "chip_id should be 64 bytes = 128 hex chars");
        // Values from the test fixture
        assert_eq!(fields.bl_svn, 10);
        assert_eq!(fields.snp_svn, 23);
        assert_eq!(fields.ucode_svn, 25);
        assert_eq!(fields.product_name, "Genoa");
    }

    #[test]
    fn tdx_quote_yields_pck_chain_and_fmspc() {
        let quote = tdx_quote_bytes();
        let fields = parse_dcap_quote(&quote, 584, 0x00000081).expect("parse TDX quote");
        assert!(
            fields.pck_chain_pem.starts_with(b"-----BEGIN CERTIFICATE-----"),
            "PCK chain should be PEM"
        );
        assert_eq!(fields.fmspc_hex, "c0806f000000", "FMSPC should match test fixture");
    }

    #[test]
    fn snp_product_detection_covers_known_families() {
        assert_eq!(snp_product_name(25, 0), "Milan");
        assert_eq!(snp_product_name(25, 160), "Genoa");
        assert_eq!(snp_product_name(25, 176), "Bergamo");
        assert_eq!(snp_product_name(99, 0), "Milan"); // fallback
    }
}
