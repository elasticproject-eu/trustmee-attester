//! Collateral fetching for TDX, SNP, and SGX attestation evidence.
//!
//! Call [`fetch_collateral`] to retrieve the relevant certificates and TCB
//! metadata for a piece of evidence, returned as [`Endorsement`]s ready to
//! attach to a [`BuildInput`](crate::BuildInput).
//!
//! Requires the `fetch-collateral` Cargo feature (enabled by default).

use crate::Endorsement;
#[cfg(any(feature = "fetch-collateral", test))]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(feature = "fetch-collateral", test))]
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
#[cfg(any(feature = "fetch-collateral", test))]
use base64::Engine as _;
#[cfg(any(feature = "fetch-collateral", test))]
use ciborium::into_writer;
#[cfg(any(feature = "fetch-collateral", test))]
use dcap_qvl::QuoteCollateralV3;
#[cfg(any(feature = "fetch-collateral", test))]
use serde::Serialize;
#[cfg(any(feature = "fetch-collateral", test))]
use serde_json::Value;
#[cfg(any(feature = "fetch-collateral", test))]
use sev::firmware::host::{CertTableEntry, CertType};

// ── Media types ───────────────────────────────────────────────────────────────

pub const MEDIA_PKIX_CERT: &str = "application/pkix-cert";
pub const MEDIA_PEM_CHAIN: &str = "application/pem-certificate-chain";
pub const MEDIA_JSON: &str = "application/json";
pub const SNP_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.snp-collateral+cbor";
pub const TDX_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.tdx-collateral+cbor";
pub const SGX_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.sgx-collateral+cbor";

// ── Endorsement labels ────────────────────────────────────────────────────────

pub const SNP_VCEK_LABEL: &str = "snp-vcek";
pub const SNP_CERT_CHAIN_LABEL: &str = "snp-cert-chain";
pub const SNP_COLLATERAL_LABEL: &str = "snp-collateral";
pub const TDX_COLLATERAL_LABEL: &str = "tdx-collateral";
pub const TDX_PCK_CHAIN_LABEL: &str = "tdx-pck-chain";
pub const TDX_TCB_INFO_LABEL: &str = "tdx-tcb-info";
pub const TDX_QE_IDENTITY_LABEL: &str = "tdx-qe-identity";
pub const SGX_COLLATERAL_LABEL: &str = "sgx-collateral";
pub const SGX_PCK_CHAIN_LABEL: &str = "sgx-pck-chain";
pub const SGX_TCB_INFO_LABEL: &str = "sgx-tcb-info";
pub const SGX_QE_IDENTITY_LABEL: &str = "sgx-qe-identity";

// ── Default service URLs ──────────────────────────────────────────────────────

pub const AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com";
pub const INTEL_PCS_TDX_BASE_URL: &str =
    "https://api.trustedservices.intel.com/tdx/certification/v4";
pub const INTEL_PCS_SGX_BASE_URL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4";
/// Phala Network's public PCCS — proxies Intel PCS for TCB/QE-identity and
/// also serves the `pckcert` endpoint without an `Ocp-Apim-Subscription-Key`
/// header. Used as the SGX default so quotes with `cert_type` 2/3 (encrypted
/// PPID) — where the PCK certificate must be fetched rather than read from
/// the quote — work out of the box.
pub const PHALA_PCCS_BASE_URL: &str = "https://pccs.phala.network";

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
/// Certification Service (PCS) or a compatible PCCS.
#[derive(Clone, Debug)]
pub struct TdxCollateralOptions {
    /// Base URL of the PCS/PCCS to query. Defaults to [`INTEL_PCS_TDX_BASE_URL`].
    pub pccs_base_url: String,
}

impl Default for TdxCollateralOptions {
    fn default() -> Self {
        Self {
            pccs_base_url: INTEL_PCS_TDX_BASE_URL.to_string(),
        }
    }
}

/// Options for fetching Intel SGX collateral from a PCS/PCCS.
///
/// SGX quotes commonly use certification data type 2 or 3 (encrypted PPID),
/// where the PCK certificate is *not* embedded in the quote and must be
/// fetched from a PCCS. Intel's PCS gates that endpoint behind a subscription
/// key, so the default is [`PHALA_PCCS_BASE_URL`] which serves it without
/// authentication.
#[derive(Clone, Debug)]
pub struct SgxCollateralOptions {
    /// Base URL of the PCS/PCCS to query. Defaults to [`PHALA_PCCS_BASE_URL`].
    pub pccs_base_url: String,
}

impl Default for SgxCollateralOptions {
    fn default() -> Self {
        Self {
            pccs_base_url: PHALA_PCCS_BASE_URL.to_string(),
        }
    }
}

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
pub fn fetch_collateral(evidence: &[u8], source: &CollateralSource) -> Result<Vec<Endorsement>> {
    match source {
        CollateralSource::Snp(opts) => fetch_snp(evidence, opts),
        CollateralSource::Tdx(opts) => fetch_tdx(evidence, opts),
        CollateralSource::Sgx(opts) => fetch_sgx(evidence, opts),
    }
}

// ── SNP ───────────────────────────────────────────────────────────────────────

#[cfg(any(feature = "fetch-collateral", test))]
struct SnpFields {
    chip_id_hex: String,
    bl_svn: u8,
    tee_svn: u8,
    snp_svn: u8,
    ucode_svn: u8,
    product_name: String,
}

#[cfg(any(feature = "fetch-collateral", test))]
#[derive(Serialize)]
struct SnpCollateral {
    cert_chain: Vec<CertTableEntry>,
}

#[cfg(any(feature = "fetch-collateral", test))]
fn snp_vcek_collateral_endorsement(vcek_bytes: Vec<u8>) -> Result<Endorsement> {
    let collateral = SnpCollateral {
        cert_chain: vec![CertTableEntry {
            cert_type: CertType::VCEK,
            data: vcek_bytes,
        }],
    };

    let mut payload = Vec::new();
    into_writer(&collateral, &mut payload).context("encode SNP collateral as CBOR")?;

    Ok(Endorsement::new(
        SNP_COLLATERAL_LABEL,
        SNP_COLLATERAL_MEDIA_TYPE,
        payload,
    ))
}

#[cfg(any(feature = "fetch-collateral", test))]
fn parse_snp_evidence(evidence: &[u8]) -> Result<SnpFields> {
    let json: Value = serde_json::from_slice(evidence).context("SNP evidence is not valid JSON")?;

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

#[cfg(any(feature = "fetch-collateral", test))]
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

    Ok(vec![snp_vcek_collateral_endorsement(vcek_bytes)?])
}

#[cfg(not(feature = "fetch-collateral"))]
fn fetch_snp(_evidence: &[u8], _opts: &SnpCollateralOptions) -> Result<Vec<Endorsement>> {
    anyhow::bail!("collateral fetching requires the `fetch-collateral` Cargo feature")
}

// ── TDX / SGX shared quote parsing ───────────────────────────────────────────

/// Parsed fields extracted from a binary ECDSA DCAP quote (TDX or SGX).
#[cfg(test)]
struct QuoteFields {
    /// PEM-encoded PCK cert chain (leaf PCK cert + intermediate + root).
    pck_chain_pem: Vec<u8>,
    /// 6-byte FMSPC extracted from the PCK leaf certificate.
    fmspc_hex: String,
}

#[cfg(test)]
fn parse_dcap_quote(
    evidence: &[u8],
    report_body_size: usize,
    tee_type: u32,
) -> Result<QuoteFields> {
    if evidence.len() < 48 {
        anyhow::bail!("quote too short for header ({} bytes)", evidence.len());
    }
    let version = u16::from_le_bytes([evidence[0], evidence[1]]);
    let actual_tee = u32::from_le_bytes(evidence[4..8].try_into().expect("slice always 4 bytes"));
    if actual_tee != tee_type {
        anyhow::bail!("expected TEE type 0x{tee_type:08x}, got 0x{actual_tee:08x}");
    }

    let _ = version; // version check left to callers

    let sig_len_offset = 48 + report_body_size;
    if evidence.len() < sig_len_offset + 4 {
        anyhow::bail!("quote truncated before signature length field");
    }
    let sig_len = u32::from_le_bytes(
        evidence[sig_len_offset..sig_len_offset + 4]
            .try_into()
            .expect("slice always 4 bytes"),
    ) as usize;
    let sig_start = sig_len_offset + 4;
    if evidence.len() < sig_start + sig_len {
        anyhow::bail!("quote truncated in signature data");
    }
    let sig_data = &evidence[sig_start..sig_start + sig_len];
    extract_pck_chain(sig_data)
}

/// Navigate the ECDSA-256 signature data to locate the PEM PCK cert chain and
/// extract the FMSPC from the leaf certificate.
#[cfg(test)]
fn extract_pck_chain(sig_data: &[u8]) -> Result<QuoteFields> {
    // Layout: ECDSA sig (64) + attest pubkey (64) + cert data type (2) +
    //         cert data len (4) + cert data (variable)
    if sig_data.len() < 134 {
        anyhow::bail!("ECDSA signature data too short ({} bytes)", sig_data.len());
    }

    let cert_type = u16::from_le_bytes([sig_data[128], sig_data[129]]);
    let cert_len =
        u32::from_le_bytes(sig_data[130..134].try_into().expect("slice always 4 bytes")) as usize;
    if sig_data.len() < 134 + cert_len {
        anyhow::bail!("cert data truncated in signature block");
    }
    let cert_data = &sig_data[134..134 + cert_len];

    let pck_pem = match cert_type {
        // Type 5: PCK cert chain in PEM (leaf + intermediate + root)
        5 => cert_data.to_vec(),
        // Type 6: QE report cert data — PCK chain nested inside as type 5
        6 => extract_pck_chain_from_type6(cert_data)?,
        t => anyhow::bail!("unsupported ECDSA cert data type {t}; expected 5 or 6"),
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
#[cfg(test)]
fn extract_pck_chain_from_type6(cert_data: &[u8]) -> Result<Vec<u8>> {
    let mut off = 384 + 64; // skip QE report + QE report sig
    if cert_data.len() < off + 2 {
        anyhow::bail!("type-6 cert data truncated before QE auth length");
    }
    let auth_len = u16::from_le_bytes([cert_data[off], cert_data[off + 1]]) as usize;
    off += 2 + auth_len;

    if cert_data.len() < off + 6 {
        anyhow::bail!("type-6 cert data truncated before inner cert type/length");
    }
    let inner_type = u16::from_le_bytes([cert_data[off], cert_data[off + 1]]);
    let inner_len = u32::from_le_bytes(
        cert_data[off + 2..off + 6]
            .try_into()
            .expect("slice always 4 bytes"),
    ) as usize;
    off += 6;

    if inner_type != 5 {
        anyhow::bail!(
            "unexpected inner cert type {inner_type} in type-6 data; expected 5 (PCK chain)"
        );
    }
    if cert_data.len() < off + inner_len {
        anyhow::bail!("inner PCK cert chain truncated");
    }
    Ok(cert_data[off..off + inner_len].to_vec())
}

/// Extract the FMSPC from the leaf PCK certificate in a PEM cert chain.
///
/// FMSPC lives in the SGX FMSPC extension (OID 1.2.840.113741.1.13.1.4),
/// encoded as a 6-byte OCTET STRING. We locate it with a fast byte-pattern
/// search on the DER-decoded leaf cert.
#[cfg(any(feature = "fetch-collateral", test))]
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
        anyhow::bail!(
            "unexpected DER encoding after FMSPC OID: {:02x?}",
            &after[..after.len().min(8)]
        );
    }
    Ok(hex::encode(&after[2..8]))
}

#[cfg(any(feature = "fetch-collateral", test))]
fn quote_bytes_from_dcap_evidence(evidence: &[u8], tee: &str) -> Result<Vec<u8>> {
    if let Ok(s) = std::str::from_utf8(evidence) {
        if s.trim_start().starts_with('{') {
            let json: Value =
                serde_json::from_str(s).with_context(|| format!("parse {tee} evidence JSON"))?;
            let quote = json
                .get("quote")
                .and_then(Value::as_str)
                .with_context(|| format!("missing base64 `quote` field in {tee} evidence JSON"))?;
            return BASE64_STANDARD
                .decode(quote)
                .with_context(|| format!("decode base64 {tee} quote"));
        }
    }

    Ok(evidence.to_vec())
}

#[cfg(any(feature = "fetch-collateral", test))]
fn dcap_collateral_endorsement(
    label: &str,
    media_type: &str,
    collateral: &QuoteCollateralV3,
) -> Result<Endorsement> {
    let mut payload = Vec::new();
    into_writer(collateral, &mut payload).context("encode DCAP collateral as CBOR")?;
    Ok(Endorsement::new(label, media_type, payload))
}

#[cfg(feature = "fetch-collateral")]
fn fetch_dcap_collateral_endorsement(
    evidence: &[u8],
    tee: &str,
    label: &str,
    media_type: &str,
    pccs_base_url: &str,
) -> Result<Endorsement> {
    let quote = quote_bytes_from_dcap_evidence(evidence, tee)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create Tokio runtime for collateral fetch")?;
    let collateral = runtime
        .block_on(fetch_quote_collateral(&quote, pccs_base_url))
        .with_context(|| format!("fetch {tee} collateral from {pccs_base_url}"))?;

    dcap_collateral_endorsement(label, media_type, &collateral)
}

/// Fetch full DCAP collateral for a quote.
///
/// `dcap_qvl::collateral::get_collateral` rejects PCK responses whose
/// `SGX-TCBm` header indicates that PCS matched the request to a *lower* TCB
/// level than the one in the quote. That's a useful safety check on a
/// freshly-attesting platform, but it makes verification of any quote whose
/// platform TCB has since aged out impossible. Instead we:
///
/// 1. Read the PCK chain straight out of the quote when `cert_type == 5`, or
///    fetch it via PCCS using the encrypted-PPID parameters when
///    `cert_type ∈ {2, 3}` — without bailing on a TCBm mismatch.
/// 2. Pull TCB info, QE identity, and CRLs via
///    [`dcap_qvl::collateral::get_collateral_for_fmspc`].
/// 3. Staple the PCK chain onto the resulting [`QuoteCollateralV3`].
#[cfg(feature = "fetch-collateral")]
async fn fetch_quote_collateral(quote: &[u8], pccs_base_url: &str) -> Result<QuoteCollateralV3> {
    use dcap_qvl::quote::Quote;

    const CERT_TYPE_ENCRYPTED_PPID_2048: u16 = 2;
    const CERT_TYPE_ENCRYPTED_PPID_3072: u16 = 3;
    const CERT_TYPE_PCK_CERT_CHAIN: u16 = 5;

    let parsed = Quote::parse(quote).context("parse DCAP quote")?;
    let cert_type = parsed.inner_cert_type();
    let pck_chain_pem: String = match cert_type {
        CERT_TYPE_PCK_CERT_CHAIN => String::from_utf8(parsed.inner_cert_data().to_vec())
            .context("PCK cert chain in quote is not valid UTF-8")?,
        CERT_TYPE_ENCRYPTED_PPID_2048 | CERT_TYPE_ENCRYPTED_PPID_3072 => {
            let params = parsed
                .encrypted_ppid_params()
                .context("decode encrypted PPID parameters from quote cert data")?;
            fetch_pck_certificate_chain(pccs_base_url, parsed.qeid(), &params).await?
        }
        other => {
            anyhow::bail!("unsupported quote certification data type {other}; expected 2, 3, or 5")
        }
    };

    let fmspc_hex = fmspc_from_pck_pem(pck_chain_pem.as_bytes())?;
    let ca = pck_chain_ca(pck_chain_pem.as_bytes());

    let mut collateral = dcap_qvl::collateral::get_collateral_for_fmspc(
        pccs_base_url,
        fmspc_hex.to_ascii_uppercase(),
        ca,
        parsed.header.is_sgx(),
    )
    .await
    .with_context(|| format!("fetch FMSPC-keyed collateral for {fmspc_hex}"))?;
    collateral.pck_certificate_chain = Some(pck_chain_pem);
    Ok(collateral)
}

/// Fetch the PCK certificate chain from a PCS/PCCS by encrypted-PPID
/// parameters, returning the leaf followed by its issuer chain in one PEM
/// string. Tolerates `SGX-TCBm` headers indicating a lower-TCB match.
#[cfg(feature = "fetch-collateral")]
async fn fetch_pck_certificate_chain(
    pccs_base_url: &str,
    qeid: &[u8],
    params: &dcap_qvl::quote::EncryptedPpidParams,
) -> Result<String> {
    let qeid = hex::encode_upper(qeid);
    let encrypted_ppid = hex::encode_upper(&params.encrypted_ppid);
    let cpusvn = hex::encode_upper(params.cpusvn);
    let pcesvn = hex::encode_upper(params.pcesvn.to_le_bytes());
    let pceid = hex::encode_upper(params.pceid);

    let base_url = pccs_base_url
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4");
    let url = format!(
        "{base_url}/sgx/certification/v4/pckcert\
         ?qeid={qeid}&encrypted_ppid={encrypted_ppid}\
         &cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}"
    );
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error fetching PCK certificate from {url}"))?;

    let issuer_chain_raw = response
        .headers()
        .get("SGX-PCK-Certificate-Issuer-Chain")
        .ok_or_else(|| {
            anyhow::anyhow!("PCK response from {url} missing SGX-PCK-Certificate-Issuer-Chain")
        })?
        .to_str()
        .context("PCK issuer chain header is not ASCII")?
        .to_owned();
    let issuer_chain = percent_decode(&issuer_chain_raw);
    let pck_leaf = response.text().await.context("read PCK certificate body")?;
    Ok(format!("{}\n{issuer_chain}", pck_leaf.trim_end()))
}

/// Minimal `application/x-www-form-urlencoded` decoder for HTTP header
/// values. The `SGX-PCK-Certificate-Issuer-Chain` header is URL-encoded.
#[cfg(feature = "fetch-collateral")]
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Detect whether a PCK leaf certificate was issued by Intel SGX PCK
/// `Processor CA` or `Platform CA`. Returns the corresponding PCS query
/// parameter (`"processor"` or `"platform"`).
#[cfg(any(feature = "fetch-collateral", test))]
fn pck_chain_ca(pem: &[u8]) -> &'static str {
    let pem_str = match std::str::from_utf8(pem) {
        Ok(s) => s,
        Err(_) => return "processor",
    };
    let mut der_blob: Vec<u8> = Vec::new();
    for chunk in pem_str.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some(end) = chunk.find("-----END CERTIFICATE-----") else {
            continue;
        };
        let b64: String = chunk[..end].lines().map(str::trim).collect();
        if let Ok(der) = BASE64_STANDARD.decode(&b64) {
            der_blob.extend(der);
        }
    }
    if der_blob
        .windows(b"Intel SGX PCK Platform CA".len())
        .any(|w| w == b"Intel SGX PCK Platform CA")
    {
        "platform"
    } else {
        "processor"
    }
}

// ── TDX ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "fetch-collateral")]
fn fetch_tdx(evidence: &[u8], opts: &TdxCollateralOptions) -> Result<Vec<Endorsement>> {
    Ok(vec![fetch_dcap_collateral_endorsement(
        evidence,
        "TDX",
        TDX_COLLATERAL_LABEL,
        TDX_COLLATERAL_MEDIA_TYPE,
        &opts.pccs_base_url,
    )?])
}

#[cfg(not(feature = "fetch-collateral"))]
fn fetch_tdx(_evidence: &[u8], _opts: &TdxCollateralOptions) -> Result<Vec<Endorsement>> {
    anyhow::bail!("collateral fetching requires the `fetch-collateral` Cargo feature")
}

// ── SGX ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "fetch-collateral")]
fn fetch_sgx(evidence: &[u8], opts: &SgxCollateralOptions) -> Result<Vec<Endorsement>> {
    Ok(vec![fetch_dcap_collateral_endorsement(
        evidence,
        "SGX",
        SGX_COLLATERAL_LABEL,
        SGX_COLLATERAL_MEDIA_TYPE,
        &opts.pccs_base_url,
    )?])
}

#[cfg(not(feature = "fetch-collateral"))]
fn fetch_sgx(_evidence: &[u8], _opts: &SgxCollateralOptions) -> Result<Vec<Endorsement>> {
    anyhow::bail!("collateral fetching requires the `fetch-collateral` Cargo feature")
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
        assert_eq!(
            fields.chip_id_hex.len(),
            128,
            "chip_id should be 64 bytes = 128 hex chars"
        );
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
            fields
                .pck_chain_pem
                .starts_with(b"-----BEGIN CERTIFICATE-----"),
            "PCK chain should be PEM"
        );
        assert_eq!(
            fields.fmspc_hex, "c0806f000000",
            "FMSPC should match test fixture"
        );
    }

    #[test]
    fn snp_product_detection_covers_known_families() {
        assert_eq!(snp_product_name(25, 0), "Milan");
        assert_eq!(snp_product_name(25, 160), "Genoa");
        assert_eq!(snp_product_name(25, 176), "Bergamo");
        assert_eq!(snp_product_name(99, 0), "Milan"); // fallback
    }

    #[test]
    fn snp_vcek_collateral_endorsement_matches_verifier_format() {
        #[derive(serde::Deserialize)]
        struct DecodedSnpCollateral {
            cert_chain: Vec<CertTableEntry>,
        }

        let endorsement =
            snp_vcek_collateral_endorsement(vec![1, 2, 3]).expect("build SNP collateral");

        assert_eq!(endorsement.label, SNP_COLLATERAL_LABEL);
        assert_eq!(endorsement.media_type, SNP_COLLATERAL_MEDIA_TYPE);

        let decoded: DecodedSnpCollateral = ciborium::from_reader(endorsement.payload.as_slice())
            .expect("decode SNP collateral CBOR");
        assert_eq!(decoded.cert_chain.len(), 1);
        assert_eq!(decoded.cert_chain[0].cert_type, CertType::VCEK);
        assert_eq!(decoded.cert_chain[0].data, vec![1, 2, 3]);
    }

    fn sample_dcap_collateral() -> QuoteCollateralV3 {
        QuoteCollateralV3 {
            pck_crl_issuer_chain: "pck issuer".to_string(),
            root_ca_crl: vec![1, 2],
            pck_crl: vec![3, 4],
            tcb_info_issuer_chain: "tcb issuer".to_string(),
            tcb_info: r#"{"nextUpdate":"2035-01-01T00:00:00Z"}"#.to_string(),
            tcb_info_signature: vec![5, 6],
            qe_identity_issuer_chain: "qe issuer".to_string(),
            qe_identity: r#"{"nextUpdate":"2035-01-01T00:00:00Z"}"#.to_string(),
            qe_identity_signature: vec![7, 8],
            pck_certificate_chain: Some("pck chain".to_string()),
        }
    }

    #[test]
    fn dcap_collateral_endorsement_matches_tdx_verifier_format() {
        let endorsement = dcap_collateral_endorsement(
            TDX_COLLATERAL_LABEL,
            TDX_COLLATERAL_MEDIA_TYPE,
            &sample_dcap_collateral(),
        )
        .expect("build TDX collateral");

        assert_eq!(endorsement.label, TDX_COLLATERAL_LABEL);
        assert_eq!(endorsement.media_type, TDX_COLLATERAL_MEDIA_TYPE);

        let decoded: QuoteCollateralV3 = ciborium::from_reader(endorsement.payload.as_slice())
            .expect("decode TDX collateral CBOR");
        assert_eq!(decoded.pck_certificate_chain.as_deref(), Some("pck chain"));
    }

    #[test]
    fn dcap_collateral_endorsement_matches_sgx_verifier_format() {
        let endorsement = dcap_collateral_endorsement(
            SGX_COLLATERAL_LABEL,
            SGX_COLLATERAL_MEDIA_TYPE,
            &sample_dcap_collateral(),
        )
        .expect("build SGX collateral");

        assert_eq!(endorsement.label, SGX_COLLATERAL_LABEL);
        assert_eq!(endorsement.media_type, SGX_COLLATERAL_MEDIA_TYPE);

        let decoded: QuoteCollateralV3 = ciborium::from_reader(endorsement.payload.as_slice())
            .expect("decode SGX collateral CBOR");
        assert_eq!(decoded.qe_identity_signature, vec![7, 8]);
    }
}
