use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail, ensure};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use x509_parser::parse_x509_certificate;
mod native;
pub(crate) use native::ServerTls;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub struct MitmCa {
    ca_cert: Certificate,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmCa {
    pub fn load_or_generate(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        ensure!(
            cert_path != key_path,
            "CA certificate and private key paths must be different: {}",
            cert_path.display()
        );

        let cert_exists = cert_path
            .try_exists()
            .with_context(|| format!("failed to inspect CA cert {}", cert_path.display()))?;
        let key_exists = key_path
            .try_exists()
            .with_context(|| format!("failed to inspect CA key {}", key_path.display()))?;

        match (cert_exists, key_exists) {
            (true, false) => bail!(
                "CA cert exists but its private key is missing: {}",
                key_path.display()
            ),
            (false, true) => bail!(
                "CA key exists but its certificate is missing: {}",
                cert_path.display()
            ),
            _ => {}
        }

        if cert_exists && key_exists {
            let cert_pem = fs::read_to_string(cert_path)
                .with_context(|| format!("failed to read CA cert {}", cert_path.display()))?;
            let ca_cert_der = parse_first_cert_der(&cert_pem)
                .with_context(|| format!("failed to parse CA cert DER {}", cert_path.display()))?;
            let key_pem = fs::read_to_string(key_path)
                .with_context(|| format!("failed to read CA key {}", key_path.display()))?;
            let key_pair = KeyPair::from_pem(&key_pem).context("failed to parse CA key PEM")?;
            ensure_ca_key_matches(&ca_cert_der, &key_pair)?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .context("failed to parse CA cert PEM")?;
            let cert = params
                .self_signed(&key_pair)
                .context("failed to rebuild CA signing metadata")?;
            return Ok(Self {
                ca_cert: cert,
                ca_cert_der,
                ca_cert_pem: cert_pem,
                ca_key: key_pair,
                cache: Mutex::new(HashMap::new()),
            });
        }

        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create CA cert dir {}", parent.display()))?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create CA key dir {}", parent.display()))?;
        }

        let key_pair = KeyPair::generate().context("failed to generate CA key")?;
        let mut params = CertificateParams::new(vec!["Traffic Recorder Proxy Root CA".to_string()])
            .context("failed to create CA params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Traffic Recorder Proxy Root CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let cert = params
            .self_signed(&key_pair)
            .context("failed to generate CA certificate")?;
        let ca_cert_pem = cert.pem();
        let ca_cert_der = cert.der().clone();
        write_new_ca_file(cert_path, ca_cert_pem.as_bytes(), 0o644)
            .with_context(|| format!("failed to write CA cert {}", cert_path.display()))?;
        write_new_ca_file(key_path, key_pair.serialize_pem().as_bytes(), 0o600)
            .with_context(|| format!("failed to write CA key {}", key_path.display()))?;

        Ok(Self {
            ca_cert: cert,
            ca_cert_der,
            ca_cert_pem,
            ca_key: key_pair,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        self.server_config_for_host_and_alpn(host, "http", vec![b"http/1.1".to_vec()])
    }

    pub(crate) fn mysql_server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        self.server_config_for_host_and_alpn(host, "mysql", Vec::new())
    }

    pub(crate) fn server_config_for_transport(
        &self,
        host: &str,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<ServerConfig>> {
        self.server_config_for_host_and_alpn(host, &format!("native/{alpn:?}"), alpn)
    }

    fn server_config_for_host_and_alpn(
        &self,
        host: &str,
        profile: &str,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Arc<ServerConfig>> {
        let normalized = normalize_host(host);
        let cache_key = format!("{profile}:{normalized}");
        if let Some(config) = self
            .cache
            .lock()
            .expect("cert cache poisoned")
            .get(&cache_key)
        {
            return Ok(config.clone());
        }

        let leaf_key = KeyPair::generate().context("failed to generate leaf key")?;
        let mut params = CertificateParams::new(vec![normalized.clone()])
            .with_context(|| format!("failed to create cert params for {normalized}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, normalized.clone());
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .with_context(|| format!("failed to sign leaf certificate for {normalized}"))?;

        let cert_chain = vec![leaf_cert.der().clone(), self.ca_cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .with_context(|| format!("failed to build rustls server config for {normalized}"))?;
        config.alpn_protocols = alpn_protocols;

        let config = Arc::new(config);
        self.cache
            .lock()
            .expect("cert cache poisoned")
            .insert(cache_key, config.clone());
        Ok(config)
    }

    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }

    pub(crate) fn ca_cert_pem_ref(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        self.ca_cert_der.clone()
    }
}

fn ensure_ca_key_matches(cert_der: &[u8], key_pair: &KeyPair) -> Result<()> {
    let (_, cert) =
        parse_x509_certificate(cert_der).context("failed to inspect CA certificate public key")?;
    ensure!(
        cert.public_key().raw == key_pair.public_key_der(),
        "CA certificate and private key do not match"
    );
    Ok(())
}

fn write_new_ca_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn parse_first_cert_der(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = pem.as_bytes();
    let mut certs = rustls_pemfile::certs(&mut reader);
    certs
        .next()
        .transpose()
        .context("failed to parse cert PEM")?
        .ok_or_else(|| anyhow::anyhow!("CA cert PEM did not contain a certificate"))
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    if let Some(stripped) = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']').map(|p| p.0))
    {
        return stripped.to_string();
    }
    host.split(':').next().unwrap_or(host).to_string()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn generates_and_reuses_ca_files() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("ca.pem");
        let key = dir.path().join("ca-key.pem");

        let ca = MitmCa::load_or_generate(&cert, &key).unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        let persisted_pem = std::fs::read_to_string(&cert).unwrap();
        assert_eq!(ca.ca_cert_pem(), persisted_pem);

        let ca = MitmCa::load_or_generate(&cert, &key).unwrap();
        assert_eq!(ca.ca_cert_pem(), persisted_pem);
        let http = ca.server_config_for_host("example.com:443").unwrap();
        let mysql = ca.mysql_server_config_for_host("example.com:3306").unwrap();
        assert_eq!(http.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(mysql.alpn_protocols.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(&cert).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(
                std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn refuses_to_overwrite_a_partial_ca_pair() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("ca.pem");
        let key = dir.path().join("ca-key.pem");
        std::fs::write(&cert, "existing certificate").unwrap();

        let error = MitmCa::load_or_generate(&cert, &key)
            .err()
            .expect("partial CA pair must fail")
            .to_string();

        assert!(error.contains("private key is missing"));
        assert_eq!(
            std::fs::read_to_string(&cert).unwrap(),
            "existing certificate"
        );
        assert!(!key.exists());
    }

    #[test]
    fn refuses_a_mismatched_ca_pair() {
        let dir = tempdir().unwrap();
        let first_cert = dir.path().join("first-ca.pem");
        let first_key = dir.path().join("first-ca-key.pem");
        let second_cert = dir.path().join("second-ca.pem");
        let second_key = dir.path().join("second-ca-key.pem");
        MitmCa::load_or_generate(&first_cert, &first_key).unwrap();
        MitmCa::load_or_generate(&second_cert, &second_key).unwrap();
        std::fs::copy(&second_key, &first_key).unwrap();

        let error = MitmCa::load_or_generate(&first_cert, &first_key)
            .err()
            .expect("mismatched CA pair must fail")
            .to_string();

        assert!(error.contains("do not match"));
    }
}
