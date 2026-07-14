use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_yaml::{Mapping, Value as YamlValue};
use url::Url;

use crate::dns_mock::FakeDnsUpstreamProtocol;

use super::{DiscoveredTarget, KubectlProxySpec, Plugin, PluginResult, RewriteInput};

const PLUGIN_NAME: &str = "pluto-eci-kubeconfig";
const PLUTO_ECI_ALIAS: &str = "k8s-c142fe56e07d04a749c1630fb5f1b680b.pluto-eci.trp.test";

pub(super) struct EciKubeconfig {
    kubectl_binary: String,
    proxy_listen: SocketAddr,
    kubectl_proxy: Url,
    connect_ip: Ipv4Addr,
    recorder_ca_pem: String,
}

impl EciKubeconfig {
    pub(super) fn new(
        kubectl_binary: &str,
        proxy_listen: SocketAddr,
        recorder_ca_pem: &str,
    ) -> Result<Self> {
        let IpAddr::V4(connect_ip) = proxy_listen.ip() else {
            bail!("managed kubectl proxy listen address is not IPv4");
        };
        let kubectl_proxy = Url::parse(&format!("https://{proxy_listen}"))
            .context("invalid managed kubectl proxy client URL")?;
        Ok(Self {
            kubectl_binary: kubectl_binary.to_string(),
            proxy_listen,
            kubectl_proxy,
            connect_ip,
            recorder_ca_pem: recorder_ca_pem.to_string(),
        })
    }
}

impl Plugin for EciKubeconfig {
    fn name(&self) -> &'static str {
        PLUGIN_NAME
    }

    fn rewrite(&self, input: &RewriteInput<'_>) -> Result<PluginResult> {
        let mut response: serde_json::Value =
            serde_json::from_slice(input.body).context("response body is not valid JSON")?;
        let config = response
            .get("config")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("response JSON has no string config field"))?
            .to_string();
        let original_kubeconfig = config.as_bytes().to_vec();
        let mut kubeconfig: YamlValue =
            serde_yaml::from_str(&config).context("config field is not valid kubeconfig YAML")?;
        {
            let server = single_cluster_server(&mut kubeconfig)?;
            let original =
                Url::parse(server).context("kubeconfig cluster server is not a valid URL")?;
            let Some(original_host) = original.host_str() else {
                bail!("kubeconfig cluster server URL has no host");
            };
            if original_host.parse::<Ipv4Addr>().is_err() {
                return Ok(PluginResult::Unchanged);
            }

            let mut rewritten = self.kubectl_proxy.clone();
            rewritten
                .set_host(Some(PLUTO_ECI_ALIAS))
                .map_err(|_| anyhow!("failed to set kubeconfig alias host"))?;
            *server = rewritten.as_str().trim_end_matches('/').to_string();
        }
        replace_cluster_ca(&mut kubeconfig, &self.recorder_ca_pem)?;
        let rendered = serde_yaml::to_string(&kubeconfig)
            .context("failed to serialize rewritten kubeconfig")?;
        response["config"] = serde_json::Value::String(rendered);
        let body = serde_json::to_vec(&response)
            .context("failed to serialize rewritten Pluto response")?;

        Ok(PluginResult::Rewritten {
            body,
            target: DiscoveredTarget {
                alias: PLUTO_ECI_ALIAS.to_string(),
                connect_ip: self.connect_ip,
                upstream_authority: self.proxy_listen.to_string(),
                upstream_protocol: FakeDnsUpstreamProtocol::Http,
            },
            kubectl_proxy: KubectlProxySpec {
                binary: self.kubectl_binary.clone(),
                listen: self.proxy_listen,
                kubeconfig: original_kubeconfig,
            },
        })
    }
}

fn single_cluster(kubeconfig: &mut YamlValue) -> Result<&mut Mapping> {
    let root = kubeconfig
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("kubeconfig root is not a mapping"))?;
    let clusters = mapping_value_mut(root, "clusters")?
        .as_sequence_mut()
        .ok_or_else(|| anyhow!("kubeconfig clusters is not a sequence"))?;
    if clusters.len() != 1 {
        bail!(
            "pluto-eci-kubeconfig requires exactly one cluster, found {}",
            clusters.len()
        );
    }
    let entry = clusters[0]
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("kubeconfig cluster entry is not a mapping"))?;
    let cluster = mapping_value_mut(entry, "cluster")?
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("kubeconfig cluster field is not a mapping"))?;
    Ok(cluster)
}

fn single_cluster_server(kubeconfig: &mut YamlValue) -> Result<&mut String> {
    let cluster = single_cluster(kubeconfig)?;
    match mapping_value_mut(cluster, "server")? {
        YamlValue::String(server) => Ok(server),
        _ => Err(anyhow!("kubeconfig cluster server is not a string")),
    }
}

fn replace_cluster_ca(kubeconfig: &mut YamlValue, recorder_ca_pem: &str) -> Result<()> {
    let cluster = single_cluster(kubeconfig)?;
    cluster.insert(
        YamlValue::String("certificate-authority-data".to_string()),
        YamlValue::String(STANDARD.encode(recorder_ca_pem.as_bytes())),
    );
    cluster.remove(YamlValue::String("certificate-authority".to_string()));
    cluster.remove(YamlValue::String("insecure-skip-tls-verify".to_string()));
    Ok(())
}

fn mapping_value_mut<'a>(mapping: &'a mut Mapping, key: &str) -> Result<&'a mut YamlValue> {
    mapping
        .get_mut(YamlValue::String(key.to_string()))
        .ok_or_else(|| anyhow!("kubeconfig has no {key} field"))
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use hyper::HeaderMap;
    use hyper::{Method, StatusCode};

    use super::*;

    fn input<'a>(uri: &'a hyper::Uri, body: &'a [u8]) -> RewriteInput<'a> {
        RewriteInput {
            method: &Method::GET,
            uri,
            authority: Some("cs.aliyuncs.com"),
            status: StatusCode::OK,
            headers: Box::leak(Box::new(HeaderMap::new())),
            body,
        }
    }

    #[test]
    fn rewrites_single_ip_server_and_preserves_credentials() {
        let recorder_ca = "-----BEGIN CERTIFICATE-----\nRECORDER-CA\n-----END CERTIFICATE-----\n";
        let plugin =
            EciKubeconfig::new("kubectl", "127.0.0.1:8001".parse().unwrap(), recorder_ca).unwrap();
        let uri = "/configured/exact/path".parse().unwrap();
        let body = serde_json::json!({
            "config": "apiVersion: v1\nclusters:\n- cluster:\n    server: https://182.92.232.38:6443\n    certificate-authority-data: REDACTED\n  name: kubernetes\nusers:\n- name: admin\n  user:\n    client-key-data: REDACTED\n",
            "expiration": "2027-01-01T00:00:00Z"
        });
        let bytes = serde_json::to_vec(&body).unwrap();

        let PluginResult::Rewritten {
            body,
            target,
            kubectl_proxy,
        } = plugin.rewrite(&input(&uri, &bytes)).unwrap()
        else {
            panic!("expected rewritten response");
        };
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let config = response["config"].as_str().unwrap();
        let kubeconfig: YamlValue = serde_yaml::from_str(config).unwrap();
        assert_eq!(
            kubeconfig["clusters"][0]["cluster"]["server"].as_str(),
            Some(format!("https://{PLUTO_ECI_ALIAS}:8001").as_str())
        );
        let rewritten_ca = kubeconfig["clusters"][0]["cluster"]["certificate-authority-data"]
            .as_str()
            .unwrap();
        assert_eq!(
            STANDARD.decode(rewritten_ca).unwrap(),
            recorder_ca.as_bytes()
        );
        assert!(config.contains("client-key-data: REDACTED"));
        assert_eq!(target.connect_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(target.upstream_authority, "127.0.0.1:8001");
        assert_eq!(target.upstream_protocol, FakeDnsUpstreamProtocol::Http);
        assert_eq!(kubectl_proxy.binary, "kubectl");
        assert!(
            String::from_utf8(kubectl_proxy.kubeconfig)
                .unwrap()
                .contains("182.92.232.38")
        );
    }

    #[test]
    fn leaves_domain_server_unchanged() {
        let plugin =
            EciKubeconfig::new("kubectl", "127.0.0.1:8001".parse().unwrap(), "recorder-ca")
                .unwrap();
        let uri = "/configured/exact/path".parse().unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "config": "clusters:\n- cluster:\n    server: https://cluster.example.test:6443\n"
        }))
        .unwrap();

        assert!(matches!(
            plugin.rewrite(&input(&uri, &body)).unwrap(),
            PluginResult::Unchanged
        ));
    }
}
