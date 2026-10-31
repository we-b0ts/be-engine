//! The single authoring boundary for standalone and embedded Recorder settings.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::{Mapping, Value};

use super::*;

// Remote derive keeps runtime state separate from authoring normalization, while
// retaining strict fields and the existing effective AppConfig public interface.
#[derive(Default, Deserialize, Serialize)]
#[serde(remote = "AppConfig", default, deny_unknown_fields)]
struct RecorderFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    capture: Option<CaptureConfig>,
    artifacts: Option<ArtifactsConfig>,
    dns_mock: DnsMockConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    upstream_routes: Vec<UpstreamRouteConfig>,
    #[serde(skip_serializing_if = "KubernetesConfig::is_default")]
    kubernetes: KubernetesConfig,
    tcp_gateway: TcpGatewayConfig,
    udp_gateway: UdpGatewayConfig,
    http: HttpConfig,
    http_response_rewrite: HttpResponseRewriteConfig,
    http_gateway: HttpGatewayConfig,
    motan_gateway: MotanGatewayConfig,
    mysql: MysqlConfig,
    recording: RecordingConfig,
    tls: TlsConfig,
    #[serde(skip)]
    process_owned_dependencies: Vec<BackgroundDependencyRuleConfig>,
    #[serde(skip)]
    process_dependency_tasks: BTreeMap<String, String>,
    #[serde(skip)]
    async_api: BTreeMap<String, crate::policy::AsyncApiRules>,
    #[serde(skip)]
    global_projection_policy: Option<String>,
}

impl<'de> Deserialize<'de> for AppConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let mut document = Value::deserialize(deserializer)?;
        let mapping = document
            .as_mapping_mut()
            .ok_or_else(|| serde::de::Error::custom("recorder must be a mapping"))?;
        if let Some(capture) = mapping.get("capture").filter(|value| !value.is_null()) {
            let capture = serde_yaml::from_value::<CaptureConfig>(capture.clone())
                .map_err(serde::de::Error::custom)?;
            capture::compile(mapping, &capture).map_err(serde::de::Error::custom)?;
        }
        RecorderFields::deserialize(document).map_err(serde::de::Error::custom)
    }
}

impl Serialize for AppConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if self.capture.is_none() {
            return RecorderFields::serialize(self, serializer);
        }
        let mut document = RecorderFields::serialize(self, serde_yaml::value::Serializer)
            .map_err(serde::ser::Error::custom)?;
        if let Some(capture) = &self.capture {
            let mut defaults = Mapping::new();
            defaults.insert(
                "capture".into(),
                serde_yaml::to_value(capture).map_err(serde::ser::Error::custom)?,
            );
            capture::compile(&mut defaults, capture).map_err(serde::ser::Error::custom)?;
            let defaults = RecorderFields::deserialize(Value::Mapping(defaults))
                .map_err(serde::ser::Error::custom)?;
            let defaults = RecorderFields::serialize(&defaults, serde_yaml::value::Serializer)
                .map_err(serde::ser::Error::custom)?;
            prune_defaults(&mut document, &defaults, true);
        }
        document.serialize(serializer)
    }
}

fn prune_defaults(document: &mut Value, defaults: &Value, root: bool) {
    let (Some(document), Some(defaults)) = (document.as_mapping_mut(), defaults.as_mapping())
    else {
        return;
    };
    document.retain(|key, value| {
        if root && key.as_str() == Some("capture") {
            return true;
        }
        let Some(default) = defaults.get(key) else {
            return true;
        };
        if value == default {
            return false;
        }
        prune_defaults(value, default, false);
        !value.as_mapping().is_some_and(Mapping::is_empty)
    });
}
