//! Optional gateway discovery and reservation coordination, separate from recording.

use super::{RecordOptions, api_policy::ApiPolicy};
use anyhow::{Context, Result, ensure};
use brz_http_gateway::redis_admission::{RecorderRegistration, RedisAdmissionProvider};
use brz_redis::{Redis, RedisService, RedisServiceOptions, Value, cmd};
use std::{num::NonZeroU32, time::Duration};
use tracing::{info, warn};

pub(super) struct Coordination {
    startup: Option<(RedisService, String)>,
    registration: Option<RecorderRegistration<RedisService>>,
    pub(super) reservations: Option<RedisAdmissionProvider<RedisService>>,
}

impl Coordination {
    pub(super) async fn connect(options: &RecordOptions, capacity: NonZeroU32) -> Result<Self> {
        if options.coordination.is_none() {
            return Ok(Self {
                startup: None,
                registration: None,
                reservations: None,
            });
        }
        let redis = connect_redis(
            options
                .redis_url
                .as_deref()
                .context("Redis coordination requires --redis-url")?,
        )
        .await?;
        let url = options
            .advertise_url
            .as_deref()
            .context("Redis coordination requires --advertise-url")?
            .parse()?;
        let registration = RecorderRegistration::new(
            redis.clone(),
            options.discovery_key(),
            url,
            Duration::from_secs(30),
        )?
        .with_max_inflight(capacity)?;
        let reservations =
            RedisAdmissionProvider::new(redis.clone(), &options.prefix, options.discovery_key())?;
        Ok(Self {
            startup: Some((redis, options.prefix.clone())),
            registration: Some(registration),
            reservations: Some(reservations),
        })
    }

    /// Called once after readiness, before exposing this round to gateways.
    /// Heartbeats and address re-registration must never reset case counts.
    pub(super) async fn initialize_round(&self, policy: Option<&ApiPolicy>) -> Result<()> {
        let Some((redis, prefix)) = &self.startup else {
            return Ok(());
        };
        let json = policy.map_or(r#"{"includes":[],"excludes":[]}"#, |policy| {
            policy.json.as_str()
        });
        let mut command = cmd("SET");
        command.arg(format!("{prefix}:api-policy")).arg(json);
        let reply: Value = redis
            .command(command)
            .await
            .context("failed to publish gateway API policy")?;
        ensure!(
            matches!(reply, Value::Okay)
                || matches!(reply, Value::SimpleString(ref value) if value == "OK"),
            "unexpected gateway API policy publication response"
        );
        let mut command = cmd("DEL");
        command.arg(format!("{prefix}:api-counts"));
        let deleted: i64 = redis
            .command(command)
            .await
            .context("failed to reset gateway API counts")?;
        ensure!(
            (0..=1).contains(&deleted),
            "unexpected gateway API count reset response"
        );
        info!(
            policy_configured = policy.is_some(),
            "gateway recording round initialized; case counts reset"
        );
        Ok(())
    }

    /// Discovery is best-effort and never changes request or Source ownership.
    pub(super) async fn refresh_registration(&self) {
        let Some(registration) = &self.registration else {
            return;
        };
        match registration.renew().await {
            Ok(true) => {}
            Ok(false) => match registration.register().await {
                Ok(true) => info!("recorder address registered"),
                Ok(false) => {
                    warn!("recorder address belongs to another owner; registration will retry")
                }
                Err(error) => warn!(%error, "recorder address registration failed; will retry"),
            },
            Err(error) => warn!(%error, "recorder address renewal failed; will retry"),
        }
    }

    pub(super) async fn unregister(&self) -> Result<()> {
        if let Some(registration) = &self.registration {
            registration.unregister().await?;
        }
        Ok(())
    }
}

async fn connect_redis(input: &str) -> Result<RedisService> {
    let parsed =
        url::Url::parse(input).map_err(|_| anyhow::anyhow!("invalid coordination Redis URL"))?;
    ensure!(
        parsed.scheme() == "redis"
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && (parsed.username().is_empty() || parsed.username() == "default"),
        "Redis requires redis:// with password-only/default-user authentication and no query"
    );
    let host = parsed.host_str().context("Redis URL requires a host")?;
    let db = parsed.path().trim_start_matches('/');
    let db = if db.is_empty() {
        0
    } else {
        db.parse::<u32>()
            .context("Redis DB must be a nonnegative integer")?
    };
    let password = parsed
        .password()
        .map(|value| {
            url::form_urlencoded::parse(format!("value={}", value.replace('+', "%2B")).as_bytes())
                .next()
                .map(|(_, value)| value.into_owned())
                .context("invalid Redis password")
        })
        .transpose()?;
    let endpoint = format!("{host}:{}:{db}", parsed.port().unwrap_or(6379));
    Ok(RedisService::single_with_options(
        endpoint,
        RedisServiceOptions::default()
            .with_password(password)
            .with_timeout(Duration::from_millis(200)),
    )
    .await?)
}
