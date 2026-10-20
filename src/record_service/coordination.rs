//! Optional gateway discovery and reservation coordination, separate from recording.

use super::RecordOptions;
use anyhow::{Context, Result, ensure};
use brz_http_gateway::redis_admission::{RecorderRegistration, RedisAdmissionProvider};
use brz_redis::{RedisService, RedisServiceOptions};
use std::time::Duration;
use tracing::{info, warn};

pub(super) struct Coordination {
    registration: Option<RecorderRegistration<RedisService>>,
    pub(super) reservations: Option<RedisAdmissionProvider<RedisService>>,
}

impl Coordination {
    pub(super) async fn connect(options: &RecordOptions) -> Result<Self> {
        if options.coordination.is_none() {
            return Ok(Self {
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
        )?;
        let reservations =
            RedisAdmissionProvider::new(redis, &options.prefix, options.discovery_key())?;
        Ok(Self {
            registration: Some(registration),
            reservations: Some(reservations),
        })
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
