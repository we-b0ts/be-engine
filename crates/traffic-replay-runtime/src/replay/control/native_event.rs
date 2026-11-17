use super::*;
pub use traffic_engine::replay::control::native_event::*;
pub(super) async fn accept<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<RuntimeState<P>>>,
) -> Value {
    let result = async {
        let mut state = state.lock().await;
        let case = request
            .case_id
            .as_deref()
            .context("native event feedback requires case_id")?;
        ensure!(
            state.active_case_id.as_deref() == Some(case)
                && state.finalized_at.is_none()
                && !state.target_session_stopped,
            "native event feedback requires the active live case"
        );
        let native = state.protocols.native_events();
        if request.command == "native_event_begin" && !native.needs_native_events(case) {
            return Ok(serde_json::json!({"ok":true,"enabled":false}));
        }
        let epoch = native
            .request_epoch(case)
            .context("native event feedback requires request admission")?;
        if request.command == "native_event_begin" {
            let capabilities = native.begin(case, epoch);
            return Ok(serde_json::json!({
                "ok":true,
                "enabled":capabilities.enabled,
                "epoch":epoch,
                "events":capabilities.events,
                "input_acks":capabilities.input_acks,
            }));
        }
        let observation = request
            .native_event
            .as_ref()
            .context("native event metadata missing")?;
        ensure!(
            observation.epoch == epoch,
            "native event request epoch changed"
        );
        if request.command == "native_input_ack" {
            ensure!(
                observation.event.is_none()
                    && observation.namespace.is_none()
                    && observation.sid.is_none(),
                "input ACK carries unrelated native metadata"
            );
            let sequence = observation
                .acknowledged
                .context("native input ACK missing")?;
            native.input_acknowledged(case, epoch, sequence)?;
            return Ok(serde_json::json!({"ok":true}));
        }
        ensure!(
            observation.acknowledged.is_none(),
            "native event carries input ACK"
        );
        if request.command == "native_connected" {
            ensure!(
                observation.event.is_none(),
                "native namespace observation carries an event"
            );
            let namespace = observation
                .namespace
                .as_deref()
                .context("native namespace missing")?;
            native.connected(case, epoch, namespace, observation.sid.as_deref())?;
            return Ok(serde_json::json!({"ok":true}));
        }
        ensure!(
            observation.namespace.is_none() && observation.sid.is_none(),
            "native event observation carries a namespace boundary"
        );
        let event = observation
            .event
            .as_ref()
            .context("native event metadata missing")?;
        native.observe(case, epoch, event)?;
        Ok::<_, anyhow::Error>(serde_json::json!({"ok":true}))
    }
    .await;
    result.unwrap_or_else(|error| {
        serde_json::json!({"ok":false,"reason":"native_event_rejected","error":error.to_string()})
    })
}
