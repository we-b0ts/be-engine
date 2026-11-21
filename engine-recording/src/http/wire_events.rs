//! Bind Recorder lifecycle receipts to the native HTTP writer.
use crate::http::termination::{ClientTermination, FlushReceipt};
use crate::recorder::ledger::CaptureReservation;
use traffic_model::{DependencyTermination, trace::OutputKind};
use traffic_protocol_http::wire_events::CaptureWire;

struct Capture(CaptureReservation);
impl CaptureWire for Capture {
    fn wire_terminal(&self) -> bool {
        self.0.wire_terminal()
    }
    fn reserve(&self, kind: OutputKind) -> FlushReceipt {
        let reserved = self.0.prepare_output(kind);
        let failed = self.0.clone();
        FlushReceipt::new(
            move || {
                if let Some(reserved) = reserved {
                    reserved.commit();
                }
            },
            move || failed.delivery_failed(),
        )
    }
    fn failed(&self, termination: Option<DependencyTermination>) {
        if let Some(termination) = termination {
            self.0.output(OutputKind::Terminated { termination });
        } else {
            self.0.delivery_failed();
        }
    }
}

pub fn record(
    response: hyper::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>>,
    capture: Option<CaptureReservation>,
    termination: ClientTermination,
) -> hyper::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>> {
    traffic_protocol_http::wire_events::record(
        response,
        capture.map(|capture| {
            std::sync::Arc::new(Capture(capture)) as std::sync::Arc<dyn CaptureWire>
        }),
        termination,
    )
}
pub use traffic_protocol_http::wire_events::replay;
