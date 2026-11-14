//! Application ownership and persistence for native Redis notifications.
mod capture;
mod evidence;
pub(super) use capture::capture;
pub(super) use evidence::record_subscription;
