//! Native server-status transitions observed at successful SQL responses.
use crate::{types::SERVER_STATUS_AUTOCOMMIT, values::normalize_sql};

pub fn after_response(
    before: u16,
    sql: &str,
    server_status: Option<u16>,
    source_before: Option<u16>,
) -> u16 {
    let mut status = before;
    update_status(&mut status, sql, server_status);
    if let Some(after) = server_status
        && source_before.is_some_and(|flags| flags & 1 != 0)
        && after & 1 == 0
        && before & SERVER_STATUS_AUTOCOMMIT == after & SERVER_STATUS_AUTOCOMMIT
    {
        status &= !0x2001;
    }
    status
}

fn update_status(status_flags: &mut u16, sql: &str, server_status: Option<u16>) {
    if let Some(enabled) = crate::autocommit::assignment(sql) {
        if enabled {
            // Only OFF -> ON implicitly commits. Repeating ON inside an
            // explicit transaction must preserve that transaction.
            if *status_flags & SERVER_STATUS_AUTOCOMMIT == 0 {
                *status_flags &= !0x2001;
            }
            *status_flags |= SERVER_STATUS_AUTOCOMMIT;
        } else {
            *status_flags &= !SERVER_STATUS_AUTOCOMMIT;
        }
        return;
    }
    match normalize_sql(sql).as_str() {
        "begin" | "start transaction" => *status_flags |= 0x0001,
        "commit" | "rollback" => *status_flags &= !0x2001,
        _ => {
            // Only copy transaction evidence when the source and target
            // use the same autocommit mode. Source implicit read sessions
            // must not turn an autocommitting target connection into one.
            if *status_flags & SERVER_STATUS_AUTOCOMMIT == 0
                && let Some(flags) = server_status
                && flags & SERVER_STATUS_AUTOCOMMIT == 0
            {
                *status_flags = (*status_flags & !0x2001) | (flags & 0x2001);
            }
        }
    }
}
