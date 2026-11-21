//! Borrowed native request facts for request-side ownership and capture.

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum DependencyRequest<'a> {
    Redis {
        target_port: u16,
        command: &'a str,
        args: &'a [Vec<u8>],
    },
    Mysql {
        target_host: Option<&'a str>,
        target_port: Option<u16>,
        database: Option<&'a str>,
        username: Option<&'a str>,
        command: &'a str,
        sql: Option<&'a str>,
    },
}
