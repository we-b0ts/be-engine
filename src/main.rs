use std::process::ExitCode;

mod cli;

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            cli::report_error(&error);
            ExitCode::FAILURE
        }
    }
}
