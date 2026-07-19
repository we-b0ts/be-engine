use std::process::ExitCode;

mod cli;

#[tokio::main]
async fn main() -> ExitCode {
    match cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            cli::report_error(&error);
            ExitCode::FAILURE
        }
    }
}
