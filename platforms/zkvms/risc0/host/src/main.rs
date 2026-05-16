mod pp2_showver;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    if let Err(error) = pp2_showver::run_from_env() {
        tracing::error!("host execution failed: {error:?}");
        std::process::exit(1);
    }
}
