fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = vc_pqc::run_pp2_aurora_cli(std::env::args())?;
    Ok(())
}
