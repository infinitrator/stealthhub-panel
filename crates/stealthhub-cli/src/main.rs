use clap::{Parser, Subcommand};
use stealthhub_core::{
    mihomo::generate_demo_mihomo_yaml,
    models::{demo_settings, demo_user},
};

#[derive(Parser)]
#[command(name = "stealthhub")]
#[command(about = "StealthHub Panel CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenerateMihomo,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenerateMihomo => {
            let yaml = generate_demo_mihomo_yaml(&demo_settings(), &demo_user())?;
            println!("{yaml}");
        }
    }

    Ok(())
}
