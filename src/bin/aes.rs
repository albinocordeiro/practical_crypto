use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{info, LevelFilter};
use simplelog::{ColorChoice, Config, TerminalMode, TermLogger};
use practical_crypto::aes::{decrypt_file, decrypt_file_cbc, encrypt_file, encrypt_file_cbc};

#[derive(Parser, Debug, Clone)]
struct Options {
    #[clap(subcommand)]
    command: Command,
    #[clap(short, long)]
    key_file: String,
    #[clap(short, long)]
    input_file: String,
    #[clap(short, long)]
    output_file: String,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Encrypt,
    Decrypt,
}
fn main() -> Result<()> {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto
    )?;
    info!("AES-128 CBC mode");
    let options = Options::parse();
    println!("{:?}", options);
    match options.command {
        Command::Encrypt => {
            encrypt_file_cbc(&options.input_file, &options.output_file, &options.key_file)?;
        }
        Command::Decrypt => {
            decrypt_file_cbc(&options.input_file, &options.output_file, &options.key_file)?;
        }
    }
    info!("Done!");
    Ok(())
}