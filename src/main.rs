mod cli;
mod compression;
mod core;
mod crypto;
mod errors;
mod extract;
mod identity;
mod log;
mod medium;
mod parcel;
mod verify;

fn main() -> anyhow::Result<()> {
    cli::run()
}
