use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::compression::CompressionKind;
use crate::core::{format_bytes, format_unix_time_utc, short_hex};
use crate::errors::{Result, SneakError};
use crate::extract::{ExtractOptions, ExtractPolicy, OverwritePolicy};
use crate::identity::{self, IdentityStore, ReplayStatus};
use crate::log::LogRecordV1;
use crate::medium::{self, MediumState};
use crate::parcel::manifest::{FileEntryV1, ManifestV1, MetadataProfile};
use crate::parcel::{CreateOptions, ParcelSummary, VerificationReport, VerifyMode};

#[derive(Debug, Parser)]
#[command(name = "sneakers")]
#[command(about = "Offline-first secure parcel transfer over physical media")]
#[command(after_help = "Quick start:
  sneakers identity create \"Laptop A\"
  sneakers parcel create ./data -o data.sparcel
  sneakers parcel inspect data.sparcel --mode normal
  sneakers parcel extract data.sparcel ./out

Passphrases can be supplied with --passphrase or SNEAKERS_PASSPHRASE.
Use `sneakers <command> --help` for command-specific examples.")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Create, list, and export local signing identities",
        visible_alias = "id"
    )]
    Identity(IdentityCommand),
    #[command(about = "Manage trusted public signing keys")]
    Trust(TrustCommand),
    #[command(
        about = "Create, inspect, verify, and extract .sparcel files",
        visible_alias = "p"
    )]
    Parcel(ParcelCommand),
    #[command(
        about = "Work with image, raw, or filesystem fallback media",
        visible_alias = "m"
    )]
    Medium(MediumCommand),
    #[command(about = "List encrypted manifest contents after verification")]
    Manifest(ManifestCommand),
    #[command(about = "Show parcel audit/log summary")]
    Log(LogCommand),
}

#[derive(Debug, Args)]
struct IdentityCommand {
    #[command(subcommand)]
    command: IdentitySubcommand,
}

#[derive(Debug, Subcommand)]
enum IdentitySubcommand {
    #[command(about = "Create a local Ed25519 signing identity")]
    Create {
        #[arg(help = "Human-readable local identity name, for example \"Laptop A\"")]
        name: String,
        #[arg(
            long,
            help = "Replace an existing identity with the same sanitized name"
        )]
        force: bool,
    },
    #[command(about = "List local identities and fingerprints")]
    List,
    #[command(about = "Export a public identity file for another machine to trust")]
    Export {
        #[arg(help = "Identity name to export")]
        name: String,
        #[arg(short, long, help = "Output .msgpack public identity file")]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct TrustCommand {
    #[command(subcommand)]
    command: TrustSubcommand,
}

#[derive(Debug, Subcommand)]
enum TrustSubcommand {
    #[command(about = "Trust a public identity exported by `identity export`")]
    Add {
        #[arg(help = "Public identity file to trust")]
        pubkey_file: PathBuf,
    },
    #[command(about = "List trusted public signing keys")]
    List,
}

#[derive(Debug, Args)]
struct ParcelCommand {
    #[command(subcommand)]
    command: ParcelSubcommand,
}

#[derive(Debug, Subcommand)]
enum ParcelSubcommand {
    #[command(about = "Pack a file or directory into an encrypted, signed parcel")]
    Create(ParcelCreateArgs),
    #[command(about = "Inspect a parcel and run normal chunk verification by default")]
    Inspect(ParcelInspectArgs),
    #[command(about = "Verify a parcel with quick, normal, or full checks")]
    Verify(ParcelVerifyArgs),
    #[command(about = "Extract fully valid files from a parcel")]
    Extract(ParcelExtractArgs),
}

#[derive(Debug, Args)]
struct ParcelCreateArgs {
    #[arg(help = "Source file or directory to pack")]
    src: PathBuf,
    #[arg(short, long, help = "Output .sparcel file")]
    output: PathBuf,
    #[arg(
        long,
        help = "Signing identity name; defaults to the first local identity"
    )]
    identity: Option<String>,
    #[arg(
        long,
        help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
    )]
    passphrase: Option<String>,
    #[arg(
        long,
        value_enum,
        default_value = "zstd",
        help = "Compression algorithm"
    )]
    compression: CompressionArg,
    #[arg(long, default_value_t = 6, help = "zstd compression level")]
    compression_level: i32,
    #[arg(
        long,
        help = "zstd worker count; 0 or omitted keeps zstd single-threaded"
    )]
    compression_threads: Option<usize>,
    #[arg(long, default_value_t = crate::parcel::DEFAULT_CHUNK_SIZE, help = "Plaintext chunk size in bytes")]
    chunk_size: usize,
    #[arg(
        long,
        value_enum,
        default_value = "unix-basic",
        help = "Stored metadata profile"
    )]
    metadata_profile: MetadataProfileArg,
}

#[derive(Debug, Args)]
struct ParcelInspectArgs {
    #[arg(help = "Parcel file to inspect")]
    parcel: PathBuf,
    #[arg(
        long,
        help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
    )]
    passphrase: Option<String>,
    #[arg(
        long,
        default_value = "normal",
        help = "Check mode: quick, normal, or full"
    )]
    mode: String,
}

#[derive(Debug, Args)]
struct ParcelVerifyArgs {
    #[arg(help = "Parcel file to verify")]
    parcel: PathBuf,
    #[arg(
        long,
        help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
    )]
    passphrase: Option<String>,
    #[arg(
        long,
        default_value = "normal",
        help = "Check mode: quick, normal, or full"
    )]
    mode: String,
}

#[derive(Debug, Args)]
struct ParcelExtractArgs {
    #[arg(help = "Parcel file to extract")]
    parcel: PathBuf,
    #[arg(help = "Destination directory")]
    dst: PathBuf,
    #[arg(
        long,
        help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
    )]
    passphrase: Option<String>,
    #[arg(
        long,
        default_value = "safe",
        help = "Extract policy: strict, safe, or partial"
    )]
    policy: String,
    #[arg(
        long,
        default_value = "rename-conflicts",
        help = "Overwrite policy: never, overwrite, or rename-conflicts"
    )]
    overwrite: String,
}

#[derive(Debug, Args)]
struct MediumCommand {
    #[command(subcommand)]
    command: MediumSubcommand,
}

#[derive(Debug, Subcommand)]
enum MediumSubcommand {
    #[command(about = "List raw block devices visible on this Linux host")]
    List,
    #[command(about = "Probe a parcel file, raw device, or filesystem fallback directory")]
    Inspect {
        #[arg(help = "Device path, .sparcel file, or filesystem fallback directory")]
        target: PathBuf,
    },
    #[command(about = "Write a parcel to an image, raw device, or filesystem fallback directory")]
    Burn {
        #[arg(help = "Source .sparcel file")]
        parcel: PathBuf,
        #[arg(help = "Target device path, image file, or filesystem fallback directory")]
        target: PathBuf,
        #[arg(
            long,
            help = "Skip interactive confirmation for raw-device/reclaim operations"
        )]
        yes: bool,
    },
    #[command(about = "Verify the parcel stored on a medium")]
    Verify {
        #[arg(help = "Device path, .sparcel file, or filesystem fallback directory")]
        target: PathBuf,
        #[arg(
            long,
            help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
        )]
        passphrase: Option<String>,
        #[arg(
            long,
            default_value = "normal",
            help = "Check mode: quick, normal, or full"
        )]
        mode: String,
    },
    #[command(about = "Extract the parcel stored on a medium")]
    Extract {
        #[arg(help = "Device path, .sparcel file, or filesystem fallback directory")]
        target: PathBuf,
        #[arg(help = "Destination directory")]
        dst: PathBuf,
        #[arg(
            long,
            help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
        )]
        passphrase: Option<String>,
        #[arg(
            long,
            default_value = "safe",
            help = "Extract policy: strict, safe, or partial"
        )]
        policy: String,
        #[arg(
            long,
            default_value = "rename-conflicts",
            help = "Overwrite policy: never, overwrite, or rename-conflicts"
        )]
        overwrite: String,
    },
    #[command(about = "Mark a medium available by removing/wiping Sneakers service areas")]
    Reclaim {
        #[arg(help = "Device path, .sparcel file, or filesystem fallback directory")]
        target: PathBuf,
        #[arg(long, help = "Skip interactive confirmation")]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct ManifestCommand {
    #[command(subcommand)]
    command: ManifestSubcommand,
}

#[derive(Debug, Subcommand)]
enum ManifestSubcommand {
    #[command(about = "List files/directories recorded in the encrypted manifest")]
    #[command(after_help = "Examples:
  sneakers manifest list /dev/sdc --tree
  sneakers manifest list /dev/sdc --limit 50
  sneakers manifest list /dev/sdc --sort size
  sneakers manifest list /dev/sdc --summary
  sneakers manifest list /dev/sdc --filter \"*.rlib\"")]
    List {
        #[arg(help = "Parcel file or medium path")]
        parcel_or_medium: PathBuf,
        #[arg(
            long,
            help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
        )]
        passphrase: Option<String>,
        #[arg(
            long,
            help = "Print a compact directory tree instead of a flat file list"
        )]
        tree: bool,
        #[arg(long, help = "Limit the number of files printed in the list/tree")]
        limit: Option<usize>,
        #[arg(
            long,
            value_enum,
            default_value = "path",
            help = "Sort file list by path, size, or extension"
        )]
        sort: ManifestSortArg,
        #[arg(
            long,
            help = "Print only the manifest summary, largest files, and extension totals"
        )]
        summary: bool,
        #[arg(long, help = "Filter files with a simple glob, for example \"*.rlib\"")]
        filter: Option<String>,
    },
}

#[derive(Debug, Args)]
struct LogCommand {
    #[command(subcommand)]
    command: LogSubcommand,
}

#[derive(Debug, Subcommand)]
enum LogSubcommand {
    #[command(about = "Show a human-readable parcel audit and integrity report")]
    #[command(after_help = "Examples:
  sneakers log show /dev/sdc
  sneakers log show /dev/sdc --mode normal
  sneakers log show data.sparcel --mode full")]
    Show {
        #[arg(help = "Parcel file or medium path")]
        parcel_or_medium: PathBuf,
        #[arg(
            long,
            help = "Parcel passphrase; otherwise prompts or reads SNEAKERS_PASSPHRASE"
        )]
        passphrase: Option<String>,
        #[arg(
            long,
            default_value = "quick",
            help = "Verification mode for the log report: quick, normal, or full"
        )]
        mode: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompressionArg {
    None,
    Zstd,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MetadataProfileArg {
    Portable,
    UnixBasic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ManifestSortArg {
    Path,
    Size,
    Extension,
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    dispatch(cli).map_err(anyhow::Error::from)
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Identity(command) => identity_command(command),
        Command::Trust(command) => trust_command(command),
        Command::Parcel(command) => parcel_command(command),
        Command::Medium(command) => medium_command(command),
        Command::Manifest(command) => manifest_command(command),
        Command::Log(command) => log_command(command),
    }
}

fn identity_command(command: IdentityCommand) -> Result<()> {
    let store = IdentityStore::open()?;
    match command.command {
        IdentitySubcommand::Create { name, force } => {
            let identity = store.create(&name, force)?;
            println!("Identity created: {}", identity.name);
            println!("Fingerprint: {}", identity.fingerprint());
        }
        IdentitySubcommand::List => {
            let identities = store.list()?;
            if identities.is_empty() {
                println!("No identities found");
            }
            for identity in identities {
                println!("{}  {}", identity.fingerprint(), identity.name);
            }
        }
        IdentitySubcommand::Export { name, output } => {
            let public = store.export_public(&name)?;
            if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, crate::parcel::to_msgpack(&public)?)?;
            println!("Exported {} to {}", public.name, output.display());
            println!("Fingerprint: {}", public.fingerprint);
        }
    }
    Ok(())
}

fn trust_command(command: TrustCommand) -> Result<()> {
    let store = IdentityStore::open()?;
    match command.command {
        TrustSubcommand::Add { pubkey_file } => {
            let trusted = store.import_trust_file(&pubkey_file)?;
            println!("Trusted: {}  {}", trusted.fingerprint, trusted.name);
        }
        TrustSubcommand::List => {
            let trusted = store.load_trusted_keys()?;
            if trusted.is_empty() {
                println!("No trusted keys found");
            }
            for key in trusted {
                println!("{}  {}  {}", key.fingerprint, key.trust_level, key.name);
            }
        }
    }
    Ok(())
}

fn parcel_command(command: ParcelCommand) -> Result<()> {
    match command.command {
        ParcelSubcommand::Create(args) => {
            let passphrase = read_new_passphrase(args.passphrase)?;
            let identity_name = args.identity.clone();
            crate::parcel::create(CreateOptions {
                src: args.src,
                output: args.output.clone(),
                passphrase,
                identity_name: args.identity,
                compression: args.compression.into(),
                compression_level: args.compression_level,
                compression_threads: args.compression_threads,
                chunk_size: args.chunk_size,
                metadata_profile: args.metadata_profile.into(),
            })?;
            println!("Parcel created: {}", args.output.display());
            if let Some(identity_name) = identity_name {
                println!("Signed by: {identity_name}");
            } else {
                println!("Signed by: default local identity");
            }
        }
        ParcelSubcommand::Inspect(args) => {
            let passphrase = read_passphrase(args.passphrase)?;
            let mode = VerifyMode::from_str(&args.mode)?;
            let report = crate::verify::verify(&args.parcel, &passphrase, mode)?;
            print_verification(&report)?;
        }
        ParcelSubcommand::Verify(args) => {
            let passphrase = read_passphrase(args.passphrase)?;
            let mode = VerifyMode::from_str(&args.mode)?;
            let report = crate::verify::verify(&args.parcel, &passphrase, mode)?;
            print_verification(&report)?;
            identity::record_seen(
                &report.summary.header.parcel_id,
                &report.summary.footer.parcel_fingerprint,
                &report.summary.header.created_by_pubkey,
                false,
                None,
            )?;
        }
        ParcelSubcommand::Extract(args) => {
            let passphrase = read_passphrase(args.passphrase)?;
            let report = crate::extract::extract(ExtractOptions {
                parcel_path: args.parcel,
                dst: args.dst,
                passphrase,
                policy: ExtractPolicy::from_str(&args.policy)?,
                overwrite: OverwritePolicy::from_str(&args.overwrite)?,
            })?;
            print_extract_report(&report);
        }
    }
    Ok(())
}

fn medium_command(command: MediumCommand) -> Result<()> {
    match command.command {
        MediumSubcommand::List => {
            for info in medium::list_raw_devices()? {
                print_medium_one_line(&info);
            }
        }
        MediumSubcommand::Inspect { target } => {
            let info = medium::inspect(&target)?;
            print_medium(&info);
        }
        MediumSubcommand::Burn {
            parcel,
            target,
            yes,
        } => {
            confirm_dangerous_medium_write(&target, yes)?;
            let info = medium::burn(&parcel, &target)?;
            print_medium(&info);
        }
        MediumSubcommand::Verify {
            target,
            passphrase,
            mode,
        } => {
            let parcel_path = parcel_path_for_medium(&target);
            let passphrase = read_passphrase(passphrase)?;
            let report =
                crate::verify::verify(&parcel_path, &passphrase, VerifyMode::from_str(&mode)?)?;
            print_verification(&report)?;
            identity::record_seen(
                &report.summary.header.parcel_id,
                &report.summary.footer.parcel_fingerprint,
                &report.summary.header.created_by_pubkey,
                false,
                Some(medium_fingerprint(&target)?),
            )?;
        }
        MediumSubcommand::Extract {
            target,
            dst,
            passphrase,
            policy,
            overwrite,
        } => {
            let parcel_path = parcel_path_for_medium(&target);
            let passphrase = read_passphrase(passphrase)?;
            let report = crate::extract::extract(ExtractOptions {
                parcel_path,
                dst,
                passphrase,
                policy: ExtractPolicy::from_str(&policy)?,
                overwrite: OverwritePolicy::from_str(&overwrite)?,
            })?;
            print_extract_report(&report);
        }
        MediumSubcommand::Reclaim { target, yes } => {
            confirm_reclaim(&target, yes)?;
            let info = medium::reclaim(&target)?;
            print_medium(&info);
        }
    }
    Ok(())
}

fn manifest_command(command: ManifestCommand) -> Result<()> {
    match command.command {
        ManifestSubcommand::List {
            parcel_or_medium,
            passphrase,
            tree,
            limit,
            sort,
            summary,
            filter,
        } => {
            let passphrase = read_passphrase(passphrase)?;
            let report = crate::verify::verify(
                &parcel_path_for_medium(&parcel_or_medium),
                &passphrase,
                VerifyMode::Quick,
            )?;
            print_manifest_list(
                &report.summary,
                ManifestListOptions {
                    tree,
                    limit,
                    sort,
                    summary_only: summary,
                    filter,
                },
            )?;
        }
    }
    Ok(())
}

fn log_command(command: LogCommand) -> Result<()> {
    match command.command {
        LogSubcommand::Show {
            parcel_or_medium,
            passphrase,
            mode,
        } => {
            let passphrase = read_passphrase(passphrase)?;
            let parcel_path = parcel_path_for_medium(&parcel_or_medium);
            let mode = VerifyMode::from_str(&mode)?;
            let report = crate::verify::verify(&parcel_path, &passphrase, mode)?;
            let log_record = crate::parcel::read_log_record(&parcel_path, &report.summary)?;
            print_log_report(&parcel_or_medium, &report, &log_record)?;
        }
    }
    Ok(())
}

fn read_passphrase(value: Option<String>) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    if let Ok(value) = std::env::var("SNEAKERS_PASSPHRASE") {
        return Ok(value);
    }
    rpassword::prompt_password("Passphrase: ")
        .map_err(|err| SneakError::other(format!("failed to read passphrase: {err}")))
}

fn read_new_passphrase(value: Option<String>) -> Result<String> {
    if value.is_some() || std::env::var("SNEAKERS_PASSPHRASE").is_ok() {
        return read_passphrase(value);
    }

    let first = rpassword::prompt_password("Passphrase: ")
        .map_err(|err| SneakError::other(format!("failed to read passphrase: {err}")))?;
    let second = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|err| SneakError::other(format!("failed to read passphrase: {err}")))?;
    if first != second {
        return Err(SneakError::other("passphrases do not match"));
    }
    Ok(first)
}

#[derive(Debug)]
struct ManifestListOptions {
    tree: bool,
    limit: Option<usize>,
    sort: ManifestSortArg,
    summary_only: bool,
    filter: Option<String>,
}

fn print_manifest_list(summary: &ParcelSummary, options: ManifestListOptions) -> Result<()> {
    let manifest = &summary.manifest;
    let mut files = manifest
        .files
        .iter()
        .filter(|file| {
            options
                .filter
                .as_deref()
                .map(|filter| file_matches_filter(&file.path, filter))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    sort_manifest_files(&mut files, options.sort);

    print_manifest_summary(manifest, &files, options.filter.as_deref());

    if options.summary_only {
        return Ok(());
    }

    println!();
    if options.tree {
        print_manifest_tree(manifest, &files, options.limit);
    } else {
        print_manifest_flat_files(&files, options.limit, options.sort);
    }

    Ok(())
}

fn print_manifest_summary(manifest: &ManifestV1, files: &[&FileEntryV1], filter: Option<&str>) {
    let selected_size = files.iter().map(|file| file.size).sum::<u64>();
    let selected_file_ids = files
        .iter()
        .map(|file| file.file_id)
        .collect::<BTreeSet<_>>();
    let selected_stored_size = manifest
        .chunks
        .iter()
        .filter(|chunk| selected_file_ids.contains(&chunk.file_id))
        .map(|chunk| chunk.stored_size)
        .sum::<u64>();
    let file_count = if let Some(filter) = filter {
        format!(
            "{} / {} (filter {filter:?})",
            files.len(),
            manifest.files.len()
        )
    } else {
        manifest.files.len().to_string()
    };

    println!("Manifest summary");
    println!("Files: {file_count}");
    println!("Directories: {}", manifest.directories.len());
    println!("Symlinks: {}", manifest.symlinks.len());
    println!("Total unpacked: {}", format_bytes(selected_size));
    println!("Total packed: {}", format_bytes(selected_stored_size));
    println!("Compression: {}", manifest.compression.as_str());

    println!();
    println!("Largest files:");
    let mut largest = files.to_vec();
    largest.sort_by(|left, right| {
        right
            .size
            .cmp(&left.size)
            .then_with(|| left.path.cmp(&right.path))
    });
    if largest.is_empty() {
        println!("  (none)");
    }
    for file in largest.into_iter().take(5) {
        println!("  {:>10}  {}", format_bytes(file.size), file.path);
    }

    println!();
    println!("Extensions:");
    let mut extensions = BTreeMap::<String, (usize, u64)>::new();
    for file in files {
        let extension = extension_label(&file.path);
        let entry = extensions.entry(extension).or_default();
        entry.0 += 1;
        entry.1 += file.size;
    }
    let mut extensions = extensions.into_iter().collect::<Vec<_>>();
    extensions.sort_by(
        |(left_ext, (left_count, left_size)), (right_ext, (right_count, right_size))| {
            right_size
                .cmp(left_size)
                .then_with(|| right_count.cmp(left_count))
                .then_with(|| left_ext.cmp(right_ext))
        },
    );
    if extensions.is_empty() {
        println!("  (none)");
    }
    for (extension, (count, size)) in extensions.into_iter().take(10) {
        println!(
            "  {:<10} {:>6}  {}",
            extension,
            plural_count(count, "file"),
            format_bytes(size)
        );
    }
}

fn print_manifest_flat_files(files: &[&FileEntryV1], limit: Option<usize>, sort: ManifestSortArg) {
    println!(
        "Files (sort: {}, limit: {}):",
        manifest_sort_label(sort),
        limit
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "all".to_string())
    );

    if files.is_empty() {
        println!("  (none)");
        return;
    }

    let limit = limit.unwrap_or(files.len());
    for file in files.iter().take(limit) {
        println!("  {:>10}  {}", format_bytes(file.size), file.path);
    }
    if files.len() > limit {
        println!("  ... {} more", files.len() - limit);
    }
}

fn print_manifest_tree(manifest: &ManifestV1, files: &[&FileEntryV1], limit: Option<usize>) {
    println!(
        "Tree (limit: {}):",
        limit
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "all".to_string())
    );

    let limit = limit.unwrap_or(files.len());
    let visible_files = files.iter().take(limit).copied().collect::<Vec<_>>();
    if visible_files.is_empty() && manifest.directories.is_empty() {
        println!("  (empty)");
        return;
    }

    let mut dirs = BTreeSet::<String>::new();
    if files.len() == manifest.files.len() {
        for dir in &manifest.directories {
            dirs.insert(dir.path.clone());
        }
    }
    for file in &visible_files {
        add_parent_dirs(&mut dirs, &file.path);
    }

    let mut entries = Vec::<TreeEntry>::new();
    for dir in dirs {
        entries.push(TreeEntry {
            path: dir,
            kind: TreeEntryKind::Directory,
        });
    }
    for file in visible_files {
        entries.push(TreeEntry {
            path: file.path.clone(),
            kind: TreeEntryKind::File(file.size),
        });
    }
    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.order().cmp(&right.kind.order()))
    });

    for entry in entries {
        let depth = entry.path.matches('/').count();
        let indent = "  ".repeat(depth + 1);
        let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
        match entry.kind {
            TreeEntryKind::Directory => println!("{indent}{name}/"),
            TreeEntryKind::File(size) => println!("{indent}{name}  {}", format_bytes(size)),
        }
    }
    if files.len() > limit {
        println!("  ... {} more files", files.len() - limit);
    }
}

#[derive(Debug)]
struct TreeEntry {
    path: String,
    kind: TreeEntryKind,
}

#[derive(Debug)]
enum TreeEntryKind {
    Directory,
    File(u64),
}

impl TreeEntryKind {
    fn order(&self) -> u8 {
        match self {
            Self::Directory => 0,
            Self::File(_) => 1,
        }
    }
}

fn sort_manifest_files(files: &mut [&FileEntryV1], sort: ManifestSortArg) {
    match sort {
        ManifestSortArg::Path => files.sort_by(|left, right| left.path.cmp(&right.path)),
        ManifestSortArg::Size => {
            files.sort_by(|left, right| {
                right
                    .size
                    .cmp(&left.size)
                    .then_with(|| left.path.cmp(&right.path))
            });
        }
        ManifestSortArg::Extension => {
            files.sort_by(|left, right| {
                extension_label(&left.path)
                    .cmp(&extension_label(&right.path))
                    .then_with(|| left.path.cmp(&right.path))
            });
        }
    }
}

fn manifest_sort_label(sort: ManifestSortArg) -> &'static str {
    match sort {
        ManifestSortArg::Path => "path",
        ManifestSortArg::Size => "size",
        ManifestSortArg::Extension => "extension",
    }
}

fn extension_label(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| format!(".{extension}"))
        .unwrap_or_else(|| ".".to_string())
}

fn plural_count(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

fn add_parent_dirs(dirs: &mut BTreeSet<String>, path: &str) {
    let mut current = String::new();
    for part in path
        .split('/')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .skip(1)
        .rev()
    {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(part);
        dirs.insert(current.clone());
    }
}

fn file_matches_filter(path: &str, filter: &str) -> bool {
    wildcard_matches(filter, path)
        || Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| wildcard_matches(filter, name))
            .unwrap_or(false)
}

fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let text = text.chars().collect::<Vec<_>>();
    let mut dp = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;

    for i in 1..=pattern.len() {
        if pattern[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=pattern.len() {
        for j in 1..=text.len() {
            dp[i][j] = match pattern[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                ch => dp[i - 1][j - 1] && ch == text[j - 1],
            };
        }
    }

    dp[pattern.len()][text.len()]
}

fn print_verification(report: &VerificationReport) -> Result<()> {
    let damaged = report.damaged_chunks.len();
    if damaged > 0 {
        println!("Parcel: damaged");
    } else if report.mode == VerifyMode::Quick {
        println!("Parcel: structurally valid");
    } else {
        println!("Parcel: valid");
    }
    println!("Verification mode: {}", report.mode.as_str());
    println!(
        "Fingerprint: {}",
        hex::encode(&report.summary.footer.parcel_fingerprint)
    );
    println!("Files: {}", report.summary.manifest.files.len());
    println!(
        "Packed size: {}",
        format_bytes(report.summary.manifest.stored_total_size)
    );
    println!(
        "Unpacked size: {}",
        format_bytes(report.summary.manifest.plaintext_total_size)
    );
    println!(
        "Compression: {}",
        report.summary.manifest.compression.as_str()
    );
    println!(
        "Metadata profile: {}",
        report.summary.manifest.metadata_profile.as_str()
    );
    let key_slot_kinds = report
        .summary
        .key_slots
        .iter()
        .map(|slot| slot.kind())
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Key slots: {}{}",
        report.summary.key_slots.len(),
        if key_slot_kinds.is_empty() {
            String::new()
        } else {
            format!(" ({key_slot_kinds})")
        }
    );
    println!(
        "Signatures: valid ({})",
        report.summary.signature_block.records.len()
    );
    if !report.trusted_signers.is_empty() {
        println!("Signed by trusted: {}", report.trusted_signers.join(", "));
    }
    if !report.untrusted_signers.is_empty() {
        println!(
            "Signed by untrusted: {}",
            report
                .untrusted_signers
                .iter()
                .map(|key| key.chars().take(16).collect::<String>())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if report.chunks_checked == 0 {
        println!("Chunk status: unchecked (use --mode normal or --mode full)");
    } else {
        println!("Damaged chunks: {}", damaged);
        println!(
            "Valid chunks: {}/{}",
            report.chunks_checked - damaged,
            report.chunks_checked
        );
        for chunk in report.damaged_chunks.iter().take(5) {
            let detail = chunk.error.as_deref().unwrap_or("unknown chunk error");
            println!("Damaged chunk {}: {}", chunk.chunk_id, detail);
        }
    }
    println!(
        "Replay status: {}",
        replay_status_text(identity::classify_seen(
            &report.summary.footer.parcel_fingerprint
        )?)
    );
    Ok(())
}

fn print_log_report(source: &Path, report: &VerificationReport, log: &LogRecordV1) -> Result<()> {
    let summary = &report.summary;
    let trusted = trusted_key_names()?;

    println!("Parcel log");
    println!("Source: {}", source.display());
    println!("Status: {}", parcel_status(report));
    println!("Verification mode: {}", report.mode.as_str());
    println!();

    println!("Parcel");
    println!("  ID: {}", hex::encode(summary.header.parcel_id));
    println!(
        "  Fingerprint: {}",
        hex::encode(&summary.footer.parcel_fingerprint)
    );
    println!(
        "  Created: {}",
        format_unix_time_utc(summary.footer.created_at)
    );
    println!("  Files: {}", summary.manifest.files.len());
    println!("  Directories: {}", summary.manifest.directories.len());
    println!("  Symlinks: {}", summary.manifest.symlinks.len());
    println!(
        "  Unpacked: {}",
        format_bytes(summary.manifest.plaintext_total_size)
    );
    println!(
        "  Packed chunks: {}",
        format_bytes(summary.manifest.stored_total_size)
    );
    println!("  Compression: {}", summary.manifest.compression.as_str());
    println!();

    println!("Integrity");
    println!("  Frames: {}", summary.footer.frame_count);
    println!("  Chunks: {}", summary.manifest.chunks.len());
    println!("  Manifest: decrypted and hash-verified");
    println!(
        "  Signatures: valid ({})",
        summary.signature_block.records.len()
    );
    if report.chunks_checked == 0 {
        println!("  Chunk payloads: unchecked (use --mode normal or --mode full)");
    } else {
        println!(
            "  Chunk payloads: {}/{} valid",
            report.chunks_checked - report.damaged_chunks.len(),
            report.chunks_checked
        );
        if !report.damaged_chunks.is_empty() {
            println!("  Damaged chunks: {}", report.damaged_chunks.len());
        }
    }
    println!();

    println!("Signers");
    for record in &summary.signature_block.records {
        let label = public_key_label(&record.signer_pubkey, &trusted);
        println!(
            "  valid  {:<28} pubkey {}",
            label,
            short_hex(&record.signer_pubkey)
        );
    }
    println!();

    println!("Events");
    let timestamp = log
        .timestamp_claim
        .map(format_unix_time_utc)
        .unwrap_or_else(|| "no timestamp claim".to_string());
    println!("  #{}  {}  {}", log.seq, log.event_type.as_str(), timestamp);
    println!(
        "      Actor: {}",
        public_key_label(&log.actor_pubkey, &trusted)
    );
    println!("      Parcel: {}", short_hex(&log.parcel_fingerprint));
    println!(
        "      Log record signature: {}",
        if log.signature.is_some() {
            "present"
        } else {
            "not present (MVP log record)"
        }
    );
    println!();

    println!(
        "Replay: {}",
        replay_status_text(identity::classify_seen(&summary.footer.parcel_fingerprint)?)
    );

    Ok(())
}

fn parcel_status(report: &VerificationReport) -> &'static str {
    if !report.damaged_chunks.is_empty() {
        "damaged"
    } else if report.mode == VerifyMode::Quick {
        "structurally valid"
    } else {
        "valid"
    }
}

fn trusted_key_names() -> Result<BTreeMap<Vec<u8>, String>> {
    Ok(IdentityStore::open()?
        .load_trusted_keys()?
        .into_iter()
        .map(|trusted| (trusted.pubkey, trusted.name))
        .collect())
}

fn public_key_label(pubkey: &[u8], trusted: &BTreeMap<Vec<u8>, String>) -> String {
    trusted
        .get(pubkey)
        .map(|name| format!("{name} (trusted)"))
        .unwrap_or_else(|| format!("{} (untrusted)", short_hex(pubkey)))
}

fn replay_status_text(status: ReplayStatus) -> &'static str {
    match status {
        ReplayStatus::FirstSeen => "first seen",
        ReplayStatus::SeenBefore { extracted: false } => "seen before",
        ReplayStatus::SeenBefore { extracted: true } => "already extracted",
    }
}

fn print_extract_report(report: &crate::extract::ExtractReport) {
    println!(
        "Files extracted: {}/{}",
        report.files_extracted, report.files_total
    );
    println!("Files skipped: {}", report.files_skipped);
    println!("Damaged chunks: {}", report.damaged_chunks);
}

fn print_medium(info: &crate::medium::MediumInfo) {
    println!("Backend: {}", info.backend);
    println!("Path: {}", info.path.display());
    println!("State: {}", info.state.as_str());
    if let Some(size) = info.size {
        println!("Size: {}", format_bytes(size));
    }
    if let Some(model) = &info.model {
        println!("Model: {}", model);
    }
    if let Some(serial) = &info.serial {
        println!("Serial: {}", serial);
    }
    if !info.partitions.is_empty() {
        println!("Partitions: {}", info.partitions.join(", "));
    }
    if let Some(parcel_id) = &info.parcel_id {
        println!("Parcel ID: {}", hex::encode(parcel_id));
    }
    if let Some(fingerprint) = &info.parcel_fingerprint {
        println!("Fingerprint: {}", hex::encode(fingerprint));
    }
}

fn print_medium_one_line(info: &crate::medium::MediumInfo) {
    let size = info
        .size
        .map(format_bytes)
        .unwrap_or_else(|| "unknown".to_string());
    let model = info.model.as_deref().unwrap_or("-");
    println!(
        "{}  {}  {}  {}",
        info.path.display(),
        size,
        info.state.as_str(),
        model
    );
}

fn parcel_path_for_medium(path: &Path) -> PathBuf {
    if path.is_dir() || path.join(".sneakers").exists() {
        path.join(".sneakers").join("parcel.sparcel")
    } else {
        path.to_path_buf()
    }
}

fn confirm_dangerous_medium_write(target: &Path, yes: bool) -> Result<()> {
    let info = medium::inspect(target)?;
    if info.backend != "raw" {
        return Ok(());
    }
    if yes {
        return Ok(());
    }

    println!("Target device: {}", target.display());
    if let Some(model) = &info.model {
        println!("Model: {}", model);
    }
    if let Some(size) = info.size {
        println!("Size: {}", format_bytes(size));
    }
    if !info.partitions.is_empty() {
        println!("Existing partitions: {}", info.partitions.join(", "));
    }
    println!("This will destroy existing data.");
    let expected = info
        .model
        .as_deref()
        .unwrap_or_else(|| target.to_str().unwrap_or(""));
    print!("Type '{}' to continue: ", expected);
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() != expected {
        return Err(SneakError::other("confirmation did not match"));
    }
    Ok(())
}

fn confirm_reclaim(target: &Path, yes: bool) -> Result<()> {
    let info = medium::inspect(target)?;
    if info.state == MediumState::Available || yes {
        return Ok(());
    }

    print!("Reclaim {}? Type 'reclaim' to continue: ", target.display());
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() != "reclaim" {
        return Err(SneakError::other("confirmation did not match"));
    }
    Ok(())
}

fn medium_fingerprint(path: &Path) -> Result<Vec<u8>> {
    let info = medium::inspect(path)?;
    Ok(crate::crypto::hash::hash_many(&[
        b"sneakers:medium-fingerprint:v1",
        info.path.to_string_lossy().as_bytes(),
    ])
    .to_vec())
}

impl From<CompressionArg> for CompressionKind {
    fn from(value: CompressionArg) -> Self {
        match value {
            CompressionArg::None => Self::None,
            CompressionArg::Zstd => Self::Zstd,
        }
    }
}

impl From<MetadataProfileArg> for MetadataProfile {
    fn from(value: MetadataProfileArg) -> Self {
        match value {
            MetadataProfileArg::Portable => Self::Portable,
            MetadataProfileArg::UnixBasic => Self::UnixBasic,
        }
    }
}
