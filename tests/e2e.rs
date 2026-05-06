use std::fs;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn parcel_roundtrip_and_fs_fallback_medium() {
    let temp = TempDir::new().expect("tempdir");
    let input = temp.path().join("input");
    fs::create_dir_all(input.join("docs")).expect("input dirs");
    fs::write(input.join("alpha.txt"), b"hello offline world\n").expect("alpha");
    fs::write(
        input.join("docs").join("beta.txt"),
        b"nested payload\nline two\n",
    )
    .expect("beta");

    run(&temp, &["identity", "create", "Laptop A"]);

    let parcel = temp.path().join("data.sparcel");
    run(
        &temp,
        &[
            "parcel",
            "create",
            input.to_str().unwrap(),
            "-o",
            parcel.to_str().unwrap(),
            "--passphrase",
            "testpass",
            "--identity",
            "Laptop A",
            "--compression",
            "zstd",
            "--compression-level",
            "1",
            "--compression-threads",
            "1",
        ],
    );

    run(
        &temp,
        &[
            "parcel",
            "verify",
            parcel.to_str().unwrap(),
            "--passphrase",
            "testpass",
            "--mode",
            "full",
        ],
    );

    let manifest_summary = run_output(
        &temp,
        &[
            "manifest",
            "list",
            parcel.to_str().unwrap(),
            "--passphrase",
            "testpass",
            "--summary",
        ],
    );
    assert!(manifest_summary.contains("Manifest summary"));
    assert!(manifest_summary.contains("Largest files:"));
    assert!(manifest_summary.contains("Extensions:"));

    let manifest_filtered = run_output(
        &temp,
        &[
            "manifest",
            "list",
            parcel.to_str().unwrap(),
            "--passphrase",
            "testpass",
            "--filter",
            "*.txt",
            "--sort",
            "size",
            "--limit",
            "1",
        ],
    );
    assert!(manifest_filtered.contains("Files (sort: size, limit: 1):"));
    assert!(manifest_filtered.contains("... 1 more"));

    let manifest_tree = run_output(
        &temp,
        &[
            "manifest",
            "list",
            parcel.to_str().unwrap(),
            "--passphrase",
            "testpass",
            "--tree",
            "--limit",
            "1",
        ],
    );
    assert!(manifest_tree.contains("Tree (limit: 1):"));

    let log = run_output(
        &temp,
        &[
            "log",
            "show",
            parcel.to_str().unwrap(),
            "--passphrase",
            "testpass",
        ],
    );
    assert!(log.contains("Parcel log"));
    assert!(log.contains("Signers"));
    assert!(log.contains("Events"));
    assert!(log.contains("Laptop A (trusted)"));

    let corrupted = temp.path().join("corrupted.sparcel");
    fs::copy(&parcel, &corrupted).expect("copy corrupted parcel");
    corrupt_first_chunk_payload(&corrupted);
    let inspect = run_output(
        &temp,
        &[
            "parcel",
            "inspect",
            corrupted.to_str().unwrap(),
            "--passphrase",
            "testpass",
        ],
    );
    assert!(
        inspect.contains("Parcel: damaged"),
        "inspect output did not report damage:\n{inspect}"
    );

    let out = temp.path().join("out");
    run(
        &temp,
        &[
            "parcel",
            "extract",
            parcel.to_str().unwrap(),
            out.to_str().unwrap(),
            "--passphrase",
            "testpass",
        ],
    );

    assert_eq!(
        fs::read(input.join("alpha.txt")).unwrap(),
        fs::read(out.join("alpha.txt")).unwrap()
    );
    assert_eq!(
        fs::read(input.join("docs").join("beta.txt")).unwrap(),
        fs::read(out.join("docs").join("beta.txt")).unwrap()
    );

    let usb = temp.path().join("usb");
    fs::create_dir_all(&usb).expect("usb dir");
    run(
        &temp,
        &[
            "medium",
            "burn",
            parcel.to_str().unwrap(),
            usb.to_str().unwrap(),
        ],
    );
    run(
        &temp,
        &[
            "medium",
            "verify",
            usb.to_str().unwrap(),
            "--passphrase",
            "testpass",
            "--mode",
            "full",
        ],
    );
}

fn run(temp: &TempDir, args: &[&str]) {
    let _ = run_output(temp, args);
}

fn run_output(temp: &TempDir, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_sneakers"))
        .args(args)
        .env("SNEAKERS_CONFIG_DIR", temp.path().join("config"))
        .env("SNEAKERS_DATA_DIR", temp.path().join("data"))
        .output()
        .unwrap_or_else(|err| panic!("failed to run sneakers {args:?}: {err}"));

    assert!(
        output.status.success(),
        "sneakers {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout utf8")
}

fn corrupt_first_chunk_payload(path: &std::path::Path) {
    const FRAME_MAGIC: &[u8; 8] = b"SNFRAME\0";
    const FRAME_HEADER_LEN: usize = 92;

    let mut bytes = fs::read(path).expect("read parcel");
    let offset = bytes
        .windows(FRAME_MAGIC.len())
        .enumerate()
        .find_map(|(offset, window)| {
            if window != FRAME_MAGIC {
                return None;
            }
            let frame_type = u16::from_le_bytes([bytes[offset + 8], bytes[offset + 9]]);
            (frame_type == 4).then_some(offset)
        })
        .expect("first chunk frame");
    let payload_byte = offset + FRAME_HEADER_LEN + 8;
    bytes[payload_byte] ^= 0x55;
    fs::write(path, bytes).expect("write corrupted parcel");
}
