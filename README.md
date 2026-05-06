# sneakers

Offline-first CLI for moving encrypted, signed parcels through physical media.

The MVP path is:

```text
data -> .sparcel -> medium -> verify/read/extract -> reclaim
```

## Quick Start

Create a local signing identity:

```sh
sneakers identity create "Laptop A"
```

Create an encrypted and signed parcel:

```sh
sneakers parcel create ./data -o data.sparcel
```

Inspect before trusting it. `inspect` defaults to `--mode normal`, so it checks
the manifest, signatures, and encrypted chunk payload hashes:

```sh
sneakers parcel inspect data.sparcel
```

Extract valid files:

```sh
sneakers parcel extract data.sparcel ./out
```

## Verify Modes

```text
quick   header, footer, encrypted manifest, signature transcript
normal  quick + encrypted chunk frame/hash checks
full    normal + decrypt, decompress, plaintext hashes
```

Use `quick` when you only need a fast structural read. Use `normal` before
reclaiming or handing a parcel onward. Use `full` before high-value extraction.

## Manifest Reports

`manifest list` decrypts and verifies the manifest/signature, then prints a
summary before the file list:

```sh
sneakers manifest list /dev/sdc --summary
sneakers manifest list /dev/sdc --tree
sneakers manifest list /dev/sdc --limit 50
sneakers manifest list /dev/sdc --sort size
sneakers manifest list /dev/sdc --filter "*.rlib"
```

The summary includes file/directory counts, total unpacked size, largest files,
and extension totals.

## Logs

```sh
sneakers log show /dev/sdc
sneakers log show /dev/sdc --mode normal
```

The log report shows parcel identity, signer/trust status, integrity status,
manifest counts, and recorded audit events.

## Medium Modes

```sh
sneakers medium inspect /dev/sdb
sneakers medium burn data.sparcel /media/USB
sneakers medium verify /media/USB --mode full
sneakers medium reclaim /media/USB
```

Filesystem fallback writes:

```text
/media/USB/.sneakers/
  parcel.sparcel
  medium.msgpack
  state.lock
```

Raw devices are treated as whole-parcel media. The CLI refuses mounted raw
devices and asks for explicit confirmation before writing.

## Identities And Trust

Parcels are signed. `parcel create` refuses to create an unsigned parcel.

Export a public identity:

```sh
sneakers identity export "Laptop A" -o laptop-a.pub.msgpack
```

Trust it on another machine:

```sh
sneakers trust add laptop-a.pub.msgpack
```

## Passphrases And Paths

By default the CLI prompts for the parcel passphrase. For scripts:

```sh
SNEAKERS_PASSPHRASE="..." sneakers parcel verify data.sparcel
```

Useful environment overrides:

```text
SNEAKERS_CONFIG_DIR  identity and trust store
SNEAKERS_DATA_DIR    seen parcel database
```
