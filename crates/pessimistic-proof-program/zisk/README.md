# ZisK pessimistic proof program

The ZisK guest of the pessimistic proof (PP).
It reads the same inputs as the SP1 guest,
runs the same `generate_pessimistic_proof` from `pessimistic-proof-core`,
and commits the same `PessimisticProofOutput`.
Certificates that carry an SP1 aggchain proof are verified in software inside the guest.

This guide covers:

1. [Installing ZisK](#1-install-zisk)
2. [Compiling the guest](#2-compile-the-guest)
3. [Obtaining inputs](#3-obtain-inputs)
4. [Running the guest in the emulator](#4-run-in-the-emulator)
5. [Proving and verifying](#5-prove-and-verify)
6. [Proving many inputs and measuring proving time](#6-prove-many-inputs)

All commands run from the repository root.

## 1. Install ZisK

The guest and the host crates use ZisK **1.4.0-alpha**,
which is not released yet:
the workspace follows the `pre-develop-1.4.0-alpha` branch,
and both lockfiles pin commit `fa82851b`.
Use tools built from that same commit.

1. Install the ZisK Rust toolchain, which compiles for the `riscv64ima-zisk-zkvm-elf` target:

   ```bash
   curl https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
   ziskup
   ```

   `ziskup` also installs the released ZisK 1.3.2 binaries into `~/.zisk/bin`.
   Do not use them with this program: they cannot run it (see step 2).

2. Build `cargo-zisk` and `ziskemu` from the pinned commit,
   into their own directory so they do not replace the released ones:

   ```bash
   cargo install --locked --git https://github.com/0xPolygonHermez/zisk.git --rev fa82851b \
       cargo-zisk ziskemu --root ~/.zisk-1.4.0
   export PATH="$HOME/.zisk-1.4.0/bin:$PATH"
   cargo-zisk --version   # cargo-zisk 1.4.0-alpha [cpu] (fa82851 ...)
   ```

On macOS with only the Command Line Tools installed,
the ZisK prover library's Makefile looks for the SDK inside Xcode.
Point it at the installed SDK before building ZisK or any host crate that depends on it:

```bash
export MAKEFLAGS="SDKPATH=$(xcrun --show-sdk-path)"
```

## 2. Compile the guest

```bash
cargo make pp-zisk-elf-build
```

This builds the guest with `cargo-zisk build --release`
and copies the ELF to `crates/pessimistic-proof/elf/riscv64ima-zisk-zkvm-elf`,
the cached copy that the host crates and tests embed.
The task remaps the cargo home and repository paths,
so the ELF, and therefore its vk, does not depend on where they live on your machine.

Without `cargo-make`, run what the task runs:

```bash
cd crates/pessimistic-proof-program/zisk
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}/registry/src=/cargo/registry/src \
--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}/git/checkouts=/cargo/git/checkouts \
--remap-path-prefix=$(cd ../../.. && pwd)=/agglayer"
cargo-zisk build --release
cp target/elf/riscv64ima-zisk-zkvm-elf/release/pessimistic-proof-program-zisk \
    ../../pessimistic-proof/elf/riscv64ima-zisk-zkvm-elf
```

The build is reproducible: rebuilding from the same sources gives the same ELF.

The guest patches two crates with ZisK precompiles, in its own `Cargo.toml` only:
`tiny-keccak` (keccak-f) and `k256` (secp256k1).
The `k256` patch needs ZisK 1.4.0-alpha:
with ZisK 1.3.2 the guest fails to link with `undefined symbol: ecdsa_verify_secp256k1_c`,
and the 1.3.2 emulator rejects its unaligned secp256k1 precompile calls.

## 3. Obtain inputs

An input is the guest's stdin, in the order the guest reads it:

1. the `NetworkState` before the certificate,
2. the `MultiBatchHeader` of the certificate,
3. the SP1 compressed aggchain proof, only if the certificate carries one.

The `zisk-inputs` tool writes them as files for `ziskemu -i` and `cargo-zisk -i`.
Each file is named after its source and saved in `--out-dir` (default `zisk-inputs/`).

### Real certificates from the prover network

The Agglayer proves its pessimistic proofs with SP1 on the Succinct prover network.
The network keeps the input of every proof request,
and the SP1 pessimistic proof program's requests are public
([explorer](https://explorer.reserved.succinct.xyz/program/0x68a7cbbd1bb0e4c029e6015a78d0761d614a1ae97e8789895f48cd7a3343578e)).
`zisk-inputs network` downloads them and converts them to ZisK inputs.
Certificates with an aggchain proof come with their real SP1 compressed proof,
so no local proving is needed.

```bash
# The latest 10 fulfilled requests.
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- network --limit 10

# Only certificates that carry an SP1 aggchain proof.
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- network --limit 50 --kind multisig+aggchain

# 20 certificates of each kind.
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- network --per-kind 20

# Specific requests, by id (as shown in the explorer).
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- \
    network --request-id 0x98cd5602d1c6da623ecf0aad4fcb319074066ea5f221c2c9006d4181259059ee
```

Requests are selected by the vk of the SP1 pessimistic proof program built by this repository.
To fetch the requests of another program version, pass its vk hash with `--vk-hash`,
as the explorer shows it.
Requests with a private stdin, or whose input cannot be downloaded or decoded, are skipped.
`--limit` is the number of input files to write (10 by default, no limit with `--per-kind`):
the tool pages through the requests (`--page-size` per page) until it has that many.

Certificates come in three kinds, by how they are authorized:
`ecdsa` (a legacy ECDSA signature), `multisig`,
and `multisig+aggchain` (a multisig and an SP1 aggchain proof, by far the most expensive to prove).
`--kind` keeps only certificates of that kind, and can be repeated.
`--per-kind N` stops once every kept kind has `N` inputs;
a kind the network has too few certificates of keeps it paging until the end of the listing.
A request is downloaded before its kind is known, so filtering saves disk, not bandwidth.

Inputs already in the output directory count towards `--limit` and `--per-kind`
and are not downloaded again, so an interrupted run resumes where it stopped.

Each line of output describes one file:

```text
zisk-inputs/0x98cd...59ee.bin: multisig+aggchain, network 85, 0 bridge exits, 1 imported bridge exits, 1 SP1 aggchain proof(s), native execution accepted
```

"native execution" runs the pessimistic proof natively on the input.
It does not verify aggchain proofs: only the guest does.

### Sample certificates

`zisk-inputs sample` builds a legacy ECDSA certificate from the test suite's sample data,
like `ppgen` does for SP1:

```bash
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- \
    sample --n-exits 10 --n-imported-exits 10
```

## 4. Run in the emulator

Run the guest on an input with the ZisK emulator.
`-X` prints the step count and the cost breakdown,
and `-o` writes the public outputs to a file:

```bash
ziskemu -e crates/pessimistic-proof/elf/riscv64ima-zisk-zkvm-elf \
    -i zisk-inputs/<input>.bin -X -o output.bin
```

Or with `cargo-zisk`, which also plans the proof and reports its execution time:

```bash
cargo-zisk execute -e crates/pessimistic-proof/elf/riscv64ima-zisk-zkvm-elf \
    -i zisk-inputs/<input>.bin
```

The public outputs are the bincode-encoded `PessimisticProofOutput`,
zero-padded to 256 bytes;
`pessimistic_proof::zisk::decode_output` decodes them.
A certificate the pessimistic proof rejects makes the guest panic,
so the emulator stops with an error.

Typical costs, measured with the 1.4.0-alpha emulator:

| Certificate | Steps | Cost |
|-------------|-------|------|
| Legacy ECDSA, 3 bridge exits and 3 imported bridge exits | 0.8M to 1.1M | 0.42B to 0.47B |
| Multisig and one SP1 aggchain proof | 760M | 93.8B |

Software verification of the SP1 aggchain proof dominates the second case.

The `zisk_equivalence` and `zisk_sp1_aggchain_proof` tests of `pessimistic-proof-test-suite`
check that the ZisK guest, the SP1 guest and the native execution agree:

```bash
cargo test -p pessimistic-proof-test-suite --test zisk_equivalence --test zisk_sp1_aggchain_proof \
    -- --include-ignored
```

## 5. Prove and verify

> **Blocked:** proving needs the ZisK 1.4.0-alpha proving key, which ZisK has not published yet.
> With the 1.3.2 key installed, `cargo-zisk setup` and `cargo-zisk prove` stop with:
> `proving key at ~/.zisk/provingKey has setup version 1.3.2-alpha, but this ZisK build requires 1.4.0-alpha`.
> The commands below are the expected flow and have not been run against this program yet.

1. Install the 1.4.0-alpha proving key once it is published, with `ziskup`.
   Until then, it can be regenerated locally with `cargo-zisk-dev proofman-setup setup`,
   which is a long and resource-heavy process.

2. Run the setup for the ELF once. It computes the program's ROM commitment and its vk:

   ```bash
   cargo-zisk setup -e crates/pessimistic-proof/elf/riscv64ima-zisk-zkvm-elf
   ```

   Then record the vk:
   `cargo make pp-zisk-accept-vkey-change` updates the snapshot,
   update `PROGRAM_VK` in `crates/pessimistic-proof/src/zisk.rs` to match,
   and remove the `#[ignore]` from the `zisk_vkey` test.
   A change of this vk is a protocol event, like an SP1 vkey change.

3. Prove an input, wrapped in PLONK as the node would need it,
   and verify the proof right after (`-y`):

   ```bash
   cargo-zisk prove -e crates/pessimistic-proof/elf/riscv64ima-zisk-zkvm-elf \
       -i zisk-inputs/<input>.bin -o proofs/ --plonk -y
   ```

   Add `-g` to prove on a GPU (Linux).
   Proving the aggchain proof case needs a large machine.

4. Verify a proof on its own, against trusted keys rather than the ones it embeds:

   ```bash
   cargo-zisk verify -p proofs/<proof file> \
       --plonk-vk <final.verkey.json> --setup-vk <vadcop_final.verkey.json>
   ```

## 6. Prove many inputs

`zisk-prove` proves a directory of inputs end to end and reports how long each step takes,
for example to measure proving on a server.
For every input it:

1. runs the native pessimistic proof, which gives the expected output or a rejection;
2. proves the input with ZisK, in this process or on a remote ZisK proving service;
3. optionally wraps the proof in PLONK (`--plonk`) and verifies it (`--verify`), each timed on its own;
4. checks that the proof's public values are the native output.

Proving needs the proving key (see the note in step 5), and a GPU for the aggchain proof case.
A server run looks like:

```bash
# 1000 real certificates; rerun the same command to resume after an interruption.
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- \
    --out-dir zisk-inputs network --limit 1000

# Prove them all, on a GPU, wrapped in PLONK and verified.
cargo run -r -p pessimistic-proof-test-suite --bin zisk-prove -- \
    --inputs zisk-inputs --out zisk-prove.csv --gpu --plonk --verify
```

Other options:
`--kind` proves only inputs of that kind, and can be repeated;
`--limit` proves only the first inputs, in file name order, after the `--kind` filter;
`--remote <url>` proves on a ZisK proving service instead of in this process;
`--proving-key` and `--proving-key-plonk` point to non-default key directories;
`--minimal-memory`, `--max-streams`, `--max-recursive-streams`, `--max-witness-stored` and `--cpu-mops`
trade speed for memory, as in `cargo-zisk prove`
(with `--plonk`, the prover reserves GPU memory for the PLONK wrap up front, about 28 GiB for this circuit);
`--save-proofs <dir>` keeps every proof.

Each input gets one CSV row, written as soon as it is done, so a long run can be followed and is not lost:

| Column | Meaning |
|--------|---------|
| `input` | Input file name (the request id for network inputs) |
| `network`, `bridge_exits`, `imported_bridge_exits` | What the certificate contains |
| `kind` | How it is authorized: `ecdsa`, `multisig`, or `multisig+aggchain` (a multisig and an SP1 aggchain proof) |
| `aggchain_vkey` | Vkey of the aggchain program, for `multisig+aggchain` certificates |
| `native` | `accepted`, or the native rejection reason |
| `steps`, `cost` | ZisK execution steps and cost |
| `zisk_ms` | Proving time as the ZisK prover reports it |
| `wall_ms` | Wall-clock time of the prove call |
| `wrap_ms`, `verify_ms` | PLONK wrapping and verification times |
| `proof_bytes` | Size of the final proof |
| `output_matches` | Whether the proof commits to the native output |
| `error` | Why the input failed, if it did |

At the end it prints a summary:
how many inputs succeeded, failed or proved an output other than the native one,
and the minimum, median, 90th and 99th percentiles, maximum and mean of every measure,
separately for each kind of certificate,
then the aggchain programs seen, with their number of certificates and median time.

The latest requests follow the network's traffic, so a few chains or kinds can dominate them.
Download a balanced set with `zisk-inputs network --per-kind N`,
or run `--execute-only` on the downloaded inputs first to see their mix in the CSV,
then prove one kind at a time with `--kind` if proving time is limited.

`--execute-only` runs the ZisK emulator instead of the prover.
It needs no proving key, so it checks a batch of inputs, or the tool itself, on any machine;
`zisk_ms` is then the emulation time, and `cost` is empty.

The node does not generate or verify ZisK proofs yet;
see the [ZisK pessimistic proof design](../../../docs/knowledge-base/src/ai-agents/specs/2026-10-14-zisk-pessimistic-proof-design.md).
