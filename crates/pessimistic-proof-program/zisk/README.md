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

All commands run from the repository root.

## 1. Install ZisK

The guest and the host crates use ZisK **1.4.0-alpha**,
which is not released yet:
the workspace follows the `feature/poseidon2-non-native` branch,
which adds the KoalaBear Poseidon2 precompile to `pre-develop-1.4.0-alpha`,
and both lockfiles pin commit `7606967`.
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
   cargo install --locked --git https://github.com/0xPolygonHermez/zisk.git --rev 7606967 \
       cargo-zisk ziskemu --root ~/.zisk-1.4.0
   export PATH="$HOME/.zisk-1.4.0/bin:$PATH"
   cargo-zisk --version   # cargo-zisk 1.4.0-alpha [cpu] (7606967 ...)
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

The guest patches three crates with ZisK precompiles, in its own `Cargo.toml` only:
`tiny-keccak` (keccak-f), `k256` (secp256k1) and `slop-koala-bear` (KoalaBear Poseidon2).
The `k256` patch needs ZisK 1.4.0-alpha:
with ZisK 1.3.2 the guest fails to link with `undefined symbol: ecdsa_verify_secp256k1_c`,
and the 1.3.2 emulator rejects its unaligned secp256k1 precompile calls.

### Patched crates

`patches/slop-koala-bear` is a modified copy of
[`slop-koala-bear`](https://crates.io/crates/slop-koala-bear) 6.2.2 by Succinct Labs,
licensed under MIT or Apache-2.0 (`LICENSE-MIT` and `LICENSE-APACHE` in that directory).
Only `src/koala_bear_poseidon2.rs` is modified:
`KoalaPerm` wraps the software permutation and, inside ZisK,
runs it on the `poseidon2_koalabear` precompile instead.
The SP1 verifier hashes its Merkle trees and drives its challenger with this permutation,
so nearly all of its Poseidon2 permutations run on the precompile.
The other files are the crate as published on crates.io.

To move to a new SP1 version, replace the copy with the new published crate
and apply the change to `src/koala_bear_poseidon2.rs` again.

## 3. Obtain inputs

An input is the guest's stdin, in the order the guest reads it:

1. the `NetworkState` before the certificate,
2. the `MultiBatchHeader` of the certificate,
3. the SP1 compressed aggchain proof, only if the certificate carries one,
   as one frame in SP1's fixed-int bincode encoding
   (`pessimistic_proof::zisk::encode_sp1_compressed_proof`), which the guest decodes faster
   than the default varint encoding.

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
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- network --limit 50 --aggchain-proof-only

# Specific requests, by id (as shown in the explorer).
cargo run -r -p pessimistic-proof-test-suite --bin zisk-inputs -- \
    network --request-id 0x98cd5602d1c6da623ecf0aad4fcb319074066ea5f221c2c9006d4181259059ee
```

Requests are selected by the vk of the SP1 pessimistic proof program built by this repository.
To fetch the requests of another program version, pass its vk hash with `--vk-hash`,
as the explorer shows it.
Requests with a private stdin are skipped.

Each line of output describes one file:

```text
zisk-inputs/0x98cd...59ee.bin: network 85, 0 bridge exits, 1 imported bridge exits, 1 SP1 aggchain proof(s), native execution accepted
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
| Multisig and one SP1 aggchain proof | 42.6M to 43.2M | 5.97B to 6.07B |

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

The node does not generate or verify ZisK proofs yet;
see the [ZisK pessimistic proof design](../../../docs/knowledge-base/src/ai-agents/specs/2026-10-14-zisk-pessimistic-proof-design.md).
