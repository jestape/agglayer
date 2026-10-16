//! Runs programs in the ZisK emulator and computes their verification keys,
//! for the ZisK pessimistic proof tests and tools.

use zisk_core::ZiskRom;
use zisk_sdk::GuestProgram;
pub use zisk_sdk::{HashMode, ProgramVK, ZiskStdin};
use ziskemu::{EmuOptions, ZiskEmulator};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to transpile the ELF into a ZisK ROM: {0}")]
    Transpile(String),
    #[error("ZisK emulation failed: {0}")]
    Emulation(String),
    #[error("failed to compute the program verification key: {0}")]
    ProgramVk(String),
}

/// Runs a program in the ZisK emulator.
///
/// This needs no prover client.
pub struct Executor {
    rom: ZiskRom,
}

impl Executor {
    /// Transpiles `elf` into a ZisK ROM, once for all executions.
    pub fn new(elf: &[u8]) -> Result<Self, Error> {
        let rom = zisk_transpiler_common::program2rom(elf)
            .map_err(|error| Error::Transpile(error.to_string()))?;
        Ok(Self { rom })
    }

    /// Runs the program with `stdin` and returns its public outputs.
    ///
    /// A guest that panics, for example on an invalid certificate, makes the
    /// emulator panic on the host instead of returning an error, so the panic
    /// is caught and reported as [`Error::Emulation`].
    pub fn execute(&self, stdin: &ZiskStdin) -> Result<Vec<u8>, Error> {
        let inputs = stdin.read_data();

        std::panic::catch_unwind(|| {
            ZiskEmulator::process_rom(&self.rom, &inputs, &EmuOptions::default(), None::<fn(_)>)
        })
        .map_err(|payload| {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("unknown cause");
            Error::Emulation(format!("the guest program panicked: {message}"))
        })?
        .map_err(|error| Error::Emulation(format!("{error:?}")))
    }
}

/// Computes the program verification key of `elf` under `hash_mode`.
pub fn program_vk(elf: &[u8], hash_mode: HashMode) -> Result<ProgramVK, Error> {
    GuestProgram::from_bytes("program", elf.to_vec())
        .vk_with_mode(hash_mode)
        .map_err(|error| Error::ProgramVk(error.to_string()))
}

/// How a certificate is authorized, which drives its proving cost: an SP1
/// aggchain proof makes the guest verify it in software.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, clap::ValueEnum)]
pub enum Kind {
    /// A legacy ECDSA signature.
    #[value(name = "ecdsa")]
    Ecdsa,
    /// A multisig only.
    #[value(name = "multisig")]
    Multisig,
    /// A multisig and an SP1 aggchain proof.
    #[value(name = "multisig+aggchain")]
    MultisigAggchain,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Ecdsa, Kind::Multisig, Kind::MultisigAggchain];

    pub fn of(header: &pessimistic_proof::multi_batch_header::MultiBatchHeader) -> Self {
        use pessimistic_proof::core::AggchainData;
        match header.aggchain_data {
            AggchainData::LegacyEcdsa { .. } => Kind::Ecdsa,
            AggchainData::MultisigOnly(_) => Kind::Multisig,
            AggchainData::MultisigAndAggchainProof { .. } => Kind::MultisigAggchain,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Ecdsa => "ecdsa",
            Kind::Multisig => "multisig",
            Kind::MultisigAggchain => "multisig+aggchain",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The vkey of the aggchain program whose proof the certificate carries, as
/// 0x-prefixed hex of its eight big-endian words, if it carries one.
pub fn aggchain_vkey(
    header: &pessimistic_proof::multi_batch_header::MultiBatchHeader,
) -> Option<String> {
    match &header.aggchain_data {
        pessimistic_proof::core::AggchainData::MultisigAndAggchainProof {
            aggchain_proof, ..
        } => Some(format!(
            "0x{}",
            hex::encode(aggchain_proof.aggchain_vkey.map(u32::to_be_bytes).concat())
        )),
        _ => None,
    }
}

/// Reads the network state and the batch header that start a ZisK input file,
/// which the native pessimistic proof takes too.
pub fn read_witness(
    path: &std::path::Path,
) -> Result<
    (
        pessimistic_proof::NetworkState,
        pessimistic_proof::multi_batch_header::MultiBatchHeader,
    ),
    zisk_sdk::SdkError,
> {
    let input = ZiskStdin::from_file(path)?;
    Ok((input.read()?, input.read()?))
}
