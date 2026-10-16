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
