//! ZisK facade: program execution and program verification keys. Proof
//! generation and verification are not part of the node yet.
//!
//! All crates outside of the pessimistic-proof family should reach ZisK
//! through this crate and avoid direct `zisk-*` dependencies.

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

#[cfg(test)]
mod tests {
    /// The ZisK source both lockfiles must resolve: the branch the manifests
    /// follow, at the commit the cached ELF is built from.
    const ZISK_SOURCE: &str = "git+https://github.com/0xPolygonHermez/zisk.git\
                               ?branch=feature%2Fposeidon2-non-native#7606967";

    /// The node and the guest program must be built with the same ZisK
    /// commit: the two lockfiles are resolved separately, so a `cargo update`
    /// in only one of them would let them drift apart.
    #[test]
    fn host_and_guest_lock_the_same_zisk_commit() {
        for lock in [
            include_str!("../../../../Cargo.lock"),
            include_str!("../../../pessimistic-proof-program/zisk/Cargo.lock"),
        ] {
            let lock: toml::Value = toml::from_str(lock).unwrap();
            let mut zisk_sources = lock["package"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|package| package.get("source")?.as_str())
                .filter(|source| source.contains("0xPolygonHermez/zisk.git"))
                .peekable();

            assert!(zisk_sources.peek().is_some(), "no ZisK package locked");
            for source in zisk_sources {
                assert!(source.starts_with(ZISK_SOURCE), "locked at {source}");
            }
        }
    }
}
