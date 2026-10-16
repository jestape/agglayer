//! Host-side helpers for the SP1 pessimistic proof program.

/// ELF of the SP1 pessimistic proof program, built by this crate's build script
/// from `crates/pessimistic-proof-program/sp1`.
pub const ELF: &[u8] = agglayer_elf_build::elf_bytes!();
