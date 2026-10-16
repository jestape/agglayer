//! Host-side helpers for the ZisK pessimistic proof program.

use pessimistic_proof_core::PessimisticProofOutput;

/// ELF of the ZisK pessimistic proof program.
///
/// Rebuilt from `crates/pessimistic-proof-program/zisk` with
/// `cargo make pp-zisk-elf-build`.
pub const ELF: &[u8] = include_bytes!("../elf/riscv64ima-zisk-zkvm-elf");

/// Verification key of [`ELF`], under the Poseidon1 hash mode. The `zisk_vkey`
/// test checks that it matches [`ELF`].
///
/// Stale: this is the vk of the ZisK 1.3.2-alpha ELF. The ROM setup of the
/// current ELF needs the ZisK 1.4.0-alpha proving key, which is not published
/// yet, so the vk and its snapshot are updated, and `zisk_vkey` re-enabled,
/// once it is.
pub const PROGRAM_VK: [u64; 4] = [
    0xb060a7b7d6b9f5ff,
    0xca4957c944e16193,
    0x7bf9029c23ace09e,
    0x760f7bcc05b4bd3f,
];

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("failed to decode the pessimistic proof output")]
    Decode(#[source] agglayer_bincode::Error),
    #[error("non-zero bytes after the pessimistic proof output")]
    TrailingBytes,
}

/// Decodes the [`PessimisticProofOutput`] committed by the ZisK program.
///
/// ZisK exposes its public values as a fixed-size buffer, so the encoded
/// output is followed by padding, which must be all zeros.
pub fn decode_output(public_values: &[u8]) -> Result<PessimisticProofOutput, OutputError> {
    let mut remaining = public_values;
    let output = PessimisticProofOutput::bincode_codec()
        .deserialize_from(&mut remaining)
        .map_err(OutputError::Decode)?;

    if remaining.iter().any(|byte| *byte != 0) {
        return Err(OutputError::TrailingBytes);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use agglayer_primitives::Digest;
    use agglayer_tries::roots::LocalExitRoot;
    use unified_bridge::NetworkId;

    use super::*;

    /// Size of the ZisK public values buffer, in bytes.
    const PUBLIC_VALUES_LEN: usize = 256;

    fn output() -> PessimisticProofOutput {
        PessimisticProofOutput {
            prev_local_exit_root: LocalExitRoot::new(Digest([1; 32])),
            prev_pessimistic_root: Digest([2; 32]),
            l1_info_root: Digest([3; 32]),
            origin_network: NetworkId::new(4),
            aggchain_hash: Digest([5; 32]),
            new_local_exit_root: LocalExitRoot::new(Digest([6; 32])),
            new_pessimistic_root: Digest([7; 32]),
        }
    }

    fn public_values() -> Vec<u8> {
        let mut bytes = PessimisticProofOutput::bincode_codec()
            .serialize(&output())
            .unwrap();
        bytes.resize(PUBLIC_VALUES_LEN, 0);
        bytes
    }

    #[test]
    fn decodes_zero_padded_output() {
        assert_eq!(decode_output(&public_values()).unwrap(), output());
    }

    #[test]
    fn rejects_non_zero_padding() {
        let mut bytes = public_values();
        *bytes.last_mut().unwrap() = 1;
        assert!(matches!(
            decode_output(&bytes),
            Err(OutputError::TrailingBytes)
        ));
    }

    #[test]
    fn rejects_truncated_output() {
        assert!(matches!(
            decode_output(&public_values()[..100]),
            Err(OutputError::Decode(_))
        ));
    }
}
