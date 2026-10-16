//! Helpers shared by the ZisK integration tests.

#![allow(dead_code)]

use std::sync::LazyLock;

use agglayer_types::{primitives::U256, Address, Signature};
use pessimistic_proof::{
    core::MultiSignature, multi_batch_header::MultiBatchHeader, NetworkState,
    PessimisticProofOutput,
};
use pessimistic_proof_test_suite::zisk::{Executor, ZiskStdin};

/// The ZisK program, transpiled once per test binary.
static ZISK_EXECUTOR: LazyLock<Executor> =
    LazyLock::new(|| Executor::new(pessimistic_proof::zisk::ELF).unwrap());

pub fn u(x: u64) -> U256 {
    x.try_into().unwrap()
}

/// The ZisK program's input, in the order the guest reads it. Aggchain proofs,
/// if any, are appended after it.
pub fn zisk_stdin(state: &NetworkState, header: &MultiBatchHeader) -> ZiskStdin {
    let stdin = ZiskStdin::new();
    stdin.write(state);
    stdin.write(header);
    stdin
}

/// Runs the ZisK program, returning its output, or `None` if it rejects.
pub fn zisk_execute(stdin: &ZiskStdin) -> Option<PessimisticProofOutput> {
    let public_values = ZISK_EXECUTOR.execute(stdin).ok()?;
    Some(pessimistic_proof::zisk::decode_output(&public_values).unwrap())
}

/// A 1-of-1 multisig of `signer`.
pub fn single_signer_multisig(signer: Address, signature: Signature) -> MultiSignature {
    MultiSignature {
        signatures: vec![Some(signature)],
        expected_signers: vec![signer],
        threshold: 1,
    }
}
