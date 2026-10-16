//! Verification of SP1 compressed aggchain proofs in software, for zkVM
//! backends that cannot verify them natively.
//!
//! It accepts exactly the proofs the SP1 backend accepts as deferred proofs:
//! `SP1CompressedVerifier::verify_compressed` checks the shard proof, the
//! recursion public values, the recursion vk against SP1's vk Merkle root, that
//! the proof is complete, and the program vkey. The SP1 deferred proof circuit
//! additionally requires a zero exit code and binds the committed public
//! values digest, which are checked here.

use std::borrow::Borrow;

use slop_algebra::{AbstractField, PrimeField32};
use sp1_hypercube::{SP1PcsProofInner, SP1RecursionProof};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_recursion_executor::RecursionPublicValues;
use sp1_verifier::compressed::{CompressedError, SP1CompressedVerifier};

use super::Vkey;

/// An SP1 compressed proof, as written to the guest input.
pub type Sp1CompressedProof = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>;

#[derive(Debug, thiserror::Error)]
pub enum Sp1CompressedProofError {
    #[error("the aggchain vkey contains a non-canonical field element")]
    NonCanonicalVkey,
    #[error("SP1 compressed proof verification failed: {0}")]
    Verification(#[from] CompressedError),
    #[error("the aggchain program did not exit successfully")]
    ExitCode,
    #[error("the committed public values do not match the expected ones")]
    PublicValues,
}

/// Reads the next SP1 compressed proof from the guest input: one frame in SP1's fixed-int bincode
/// encoding, as `pessimistic_proof::zisk::encode_sp1_compressed_proof` writes it. It is decoded
/// with [`super::fixint`], which reads that encoding in fewer steps than bincode.
pub fn read_proof() -> Sp1CompressedProof {
    super::fixint::deserialize(&ziskos::io::read_slice()).expect("malformed SP1 compressed proof")
}

/// Verifies that `proof` is a valid SP1 compressed proof of the program
/// `vkey`, committing to public values hashing to `public_values_digest`.
pub fn verify(
    proof: &Sp1CompressedProof,
    vkey: &Vkey,
    public_values_digest: &[u8; 32],
) -> Result<(), Sp1CompressedProofError> {
    if vkey.iter().any(|word| *word >= SP1Field::ORDER_U32) {
        return Err(Sp1CompressedProofError::NonCanonicalVkey);
    }
    let vkey = vkey.map(SP1Field::from_canonical_u32);

    SP1CompressedVerifier::new().verify_compressed(proof, &vkey)?;

    // The public values length was checked by `verify_compressed`.
    let public_values: &RecursionPublicValues<SP1Field> =
        proof.proof.public_values.as_slice().borrow();

    if public_values.exit_code != SP1Field::zero() {
        return Err(Sp1CompressedProofError::ExitCode);
    }

    let committed_digest = public_values.committed_value_digest.iter().flatten();
    if !committed_digest
        .zip(public_values_digest)
        .all(|(actual, expected)| actual.as_canonical_u32() == u32::from(*expected))
    {
        return Err(Sp1CompressedProofError::PublicValues);
    }

    Ok(())
}

