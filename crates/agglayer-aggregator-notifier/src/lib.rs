/// ELF of the pessimistic proof program
const ELF: &[u8] = pessimistic_proof::sp1::ELF;

mod certifier;
mod prover;

pub use certifier::CertifierClient;
pub use prover::ProverRouter;
