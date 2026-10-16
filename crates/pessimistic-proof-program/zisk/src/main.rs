#![no_main]

use pessimistic_proof_core::{
    generate_pessimistic_proof, multi_batch_header::MultiBatchHeader, NetworkState,
    PessimisticProofOutput,
};

ziskos::entrypoint!(main);
pub fn main() {
    let initial_state = ziskos::io::read::<NetworkState>();
    let batch_header = ziskos::io::read::<MultiBatchHeader>();

    let (outputs, _targets) = generate_pessimistic_proof(initial_state, &batch_header).unwrap();

    let pp_inputs = PessimisticProofOutput::bincode_codec()
        .serialize(&outputs)
        .unwrap();

    ziskos::io::commit_slice(&pp_inputs);
}
