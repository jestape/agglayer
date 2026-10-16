//! The ZisK pessimistic proof program verifies SP1 compressed aggchain proofs
//! in software. It must accept and reject the same aggchain proofs as the SP1
//! program, which verifies them as deferred proofs.

use agglayer_types::{
    aggchain_data::CertificateAggchainDataCtx, L1WitnessCtx, PessimisticRootInput,
};
use common::{single_signer_multisig, u, zisk_execute, zisk_stdin};
use ecdsa_proof_lib::AggchainECDSA;
use pessimistic_proof::{
    core::{
        commitment::{
            PessimisticRootCommitmentVersion, SignatureCommitmentValues, SignatureCommitmentVersion,
        },
        generate_pessimistic_proof, AggchainData, AggchainProof,
    },
    keccak::keccak256_combine,
    local_state::LocalNetworkState,
    multi_batch_header::MultiBatchHeader,
    unified_bridge::ImportedBridgeExitCommitmentVersion,
    NetworkState, PessimisticProofOutput,
};
use pessimistic_proof_test_suite::{
    forest::{compute_aggchain_proof, Forest},
    runner::Runner,
    sample_data::{ETH, USDC},
    PESSIMISTIC_PROOF_ELF,
};
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    Elf, HashableKey, SP1Proof, SP1VerifyingKey,
};

mod common;

struct Fixture {
    state: NetworkState,
    header: MultiBatchHeader,
    aggchain_proof: SP1Proof,
    aggchain_vkey: SP1VerifyingKey,
}

/// A certificate carrying a real SP1 compressed aggchain proof from the ECDSA
/// example program, and a multisig over the commitment the PP expects.
///
/// `Forest::apply_events_with_aggchain_proof` is not used: it feeds the ECDSA
/// program a witness that the program rejects, so the resulting proof has a
/// non-zero exit code.
fn fixture() -> Fixture {
    let initial = Forest::new(vec![(USDC, u(100)), (ETH, u(200))]);
    let certificate = initial.clone().apply_events_with_version(
        &[(USDC, u(50)), (ETH, u(100)), (USDC, u(10))],
        &[(USDC, u(20)), (ETH, u(50)), (USDC, u(130))],
        SignatureCommitmentVersion::V5,
    );
    let signer = initial.get_signer();
    let l1_info_root = certificate.l1_info_root().unwrap().unwrap_or_default();

    // The aggchain proof commits to the imported bridge exits with the
    // version the PP expects, and is signed by the forest's wallet.
    let mut commitment_values = SignatureCommitmentValues::from(&certificate);
    let commit_imported_bridge_exits = commitment_values
        .commit_imported_bridge_exits
        .commitment(ImportedBridgeExitCommitmentVersion::V3)
        .0;
    let (ecdsa_signature, _) = initial
        .sign(keccak256_combine([
            certificate.new_local_exit_root.as_ref(),
            commit_imported_bridge_exits.as_slice(),
        ]))
        .unwrap();
    let (aggchain_proof, aggchain_vkey, aggchain_params) = compute_aggchain_proof(AggchainECDSA {
        prev_local_exit_root: certificate.prev_local_exit_root,
        new_local_exit_root: certificate.new_local_exit_root,
        commit_imported_bridge_exits,
        l1_info_root: *l1_info_root,
        origin_network: initial.network_id,
        signer,
        signature: ecdsa_signature,
    });

    // The multisig signs the commitment that includes the aggchain params.
    commitment_values.aggchain_params = Some(aggchain_params.into());
    let (multisig_signature, _) = initial
        .sign(commitment_values.multisig_commitment().0.into())
        .unwrap();

    let mut header = initial
        .state_b
        .clone()
        .make_multi_batch_header(
            &certificate,
            L1WitnessCtx {
                l1_info_root,
                prev_pessimistic_root: PessimisticRootInput::Computed(
                    PessimisticRootCommitmentVersion::V2,
                ),
                aggchain_data_ctx: CertificateAggchainDataCtx::LegacyEcdsa { signer },
            },
        )
        .unwrap();
    header.aggchain_data = AggchainData::MultisigAndAggchainProof {
        multisig: single_signer_multisig(signer, multisig_signature),
        aggchain_proof: AggchainProof {
            aggchain_params: aggchain_params.into(),
            aggchain_vkey: aggchain_vkey.hash_u32(),
        },
    };

    Fixture {
        state: LocalNetworkState::from(initial.state_b).into(),
        header,
        aggchain_proof,
        aggchain_vkey,
    }
}

fn sp1(fixture: &Fixture, header: &MultiBatchHeader) -> Option<PessimisticProofOutput> {
    let mut stdin = Runner::prepare_stdin(&fixture.state, header);
    stdin.write_proof(
        *fixture.aggchain_proof.clone().try_as_compressed().unwrap(),
        fixture.aggchain_vkey.vk.clone(),
    );

    let (public_values, _) = ProverClient::from_env()
        .execute(Elf::Static(PESSIMISTIC_PROOF_ELF), stdin)
        // As the certifier does: otherwise SP1 does not check the proof.
        .deferred_proof_verification(true)
        .run()
        .ok()?;
    Some(Runner::extract_output(public_values))
}

fn zisk(fixture: &Fixture, header: &MultiBatchHeader) -> Option<PessimisticProofOutput> {
    let SP1Proof::Compressed(proof) = &fixture.aggchain_proof else {
        panic!("not a compressed proof")
    };
    let stdin = zisk_stdin(&fixture.state, header);
    stdin.write_slice(&pessimistic_proof::zisk::encode_sp1_compressed_proof(&**proof).unwrap());
    zisk_execute(&stdin)
}

fn aggchain_proof_mut(header: &mut MultiBatchHeader) -> &mut AggchainProof {
    let AggchainData::MultisigAndAggchainProof { aggchain_proof, .. } = &mut header.aggchain_data
    else {
        panic!("inconsistent test data")
    };
    aggchain_proof
}

#[test]
#[ignore = "generates a real SP1 compressed proof"]
fn sp1_aggchain_proof() {
    let fixture = fixture();

    // A valid proof: the three executions agree.
    let native = generate_pessimistic_proof(fixture.state.clone(), &fixture.header)
        .unwrap()
        .0;
    assert_eq!(sp1(&fixture, &fixture.header), Some(native.clone()));
    assert_eq!(zisk(&fixture, &fixture.header), Some(native));

    // Invalid aggchain proofs. SP1 execution cannot serve as the reference
    // here: it checks a deferred proof against the vkey it is supplied with,
    // and only proving binds that proof to the vkey and public values the
    // guest expects. The SP1 PP rejects these when proving.

    // The proof does not match the expected program vkey.
    let mut header = fixture.header.clone();
    aggchain_proof_mut(&mut header).aggchain_vkey[0] ^= 1;
    assert_eq!(zisk(&fixture, &header), None);

    // The proof does not commit to the certificate's aggchain params.
    let mut header = fixture.header.clone();
    aggchain_proof_mut(&mut header).aggchain_params = Default::default();
    assert_eq!(zisk(&fixture, &header), None);
}
