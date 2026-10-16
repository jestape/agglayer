//! The ZisK pessimistic proof program must accept and reject the same
//! certificates as the native execution and the SP1 program, and produce the
//! same output. Any difference would let the two provers settle different
//! state transitions.

use agglayer_types::{
    aggchain_data::CertificateAggchainDataCtx, primitives::U256, Address, L1WitnessCtx,
    PessimisticRootInput,
};
use common::{single_signer_multisig, u, zisk_execute, zisk_stdin};
use pessimistic_proof::{
    core::{
        commitment::{PessimisticRootCommitmentVersion, SignatureCommitmentVersion},
        generate_pessimistic_proof, AggchainData, AggchainProof,
    },
    multi_batch_header::MultiBatchHeader,
    NetworkState, PessimisticProofOutput,
};
use pessimistic_proof_test_suite::{
    forest::Forest,
    runner::Runner,
    sample_data::{self as data, ETH, USDC},
};
use rstest::rstest;

mod common;

/// Builds the pessimistic proof inputs for a certificate applying the given
/// events, signed with the given commitment version. Also returns the forest
/// after the transition, to check the output against.
fn inputs(
    initial: Forest,
    imported_bridge_events: &[(pessimistic_proof::unified_bridge::TokenInfo, U256)],
    bridge_events: &[(pessimistic_proof::unified_bridge::TokenInfo, U256)],
    version: SignatureCommitmentVersion,
) -> (NetworkState, MultiBatchHeader, Forest) {
    let state = initial.local_state().into();
    let signer = initial.get_signer();
    let certificate =
        initial
            .clone()
            .apply_events_with_version(imported_bridge_events, bridge_events, version);

    let mut forest = initial;
    let multi_batch_header = forest
        .state_b
        .apply_certificate(
            &certificate,
            L1WitnessCtx {
                l1_info_root: certificate.l1_info_root().unwrap().unwrap_or_default(),
                prev_pessimistic_root: PessimisticRootInput::Computed(
                    PessimisticRootCommitmentVersion::V2,
                ),
                aggchain_data_ctx: CertificateAggchainDataCtx::LegacyEcdsa { signer },
            },
        )
        .unwrap();

    (state, multi_batch_header, forest)
}

fn native(state: &NetworkState, header: &MultiBatchHeader) -> Option<PessimisticProofOutput> {
    generate_pessimistic_proof(state.clone(), header)
        .ok()
        .map(|(output, _)| output)
}

fn sp1(state: &NetworkState, header: &MultiBatchHeader) -> Option<PessimisticProofOutput> {
    // The runner panics when a rejecting guest commits no public values.
    std::panic::catch_unwind(|| Runner::new().execute(state, header))
        .ok()?
        .ok()
        .map(|(output, _)| output)
}

fn zisk(state: &NetworkState, header: &MultiBatchHeader) -> Option<PessimisticProofOutput> {
    zisk_execute(&zisk_stdin(state, header))
}

/// Runs the three executions and checks that they agree.
fn assert_equivalent(
    state: &NetworkState,
    header: &MultiBatchHeader,
) -> Option<PessimisticProofOutput> {
    let native = native(state, header);
    assert_eq!(
        sp1(state, header),
        native,
        "SP1 and native executions differ"
    );
    assert_eq!(
        zisk(state, header),
        native,
        "ZisK and native executions differ"
    );
    native
}

#[rstest]
#[case::no_events(Forest::new([]), &[], &[])]
#[case::exits(
    data::sample_state_01(),
    &[],
    &[(USDC, u(20)), (ETH, u(50)), (USDC, u(30))],
)]
#[case::imported_and_exits(
    Forest::new([(USDC, u(100)), (ETH, u(200))]),
    &[(USDC, u(50)), (ETH, u(100)), (USDC, u(10))],
    &[(USDC, u(20)), (ETH, u(50)), (USDC, u(130))],
)]
fn legacy_ecdsa_certificates(
    #[case] forest: Forest,
    #[case] imported_bridge_events: &[(pessimistic_proof::unified_bridge::TokenInfo, U256)],
    #[case] bridge_events: &[(pessimistic_proof::unified_bridge::TokenInfo, U256)],
) {
    let (state, header, forest) = inputs(
        forest,
        imported_bridge_events,
        bridge_events,
        SignatureCommitmentVersion::V2,
    );

    let output = assert_equivalent(&state, &header).expect("valid certificate rejected");
    forest.assert_output_matches(&output);
}

#[test]
fn multisig_certificate() {
    let (state, mut header, _) = inputs(
        Forest::new([(USDC, u(100))]),
        &[(USDC, u(10))],
        &[(USDC, u(20))],
        SignatureCommitmentVersion::V5,
    );
    let AggchainData::LegacyEcdsa { signer, signature } = header.aggchain_data else {
        panic!("inconsistent test data")
    };
    header.aggchain_data = AggchainData::MultisigOnly(single_signer_multisig(signer, signature));

    // `Forest::assert_output_matches` only knows the legacy pessimistic root
    // layout, so only check that the three executions agree.
    assert_equivalent(&state, &header).expect("valid certificate rejected");
}

#[test]
fn wrong_signer_is_rejected() {
    let (state, mut header, _) = inputs(
        Forest::new([(USDC, u(100))]),
        &[],
        &[(USDC, u(20))],
        SignatureCommitmentVersion::V2,
    );
    let AggchainData::LegacyEcdsa { signature, .. } = header.aggchain_data else {
        panic!("inconsistent test data")
    };
    header.aggchain_data = AggchainData::LegacyEcdsa {
        signer: Address::new([0x42; 20]),
        signature,
    };

    assert_eq!(assert_equivalent(&state, &header), None);
}

/// The native execution does not verify aggchain proofs: the zkVM does. A
/// certificate with an aggchain proof but no valid proof in the input must be
/// rejected by the ZisK program rather than accepted unchecked. Valid SP1
/// aggchain proofs are covered by the `zisk_sp1_aggchain_proof` test.
#[test]
fn missing_aggchain_proof_is_rejected_by_zisk() {
    let (state, mut header, _) = inputs(
        Forest::new([(USDC, u(100))]),
        &[],
        &[(USDC, u(20))],
        SignatureCommitmentVersion::V5,
    );
    let AggchainData::LegacyEcdsa { signer, signature } = header.aggchain_data else {
        panic!("inconsistent test data")
    };
    header.aggchain_data = AggchainData::MultisigAndAggchainProof {
        multisig: single_signer_multisig(signer, signature),
        aggchain_proof: AggchainProof {
            aggchain_params: Default::default(),
            aggchain_vkey: [0; 8],
        },
    };

    assert!(native(&state, &header).is_some());
    assert_eq!(zisk(&state, &header), None);
}
