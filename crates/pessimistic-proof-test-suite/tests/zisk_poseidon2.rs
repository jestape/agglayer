//! The ZisK guest runs the SP1 verifier's Poseidon2 permutation on the ZisK
//! `poseidon2_koalabear` precompile, through the patched `slop-koala-bear`. The
//! precompile must compute SP1's software permutation, or the guest would
//! accept different proofs than SP1.
//!
//! This checks ZisK's implementation of the precompile, the one its emulator
//! runs, against the unpatched `slop-koala-bear`, with the state packed as the
//! patch packs it: the sixteen lanes as they are in memory, in Montgomery form,
//! two per little-endian `u64`.

use rand::{rngs::StdRng, Rng, SeedableRng};
use slop_algebra::AbstractField;
use slop_koala_bear::{my_kb_16_perm, KoalaBear};
use slop_symmetric::Permutation;
use zisk_precomp_helpers::POSEIDON2_KOALABEAR_SP1;

/// KoalaBear modulus.
const P: u32 = 0x7f00_0001;

fn precompile(state: [KoalaBear; 16]) -> [KoalaBear; 16] {
    // As the patch does: `KoalaBear` is a `repr(transparent)` Montgomery `u32`.
    let mut words: [u64; 8] = unsafe { core::mem::transmute(state) };
    POSEIDON2_KOALABEAR_SP1
        .permute_words(&mut words)
        .expect("a lane is not canonical");
    unsafe { core::mem::transmute(words) }
}

fn software(mut state: [KoalaBear; 16]) -> [KoalaBear; 16] {
    my_kb_16_perm().permute_mut(&mut state);
    state
}

fn state(mut lanes: impl FnMut(usize) -> u32) -> [KoalaBear; 16] {
    core::array::from_fn(|i| KoalaBear::from_canonical_u32(lanes(i)))
}

#[test]
fn precompile_matches_the_sp1_permutation() {
    let mut states = vec![
        state(|_| 0),
        state(|_| 1),
        state(|_| P - 1),
        state(|i| i as u32),
        state(|i| if i % 2 == 0 { 0 } else { P - 1 }),
    ];
    let mut rng = StdRng::seed_from_u64(0x504f_5345_4944_4f4e);
    states.extend((0..1000).map(|_| state(|_| rng.random_range(0..P))));

    for input in states {
        assert_eq!(precompile(input), software(input), "input {input:?}");
    }
}
