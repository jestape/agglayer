use pessimistic_proof_test_suite::zisk::{program_vk, HashMode};

#[test]
#[ignore = "needs the ZisK 1.4.0-alpha proving key, which is not published yet"]
fn zisk_vkey_snapshot() {
    // The vk depends on the hash mode, which comes from the proving key. Pin
    // Poseidon1 rather than whatever key is installed locally. The vk is read
    // from the setup cache, populated by `cargo make pp-zisk-setup`.
    let vk = program_vk(pessimistic_proof::zisk::ELF, HashMode::Poseidon1)
        .expect("run the ZisK setup for the cached ELF first");
    assert_eq!(
        vk.vk,
        pessimistic_proof::zisk::PROGRAM_VK,
        "update pessimistic_proof::zisk::PROGRAM_VK"
    );
    let words: Vec<String> = vk.vk.iter().map(|word| format!("{word:016x}")).collect();

    let message = format!(
        "# If this test fails, it means the ZisK PP program vk has changed.\n\
         # Like an SP1 PP vkey change, this is a protocol event.\n\
         | ZISK_PP_VK_HASH_MODE | {:?} |\n\
         | ZISK_PP_VK           | {} |\n",
        vk.hash_mode,
        words.join(" "),
    );

    insta::assert_snapshot!(message);
}
