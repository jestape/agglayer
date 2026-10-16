//! The ZisK versions and patches the node and the guest program are built with.

const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
const GUEST_LOCK: &str = include_str!("../../pessimistic-proof-program/zisk/Cargo.lock");
const GUEST_MANIFEST: &str = include_str!("../../pessimistic-proof-program/zisk/Cargo.toml");

/// The ZisK source both lockfiles must resolve: the branch the manifests
/// follow, at the commit the cached ELF is built from.
const ZISK_SOURCE: &str = "git+https://github.com/0xPolygonHermez/zisk.git\
                           ?branch=feature%2Fposeidon2-non-native#80c443d";

fn parse(toml: &str) -> toml::Value {
    toml::from_str(toml).unwrap()
}

/// The `(name, source)` of every package of a lockfile.
fn locked(lock: &toml::Value) -> Vec<(&str, Option<&str>)> {
    lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| {
            let source = package.get("source").and_then(|source| source.as_str());
            (package["name"].as_str().unwrap(), source)
        })
        .collect()
}

/// The node and the guest program must be built with the same ZisK
/// commit: the two lockfiles are resolved separately, so a `cargo update`
/// in only one of them would let them drift apart.
#[test]
fn host_and_guest_lock_the_same_zisk_commit() {
    for lock in [WORKSPACE_LOCK, GUEST_LOCK] {
        let lock = parse(lock);
        let zisk_sources: Vec<_> = locked(&lock)
            .into_iter()
            .filter_map(|(_, source)| source)
            .filter(|source| source.contains("0xPolygonHermez/zisk.git"))
            .collect();

        assert!(!zisk_sources.is_empty(), "no ZisK package locked");
        for source in zisk_sources {
            assert!(source.starts_with(ZISK_SOURCE), "locked at {source}");
        }
    }
}

/// Every precompile patch of the guest must be in use. A patch that stops
/// matching the version the guest resolves is only a Cargo warning, and
/// the guest silently falls back to the unpatched crate, in software.
#[test]
fn guest_uses_its_precompile_patches() {
    let lock = parse(GUEST_LOCK);
    assert!(
        lock.get("patch").is_none(),
        "unused patches: {:?}",
        lock["patch"]
    );

    let manifest = parse(GUEST_MANIFEST);
    let patches = manifest["patch"]["crates-io"].as_table().unwrap();
    assert!(!patches.is_empty());
    for (name, patch) in patches {
        let (git, rev) = (
            patch["git"].as_str().unwrap(),
            patch["rev"].as_str().unwrap(),
        );
        let expected = format!("git+{git}?rev={rev}#{rev}");
        let sources: Vec<_> = locked(&lock)
            .into_iter()
            .filter(|(package, _)| package == name)
            .map(|(_, source)| source)
            .collect();
        assert_eq!(sources, [Some(expected.as_str())], "{name}");
    }
}
