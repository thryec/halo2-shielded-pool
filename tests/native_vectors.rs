//! Fixed decimal fixtures from direct light-poseidon 0.4.0 calls, without this
//! crate's wrappers. The [1, 2] fixture also appears in light-poseidon's tests.
use halo2_proofs::halo2curves::ff::{Field, PrimeField};
use halo2_shielded_pool::{
    Fr, poseidon_hash,
    primitives::{
        context::{ProtocolDomain, address_field, withdrawal_binding},
        merkle::{MerkleError, MerkleTree, TREE_CAPACITY},
        note::Note,
        poseidon::parameters,
    },
};

fn f(decimal: &str) -> Fr {
    Fr::from_str_vartime(decimal).unwrap()
}

fn address(value: u64) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[12..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn domain() -> ProtocolDomain {
    let mut chain_id = [0; 32];
    chain_id[24..].copy_from_slice(&31337_u64.to_be_bytes());
    ProtocolDomain {
        chain_id,
        pool: address(0x1111),
        asset: [0; 20],
        version: 1,
    }
}

#[test]
fn poseidon_matches_fixed_one_and_two_input_vectors() {
    assert_eq!(
        poseidon_hash([Fr::from(1)]),
        f("18586133768512220936620570745912940619677854269274689475585506675881198879027")
    );
    assert_eq!(
        poseidon_hash([Fr::from(1), Fr::from(2)]),
        f("7853200120776062878684798364095072458815029376092732009249414926327459813530")
    );
}

#[test]
fn poseidon_preserves_full_field_values_and_byte_order() {
    // Published big-endian light-poseidon fixture: two 32-byte repeated inputs.
    let first = Option::<Fr>::from(Fr::from_repr([1; 32])).unwrap();
    let second = Option::<Fr>::from(Fr::from_repr([2; 32])).unwrap();
    let expected_be = [
        13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132, 254,
        156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144,
    ];
    let mut actual = poseidon_hash([first, second]).to_repr();
    actual.reverse();
    assert_eq!(actual, expected_be);
}

#[test]
fn exported_parameters_reproduce_fixed_vectors_in_round_order() {
    // This round loop checks the parameter export independently of the native
    // hash wrapper, which calls light-poseidon's own permutation.
    for (inputs, expected) in [
        (
            vec![Fr::from(1)],
            f("18586133768512220936620570745912940619677854269274689475585506675881198879027"),
        ),
        (
            vec![Fr::from(1), Fr::from(2)],
            f("7853200120776062878684798364095072458815029376092732009249414926327459813530"),
        ),
    ] {
        let spec = parameters(inputs.len());
        let mut state = vec![Fr::ZERO];
        state.extend(inputs);
        for (round, constants) in spec.round_constants.iter().enumerate() {
            let full =
                round < spec.full_rounds / 2 || round >= spec.full_rounds / 2 + spec.partial_rounds;
            for i in 0..spec.width {
                state[i] += constants[i];
                if i == 0 || full {
                    state[i] = state[i].square().square() * state[i];
                }
            }
            state = spec
                .mds
                .iter()
                .map(|row| {
                    row.iter()
                        .zip(&state)
                        .map(|(coefficient, value)| *coefficient * value)
                        .sum()
                })
                .collect();
        }
        assert_eq!(state[0], expected);
    }
}

#[test]
#[should_panic(expected = "only one or two inputs")]
fn poseidon_rejects_unselected_arity() {
    poseidon_hash([Fr::from(1); 3]);
}

#[test]
#[should_panic(expected = "only one or two inputs")]
fn poseidon_rejects_empty_input() {
    poseidon_hash([]);
}

#[test]
fn note_matches_fixed_vector_and_keeps_secret_out_of_nullifier_hash() {
    let note = Note::new(Fr::from(7), Fr::from(42));
    assert_eq!(
        note.commitment(),
        f("1888155568319425867877709792824897021401996711228592430685774487359498389896")
    );
    assert_eq!(
        note.nullifier_hash(),
        f("7061949393491957813657776856458368574501817871421526214197139795307327923534")
    );
    let changed_secret = Note::new(note.nullifier(), note.secret() + Fr::from(1));
    assert_ne!(changed_secret.commitment(), note.commitment());
    assert_eq!(changed_secret.nullifier_hash(), note.nullifier_hash());
    let changed_nullifier = Note::new(note.nullifier() + Fr::from(1), note.secret());
    assert_ne!(changed_nullifier.commitment(), note.commitment());
    assert_ne!(changed_nullifier.nullifier_hash(), note.nullifier_hash());
}

#[test]
fn empty_tree_matches_fixed_root() {
    assert_eq!(
        MerkleTree::new().root(),
        f("21551820661461729022865262380882070649935529853313286572328683688269863701601")
    );
}

#[test]
fn three_notes_match_fixed_root_and_path_with_both_directions() {
    let mut tree = MerkleTree::new();
    for (index, (nullifier, secret)) in [(3, 4), (7, 42), (9, 10)].into_iter().enumerate() {
        assert_eq!(
            tree.insert(Note::new(Fr::from(nullifier), Fr::from(secret)).commitment()),
            Ok(index)
        );
    }
    let root = f("6728680792506271963433879736350438974885545747502843013872348209184901611108");
    assert_eq!(tree.root(), root);
    let path = tree.prove(1).unwrap();
    assert_eq!(
        path.path_bits(),
        &[true, false, false, false, false, false, false, false]
    );
    assert_eq!(
        path.siblings(),
        &[
            f("14763215145315200506921711489642608356394854266165572616578112107564877678998"),
            f("7487303337757779825729213987459765205788301520430340293284628882760567206217"),
            f("7423237065226347324353380772367382631490014989348495481811164164159255474657"),
            f("11286972368698509976183087595462810875513684078608517520839298933882497716792"),
            f("3607627140608796879659380071776844901612302623152076817094415224584923813162"),
            f("19712377064642672829441595136074946683621277828620209496774504837737984048981"),
            f("20775607673010627194014556968476266066927294572720319469184847051418138353016"),
            f("3396914609616007258851405644437304192397291162432396347162513310381425243293"),
        ]
    );
    let leaf = Note::new(Fr::from(7), Fr::from(42)).commitment();
    assert_eq!(path.clone().compute_root(leaf), root);
    assert!(path.verify(leaf, root));
    assert!(!path.verify(leaf + Fr::from(1), root));
    assert!(!path.verify(leaf, root + Fr::from(1)));
    tree.insert(Fr::from(99)).unwrap();
    assert!(!path.verify(leaf, tree.root()));
}

#[test]
fn merkle_rejects_uninserted_indices_and_overflow_without_changing_root() {
    let mut tree = MerkleTree::default();
    assert!(matches!(
        tree.prove(0),
        Err(MerkleError::LeafIndexOutOfBounds)
    ));
    for index in 0..TREE_CAPACITY {
        assert_eq!(tree.insert(Fr::from(index as u64 + 1)), Ok(index));
    }
    assert!(matches!(
        tree.prove(TREE_CAPACITY),
        Err(MerkleError::LeafIndexOutOfBounds)
    ));
    let root = tree.root();
    assert_eq!(tree.insert(Fr::from(999)), Err(MerkleError::TreeFull));
    assert_eq!(tree.root(), root);
    assert!(
        tree.prove(TREE_CAPACITY - 1)
            .unwrap()
            .verify(Fr::from(TREE_CAPACITY as u64), root)
    );
}

#[test]
fn context_and_private_nullifier_binding_match_fixed_vectors() {
    let digest = domain().digest();
    assert_eq!(
        digest,
        f("7435514727583055506883087577328231697046918116103978064544660803043359354150")
    );
    let recipient = address_field(address(0x2222));
    assert_eq!(recipient, Fr::from(0x2222));
    let binding = withdrawal_binding(Fr::from(7), recipient, digest);
    assert_eq!(
        binding,
        f("3823014039291392129407375480527439191252523218263895949729914267965686033809")
    );
    assert_ne!(withdrawal_binding(Fr::from(8), recipient, digest), binding);
    assert_ne!(
        withdrawal_binding(Fr::from(7), recipient + Fr::from(1), digest),
        binding
    );
    assert_ne!(
        withdrawal_binding(Fr::from(7), recipient, digest + Fr::from(1)),
        binding
    );
}

#[test]
fn domain_binds_all_chain_bytes_pool_asset_and_version() {
    let original = domain();
    let digest = original.digest();
    for i in 0..32 {
        let mut changed = original;
        changed.chain_id[i] ^= 1;
        assert_ne!(changed.digest(), digest, "chain byte {i} must bind");
    }
    for i in 0..20 {
        let mut pool = original;
        pool.pool[i] ^= 1;
        assert_ne!(pool.digest(), digest, "pool byte {i} must bind");
        let mut asset = original;
        asset.asset[i] ^= 1;
        assert_ne!(asset.digest(), digest, "asset byte {i} must bind");
    }
    for version in [0, 2, u64::MAX] {
        let mut changed = original;
        changed.version = version;
        assert_ne!(changed.digest(), digest);
    }
    assert_eq!(
        address_field([0xff; 20]),
        f("1461501637330902918203684832716283019655932542975")
    );
}

#[test]
fn chain_id_avoids_field_reduction_aliases() {
    let mut zero_chain = domain();
    zero_chain.chain_id = [0; 32];
    let mut modulus_chain = zero_chain;
    modulus_chain.chain_id.copy_from_slice(
        &hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001").unwrap(),
    );
    assert_ne!(zero_chain.digest(), modulus_chain.digest());
}
