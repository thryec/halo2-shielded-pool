// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Halo2Verifier} from "../contracts/generated/Halo2Verifier.sol";
import {Poseidon1} from "../contracts/generated/Poseidon1.sol";
import {Poseidon2} from "../contracts/generated/Poseidon2.sol";

interface Vm {
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function parseJsonBytes32Array(string calldata json, string calldata key) external pure returns (bytes32[] memory);
    function parseJsonUintArray(string calldata json, string calldata key) external pure returns (uint256[] memory);
    function cool(address target) external;
}

// Hash parity and statement checks only, not a pool contract.
contract WithdrawalProofTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant VERIFY_GAS = 2_000_000;
    Halo2Verifier private verifier;
    Poseidon1 private h1;
    Poseidon2 private h2;
    bytes private input;
    string private vectors;

    event log_named_uint(string key, uint256 value);

    function setUp() public {
        verifier = new Halo2Verifier();
        h1 = new Poseidon1();
        h2 = new Poseidon2();
        vectors = vm.readFile("artifacts/withdrawal.json");
        input = vm.parseJsonBytes(vectors, ".calldata");
    }

    function expected(string memory key) private view returns (uint256) {
        return uint256(vm.parseJsonBytes32(vectors, key));
    }

    function testValidWithdrawalProofAndVerifierLimits() public {
        bytes memory data = input;
        address target = address(verifier);
        vm.cool(target);
        uint256 beforeGas = gasleft();
        (bool ok, bytes memory result) = target.staticcall{gas: VERIFY_GAS}(data);
        uint256 used = beforeGas - gasleft();
        require(ok && result.length == 0, "valid withdrawal rejected");
        require(target.code.length > 0 && target.code.length <= 24576, "bad verifier size");
        emit log_named_uint("Verifier runtime bytes", target.code.length);
        emit log_named_uint("Verifier creation bytes", type(Halo2Verifier).creationCode.length);
        emit log_named_uint("Cold valid proof call gas", used);
    }

    function testChangedRootNullifierRecipientDomainAndBindingFail() public view {
        for (uint256 row; row < 5; ++row) {
            bytes memory changed = input;
            // Valid field value, wrong statement, same proof.
            uint256 word;
            assembly ("memory-safe") { word := mload(add(add(changed, 32), mul(row, 32))) }
            word = addmod(word, 1, P);
            assembly ("memory-safe") { mstore(add(add(changed, 32), mul(row, 32)), word) }
            (bool ok,) = address(verifier).staticcall{gas: VERIFY_GAS}(changed);
            require(!ok, "changed public input accepted");
        }
    }

    function testNonCanonicalAliasesFailForEveryPublicWord() public view {
        for (uint256 row; row < 5; ++row) {
            bytes memory changed = input;
            uint256 word;
            assembly ("memory-safe") { word := mload(add(add(changed, 32), mul(row, 32))) }
            word += P;
            assembly ("memory-safe") { mstore(add(add(changed, 32), mul(row, 32)), word) }
            (bool ok,) = address(verifier).staticcall{gas: VERIFY_GAS}(changed);
            require(!ok, "field alias accepted");
        }
    }

    function testCorruptedProofFails() public view {
        bytes memory changed = input;
        changed[160] = bytes1(uint8(changed[160]) ^ 1);
        (bool ok,) = address(verifier).staticcall{gas: VERIFY_GAS}(changed);
        require(!ok, "corrupted proof accepted");
    }

    function testNonCanonicalProofScalarsFailLikeRust() public view {
        uint256[] memory offsets = vm.parseJsonUintArray(vectors, ".proof_scalar_offsets");
        require(offsets.length > 0, "no proof scalars tested");
        for (uint256 i; i < offsets.length; ++i) {
            bytes memory changed = input;
            uint256 offset = offsets[i];
            require(offset >= 160 && offset + 32 <= changed.length, "bad scalar offset");
            uint256 scalar;
            assembly ("memory-safe") { scalar := mload(add(add(changed, 32), offset)) }
            require(scalar < P, "original scalar not canonical");
            scalar += P;
            assembly ("memory-safe") { mstore(add(add(changed, 32), offset), scalar) }
            (bool ok,) = address(verifier).staticcall{gas: VERIFY_GAS}(changed);
            require(!ok, "noncanonical proof scalar accepted");
        }
    }

    function testTruncatedEmptyAndAppendedCalldataFail() public view {
        bytes memory shortData = input;
        assembly ("memory-safe") { mstore(shortData, sub(mload(shortData), 1)) }
        (bool shortOk,) = address(verifier).staticcall{gas: VERIFY_GAS}(shortData);
        (bool emptyOk,) = address(verifier).staticcall{gas: VERIFY_GAS}(hex"");
        (bool longOk,) = address(verifier).staticcall{gas: VERIFY_GAS}(bytes.concat(input, hex"00"));
        require(!shortOk && !emptyOk && !longOk, "wrong calldata length accepted");
    }

    function testHashNoteAndNullifierVectors() public view {
        require(
            h2.hash(1, 2) == 7853200120776062878684798364095072458815029376092732009249414926327459813530, "H2 vector"
        );
        require(h1.hash(1) == expected(".vectors.h1_one"), "H1 vector");
        require(h2.hash(7, 42) == expected(".vectors.commitment"), "note vector");
        require(h1.hash(7) == expected(".vectors.nullifier_hash"), "nullifier vector");
        require(h1.hash(7) != h2.hash(7, 0), "wrong hash arity");
        require(h1.hash(P - 1) == expected(".vectors.h1_max"), "H1 boundary vector");
        require(h2.hash(P - 1, 42) == expected(".vectors.h2_max"), "H2 boundary vector");
    }

    function testEmptyRootAndMerklePathVectors() public view {
        uint256 empty;
        for (uint256 level; level < 8; ++level) {
            empty = h2.hash(empty, empty);
        }
        require(empty == expected(".vectors.empty_root"), "empty root vector");
        bytes32[] memory siblings = vm.parseJsonBytes32Array(vectors, ".vectors.siblings");
        require(siblings.length == 8, "wrong path depth");
        uint256 current = h2.hash(7, 42);
        // Leaf index 1: right at level 0, left at all later levels.
        for (uint256 level; level < 8; ++level) {
            current =
                level == 0 ? h2.hash(uint256(siblings[level]), current) : h2.hash(current, uint256(siblings[level]));
        }
        require(current == expected(".vectors.root"), "Merkle path vector");
    }

    function domain(uint256 chainId, address pool, address asset, uint64 version) private view returns (uint256) {
        uint256 chain = h2.hash(uint128(chainId), chainId >> 128);
        uint256 target = h2.hash(uint160(pool), uint160(asset));
        uint256 body = h2.hash(h2.hash(chain, target), version);
        return h2.hash(0x485350, body);
    }

    function testDomainAndWithdrawalBindingVectors() public view {
        uint256 digest = domain(31337, address(0x1111111111111111111111111111111111111111), address(0), 1);
        require(digest == expected(".vectors.domain"), "domain vector");
        uint256 binding = h2.hash(h2.hash(7, uint160(0x2222222222222222222222222222222222222222)), digest);
        require(binding == expected(".vectors.binding"), "binding vector");
        require(
            domain(type(uint256).max, address(type(uint160).max), address(type(uint160).max), type(uint64).max)
                == expected(".vectors.max_domain"),
            "domain boundary vector"
        );
    }

    function testNonCanonicalHashInputsFail() public view {
        (bool one,) = address(h1).staticcall(abi.encodeWithSelector(Poseidon1.hash.selector, P));
        (bool left,) = address(h2).staticcall(abi.encodeWithSelector(Poseidon2.hash.selector, P, 1));
        (bool right,) = address(h2).staticcall(abi.encodeWithSelector(Poseidon2.hash.selector, 1, P));
        require(!one && !left && !right, "noncanonical hash input accepted");
    }
}
