// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Halo2Verifier} from "../contracts/generated/Halo2Verifier.sol";
import {Poseidon2} from "../contracts/generated/Poseidon2.sol";

interface Vm {
    function readFile(string calldata path) external view returns (string memory data);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory value);
    function cool(address target) external;
}

contract SpikeTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    // use the same bounded budget for valid and invalid proofs.
    uint256 private constant VERIFIER_GAS_LIMIT = 1_000_000;
    uint256 private constant FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant POSEIDON_1_2 =
        7853200120776062878684798364095072458815029376092732009249414926327459813530;

    Halo2Verifier private verifier;
    Poseidon2 private poseidon;
    bytes private validCalldata;
    bytes private wrongInstanceCalldata;
    bytes private corruptedCalldata;

    event log_named_uint(string key, uint256 val);

    function setUp() public {
        verifier = new Halo2Verifier();
        poseidon = new Poseidon2();
        string memory proofJson = vm.readFile("artifacts/proof.json");
        validCalldata = vm.parseJsonBytes(proofJson, ".calldata");
        wrongInstanceCalldata = vm.parseJsonBytes(proofJson, ".wrong_instance_calldata");
        corruptedCalldata = vm.parseJsonBytes(proofJson, ".corrupted_calldata");
    }

    function testValidProofAndVerifierLimits() public {
        address target = address(verifier);
        bytes memory input = validCalldata;
        vm.cool(target);
        uint256 gasBefore = gasleft();
        (bool success, bytes memory output) = target.staticcall{gas: VERIFIER_GAS_LIMIT}(input);
        uint256 gasUsed = gasBefore - gasleft();

        require(success, "valid proof rejected");
        require(output.length == 0, "unexpected verifier output");
        uint256 runtimeBytes = target.code.length;
        require(runtimeBytes > 0, "verifier has no code");
        require(runtimeBytes <= 24576, "verifier exceeds EIP-170");
        emit log_named_uint("Verifier runtime bytes", runtimeBytes);
        emit log_named_uint("Verifier creation bytes", type(Halo2Verifier).creationCode.length);
        // The measurement includes STATICCALL overhead and return-data handling.
        emit log_named_uint("Cold valid proof call gas (includes call overhead)", gasUsed);
    }

    function testWrongPublicInstanceRejected() public view {
        require(keccak256(wrongInstanceCalldata) != keccak256(validCalldata), "unchanged instance fixture");
        (bool success,) = address(verifier).staticcall{gas: VERIFIER_GAS_LIMIT}(wrongInstanceCalldata);
        require(!success, "wrong public instance accepted");
    }

    function testCorruptedProofRejected() public view {
        require(keccak256(corruptedCalldata) != keccak256(validCalldata), "unchanged corrupt fixture");
        (bool success,) = address(verifier).staticcall{gas: VERIFIER_GAS_LIMIT}(corruptedCalldata);
        require(!success, "corrupted proof accepted");
    }

    function testPoseidonKnownVector() public view {
        require(poseidon.hash(1, 2) == POSEIDON_1_2, "Poseidon vector mismatch");
    }

    function testPoseidonChangedInputDiffers() public view {
        require(poseidon.hash(1, 3) != POSEIDON_1_2, "changed Poseidon input has same hash");
        require(poseidon.hash(2, 1) != POSEIDON_1_2, "swapped Poseidon inputs have same hash");
    }

    function testPoseidonRejectsNonCanonicalInputs() public view {
        (bool firstAccepted,) =
            address(poseidon).staticcall(abi.encodeWithSelector(Poseidon2.hash.selector, FR_MODULUS, 2));
        require(!firstAccepted, "non-canonical first input accepted");
        (bool secondAccepted,) =
            address(poseidon).staticcall(abi.encodeWithSelector(Poseidon2.hash.selector, 1, FR_MODULUS));
        require(!secondAccepted, "non-canonical second input accepted");
        (bool maxAccepted,) =
            address(poseidon).staticcall(abi.encodeWithSelector(Poseidon2.hash.selector, type(uint256).max, 2));
        require(!maxAccepted, "maximum uint256 input accepted");
    }
}
