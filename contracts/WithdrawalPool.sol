// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerificationKey} from "./generated/VerificationKey.sol";

// test-only because the public setup seed lets anyone forge proofs

interface IHalo2Verifier {
    function VERIFICATION_KEY_ID() external view returns (bytes32);
}

interface IPoseidon2 {
    function hash(uint256 left, uint256 right) external view returns (uint256);
}

contract WithdrawalPool {
    uint256 public constant DENOMINATION = 1 ether;
    uint256 public constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant TREE_CAPACITY = 256;
    uint256 public constant ROOT_HISTORY_SIZE = 32;
    uint256 public constant PROTOCOL_VERSION = 1;

    address public immutable verifier;
    IPoseidon2 public immutable poseidon;

    uint32 public nextLeafIndex;
    uint8 private currentRootIndex;
    uint8 private rootCount;
    uint256[8] private zeros;
    uint256[8] private filledSubtrees;
    uint256[32] private roots;
    mapping(uint256 => bool) public nullifierSpent;
    uint256 private withdrawalStatus = 1;

    error InvalidDependency();
    error WrongVerificationKey();
    error WrongDepositValue();
    error NoncanonicalFieldValue();
    error TreeFull();
    error UnknownRoot();
    error NullifierAlreadySpent();
    error ZeroRecipient();
    error InvalidProof();
    error PaymentFailed();
    error ReentrantWithdrawal();

    event Deposit(uint256 indexed commitment, uint256 indexed leafIndex, uint256 root);
    event Withdrawal(uint256 indexed nullifierHash, address indexed recipient);

    modifier nonReentrantWithdrawal() {
        if (withdrawalStatus != 1) revert ReentrantWithdrawal();

        withdrawalStatus = 2;
        _;
        withdrawalStatus = 1;
    }

    constructor(address verifier_, address poseidon_) {
        if (verifier_.code.length == 0 || poseidon_.code.length == 0) {
            revert InvalidDependency();
        }

        try IHalo2Verifier(verifier_).VERIFICATION_KEY_ID() returns (bytes32 id) {
            if (id != VerificationKey.ID) revert WrongVerificationKey();
        } catch {
            revert WrongVerificationKey();
        }

        verifier = verifier_;
        poseidon = IPoseidon2(poseidon_);

        uint256 zero;

        for (uint256 level; level < 8; ++level) {
            zeros[level] = zero;
            filledSubtrees[level] = zero;
            zero = poseidon.hash(zero, zero);
        }

        roots[0] = zero;
        rootCount = 1;
    }

    function currentRoot() public view returns (uint256) {
        return roots[currentRootIndex];
    }

    function isKnownRoot(uint256 root) public view returns (bool) {
        for (uint256 index; index < rootCount; ++index) {
            if (roots[index] == root) return true;
        }

        return false;
    }

    function protocolDomain() public view returns (uint256) {
        uint256 chain = poseidon.hash(uint128(block.chainid), block.chainid >> 128);
        uint256 deployment = poseidon.hash(uint160(address(this)), 0);
        uint256 body = poseidon.hash(poseidon.hash(chain, deployment), PROTOCOL_VERSION);

        return poseidon.hash(0x485350, body);
    }

    function deposit(uint256 commitment) external payable returns (uint256 leafIndex) {
        if (msg.value != DENOMINATION) revert WrongDepositValue();
        if (commitment >= FIELD_MODULUS) revert NoncanonicalFieldValue();

        leafIndex = nextLeafIndex;

        if (leafIndex == TREE_CAPACITY) revert TreeFull();

        nextLeafIndex = uint32(leafIndex + 1);

        uint256 current = commitment;
        uint256 index = leafIndex;

        for (uint256 level; level < 8; ++level) {
            if (index & 1 == 0) {
                filledSubtrees[level] = current;
                current = poseidon.hash(current, zeros[level]);
            } else {
                current = poseidon.hash(filledSubtrees[level], current);
            }

            index >>= 1;
        }

        currentRootIndex = uint8((uint256(currentRootIndex) + 1) % ROOT_HISTORY_SIZE);
        roots[currentRootIndex] = current;

        if (rootCount < ROOT_HISTORY_SIZE) ++rootCount;

        emit Deposit(commitment, leafIndex, current);
    }

    function withdraw(
        uint256 root,
        uint256 nullifierHash,
        address payable recipient,
        uint256 binding,
        bytes calldata proof
    ) external nonReentrantWithdrawal {
        if (!isKnownRoot(root)) revert UnknownRoot();
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadySpent();
        if (recipient == address(0)) revert ZeroRecipient();

        bytes memory input = bytes.concat(
            abi.encode(root, nullifierHash, uint256(uint160(address(recipient))), protocolDomain(), binding), proof
        );
        (bool valid, bytes memory result) = verifier.staticcall(input);

        if (!valid || result.length != 0) revert InvalidProof();

        nullifierSpent[nullifierHash] = true;

        (bool paid,) = recipient.call{value: DENOMINATION}("");

        if (!paid) revert PaymentFailed();

        emit Withdrawal(nullifierHash, recipient);
    }
}
