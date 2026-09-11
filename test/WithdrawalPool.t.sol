// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Poseidon2} from "../contracts/generated/Poseidon2.sol";
import {VerificationKey} from "../contracts/generated/VerificationKey.sol";
import {WithdrawalPool} from "../contracts/WithdrawalPool.sol";

interface PoolVm {
    function deal(address account, uint256 balance) external;
    function expectRevert(bytes4 revertData) external;
    function load(address target, bytes32 slot) external view returns (bytes32 data);
    function store(address target, bytes32 slot, bytes32 value) external;
}

contract AcceptingVerifier {
    bytes32 public constant VERIFICATION_KEY_ID = VerificationKey.ID;

    fallback(bytes calldata) external returns (bytes memory) {
        return "";
    }
}

contract RejectingVerifier {
    bytes32 public constant VERIFICATION_KEY_ID = VerificationKey.ID;

    fallback(bytes calldata) external returns (bytes memory) {
        revert();
    }
}

contract WrongKeyVerifier {
    bytes32 public constant VERIFICATION_KEY_ID = bytes32(uint256(1));

    fallback(bytes calldata) external returns (bytes memory) {
        return "";
    }
}

contract ToggleVerifier {
    bytes32 public constant VERIFICATION_KEY_ID = VerificationKey.ID;
    bool private accepts = true;

    function reject() external {
        accepts = false;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        if (!accepts) revert();

        return "";
    }
}

contract RejectEther {
    receive() external payable {
        revert();
    }
}

contract ReentrantRecipient {
    WithdrawalPool private pool;
    uint256 private root;
    bool private attempted;
    bool public nestedWithdrawalSucceeded;

    function configure(WithdrawalPool pool_, uint256 root_) external {
        pool = pool_;
        root = root_;
    }

    receive() external payable {
        if (attempted) return;

        attempted = true;
        (nestedWithdrawalSucceeded,) =
            address(pool).call(abi.encodeCall(pool.withdraw, (root, 10, payable(address(this)), 11, hex"1234")));
    }
}

contract WithdrawalPoolTest {
    PoolVm private constant vm = PoolVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    Poseidon2 private poseidon;
    WithdrawalPool private pool;

    function setUp() public {
        poseidon = new Poseidon2();
        pool = new WithdrawalPool(address(new AcceptingVerifier()), address(poseidon));
        vm.deal(address(this), 2 ether);
    }

    function testDepositAppendsCommitmentAndRecordsRoot() public {
        uint256 oldRoot = pool.currentRoot();

        pool.deposit{value: 1 ether}(7);

        uint256 newRoot = pool.currentRoot();
        require(newRoot != oldRoot, "root did not change");
        require(pool.nextLeafIndex() == 1, "leaf index did not advance");
        require(pool.isKnownRoot(newRoot), "new root not recorded");
        require(address(pool).balance == 1 ether, "deposit not held");
    }

    function testDepositRejectsWrongValue() public {
        vm.expectRevert(WithdrawalPool.WrongDepositValue.selector);
        pool.deposit{value: 1 ether - 1}(7);
    }

    function testDepositRejectsNoncanonicalCommitment() public {
        uint256 modulus = pool.FIELD_MODULUS();

        vm.expectRevert(WithdrawalPool.NoncanonicalFieldValue.selector);
        pool.deposit{value: 1 ether}(modulus);
    }

    function testRootHistoryKeepsOnlyLatestThirtyTwoRoots() public {
        vm.deal(address(this), 40 ether);

        uint256 initialRoot = pool.currentRoot();

        pool.deposit{value: 1 ether}(1);

        uint256 firstRoot = pool.currentRoot();

        for (uint256 commitment = 2; commitment <= 32; ++commitment) {
            pool.deposit{value: 1 ether}(commitment);
        }

        require(!pool.isKnownRoot(initialRoot), "initial root did not expire");
        require(pool.isKnownRoot(firstRoot), "first root expired early");

        pool.deposit{value: 1 ether}(33);

        require(!pool.isKnownRoot(firstRoot), "first root did not expire");
        require(pool.isKnownRoot(pool.currentRoot()), "latest root missing");
    }

    function testDepositRejectsLeafBeyondDepthEightTree() public {
        bytes32 slot;
        uint256 packed = uint256(vm.load(address(pool), slot));
        packed = (packed & ~uint256(type(uint32).max)) | 256;

        vm.store(address(pool), slot, bytes32(packed));

        vm.expectRevert(WithdrawalPool.TreeFull.selector);
        pool.deposit{value: 1 ether}(257);
    }

    function testWithdrawalRecordsNullifierAndPaysRecipient() public {
        pool.deposit{value: 1 ether}(7);

        uint256 root = pool.currentRoot();
        address payable recipient = payable(address(0xbeef));

        pool.withdraw(root, 9, recipient, 10, hex"1234");

        require(pool.nullifierSpent(9), "nullifier not recorded");
        require(recipient.balance == 1 ether, "recipient not paid");
        require(address(pool).balance == 0, "pool balance not reduced");
    }

    function testProtocolDomainBindsChainPoolNativeAssetAndVersion() public view {
        uint256 chain = poseidon.hash(uint128(block.chainid), block.chainid >> 128);
        uint256 deployment = poseidon.hash(uint160(address(pool)), 0);
        uint256 body = poseidon.hash(poseidon.hash(chain, deployment), 1);
        uint256 expected = poseidon.hash(0x485350, body);

        require(pool.protocolDomain() == expected, "wrong protocol domain");
    }

    function testInvalidProofCannotSpendNullifierOrFunds() public {
        WithdrawalPool rejectingPool = new WithdrawalPool(address(new RejectingVerifier()), address(poseidon));
        vm.deal(address(this), 1 ether);

        rejectingPool.deposit{value: 1 ether}(7);

        uint256 root = rejectingPool.currentRoot();
        address payable recipient = payable(address(0xbeef));

        vm.expectRevert(WithdrawalPool.InvalidProof.selector);
        rejectingPool.withdraw(root, 9, recipient, 10, hex"1234");

        require(!rejectingPool.nullifierSpent(9), "invalid proof spent nullifier");
        require(recipient.balance == 0, "invalid proof paid recipient");
        require(address(rejectingPool).balance == 1 ether, "invalid proof moved funds");
    }

    function testUnknownRootFailsBeforeProofVerification() public {
        WithdrawalPool rejectingPool = new WithdrawalPool(address(new RejectingVerifier()), address(poseidon));

        vm.expectRevert(WithdrawalPool.UnknownRoot.selector);
        rejectingPool.withdraw(123, 9, payable(address(0xbeef)), 10, hex"1234");
    }

    function testSpentNullifierFailsBeforeProofVerification() public {
        ToggleVerifier toggle = new ToggleVerifier();
        WithdrawalPool togglePool = new WithdrawalPool(address(toggle), address(poseidon));
        vm.deal(address(this), 2 ether);

        togglePool.deposit{value: 1 ether}(7);

        uint256 root = togglePool.currentRoot();

        togglePool.withdraw(root, 9, payable(address(0xbeef)), 10, hex"1234");
        togglePool.deposit{value: 1 ether}(8);
        toggle.reject();

        vm.expectRevert(WithdrawalPool.NullifierAlreadySpent.selector);
        togglePool.withdraw(root, 9, payable(address(0xbeef)), 10, hex"1234");
    }

    function testWithdrawalRejectsZeroRecipient() public {
        pool.deposit{value: 1 ether}(7);

        uint256 root = pool.currentRoot();

        vm.expectRevert(WithdrawalPool.ZeroRecipient.selector);
        pool.withdraw(root, 9, payable(address(0)), 10, hex"1234");
    }

    function testPaymentFailureDoesNotSpendNullifier() public {
        pool.deposit{value: 1 ether}(7);

        uint256 root = pool.currentRoot();
        address payable recipient = payable(address(new RejectEther()));

        vm.expectRevert(WithdrawalPool.PaymentFailed.selector);
        pool.withdraw(root, 9, recipient, 10, hex"1234");

        require(!pool.nullifierSpent(9), "failed payment spent nullifier");
        require(address(pool).balance == 1 ether, "failed payment moved funds");
    }

    function testRecipientCannotReenterWithAnotherNullifier() public {
        pool.deposit{value: 1 ether}(7);
        pool.deposit{value: 1 ether}(8);

        uint256 root = pool.currentRoot();
        ReentrantRecipient recipient = new ReentrantRecipient();

        recipient.configure(pool, root);
        pool.withdraw(root, 9, payable(address(recipient)), 10, hex"1234");

        require(!recipient.nestedWithdrawalSucceeded(), "nested withdrawal succeeded");
        require(address(recipient).balance == 1 ether, "recipient drained extra deposit");
        require(pool.nullifierSpent(9), "outer nullifier missing");
        require(!pool.nullifierSpent(10), "nested nullifier spent");
    }

    function testConstructorRejectsDependenciesWithoutCode() public {
        vm.expectRevert(WithdrawalPool.InvalidDependency.selector);
        new WithdrawalPool(address(0), address(poseidon));

        address accepting = address(new AcceptingVerifier());

        vm.expectRevert(WithdrawalPool.InvalidDependency.selector);
        new WithdrawalPool(accepting, address(0));
    }

    function testConstructorRejectsWrongVerificationKey() public {
        address wrong = address(new WrongKeyVerifier());

        vm.expectRevert(WithdrawalPool.WrongVerificationKey.selector);
        new WithdrawalPool(wrong, address(poseidon));
    }
}
