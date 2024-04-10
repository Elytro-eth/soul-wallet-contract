pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "@source/modules/socialRecovery/SocialRecoveryModule.sol";
import {ISocialRecovery} from "@source/modules/socialRecovery/interfaces/ISocialRecovery.sol";
import "../../soulwallet/base/SoulWalletInstence.sol";
import {UserOperationHelper} from "@soulwallet-core/test/dev/userOperationHelper.sol";
import {Execution} from "@soulwallet-core/contracts/interface/IStandardExecutor.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SocialRecoveryModuleTest is Test {
    using TypeConversion for address;
    using MessageHashUtils for bytes32;

    struct GuardianData {
        address[] guardians;
        uint256 threshold;
        uint256 salt;
    }

    SocialRecoveryModule socialRecoveryModule;
    SoulWalletInstence public soulWalletInstence;
    ISoulWallet soulWallet;
    GuardianData guarianData;
    address _owner;
    uint256 _ownerPrivateKey;
    address _newOwner;
    uint256 _newOwnerPrivateKey;
    address _guardian;
    uint256 _guardianPrivateKey;
    address _newGuardian;
    uint256 _newguardianPrivateKey;

    uint256 delayTime;
    bytes32 private constant _TYPE_HASH_SOCIAL_RECOVERY =
        keccak256("SocialRecovery(address wallet,uint256 nonce, bytes32[] newOwner)");
    bytes32 private constant _TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private DOMAIN_SEPARATOR;

    function setUp() public {
        (_owner, _ownerPrivateKey) = makeAddrAndKey("owner");
        (_newOwner, _newOwnerPrivateKey) = makeAddrAndKey("newOwner");
        (_guardian, _guardianPrivateKey) = makeAddrAndKey("guardian");
        (_newGuardian, _newguardianPrivateKey) = makeAddrAndKey("newguardian");
        socialRecoveryModule = new SocialRecoveryModule();
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _TYPEHASH,
                keccak256(bytes("SocialRecovery")),
                keccak256(bytes("1")),
                block.chainid,
                address(socialRecoveryModule)
            )
        );
    }

    function deployWallet() private {
        bytes[] memory modules = new bytes[](1);
        bytes[] memory hooks = new bytes[](0);
        bytes32[] memory owners = new bytes32[](1);
        owners[0] = address(_owner).toBytes32();

        address[] memory guardians = new address[](1);
        guardians[0] = _guardian;
        guarianData = GuardianData(guardians, 1, 0);

        bytes32 guardianHash = keccak256(abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt));
        delayTime = 1 days;

        bytes memory socialRecoveryInitData = abi.encode(guardianHash, delayTime);
        modules[0] = abi.encodePacked(socialRecoveryModule, socialRecoveryInitData);
        bytes32 salt = bytes32(0);
        soulWalletInstence = new SoulWalletInstence(address(0), owners, modules, hooks, salt);
        soulWallet = soulWalletInstence.soulWallet();
        assertEq(soulWallet.isOwner(_owner.toBytes32()), true);
        assertEq(soulWallet.isOwner(_newOwner.toBytes32()), false);
        assertEq(soulWallet.isInstalledModule(address(socialRecoveryModule)), true);
    }

    function test_deployWalletWithSocialRecoveryModule() public {
        deployWallet();
    }

    function test_executeSocialRecovery() public {
        deployWallet();
        uint256 nonce = socialRecoveryModule.walletNonce(address(soulWallet));
        bytes32[] memory newOwners = new bytes32[](1);
        newOwners[0] = address(_newOwner).toBytes32();

        bytes32 structHash = keccak256(
            abi.encode(_TYPE_HASH_SOCIAL_RECOVERY, address(soulWallet), nonce, keccak256(abi.encodePacked(newOwners)))
        );

        bytes32 typedDataHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_guardianPrivateKey, typedDataHash);
        bytes memory keySignature = abi.encodePacked(v, s, r);
        bytes memory guardianSig = abi.encodePacked(keySignature);

        socialRecoveryModule.executeReocvery(
            address(soulWallet),
            abi.encode(newOwners),
            abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt),
            guardianSig
        );

        assertEq(soulWallet.isOwner(_newOwner.toBytes32()), true);
        assertEq(soulWallet.isOwner(_owner.toBytes32()), false);
    }

    function test_updateGuardian() public {
        deployWallet();
        soulWalletInstence.entryPoint().depositTo{value: 5 ether}(address(soulWallet));
        vm.startBroadcast(_ownerPrivateKey);
        address[] memory guardians = new address[](1);
        guardians[0] = _newGuardian;
        guarianData = GuardianData(guardians, 1, 0);

        bytes32 newGuardianHash = keccak256(abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt));

        Execution[] memory executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        executions[0].data = abi.encodeWithSignature("updateGuardian(bytes32)", newGuardianHash);

        bytes memory callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);

        PackedUserOperation memory userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));

        vm.warp(block.timestamp + 1 days);

        uint256 nonce = socialRecoveryModule.walletNonce(address(soulWallet));
        bytes32[] memory newOwners = new bytes32[](1);
        newOwners[0] = address(_newOwner).toBytes32();

        bytes32 structHash = keccak256(
            abi.encode(_TYPE_HASH_SOCIAL_RECOVERY, address(soulWallet), nonce, keccak256(abi.encodePacked(newOwners)))
        );

        bytes32 typedDataHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        // should be able to recovery using new guardian
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_newguardianPrivateKey, typedDataHash);
        bytes memory keySignature = abi.encodePacked(v, s, r);
        bytes memory guardianSig = abi.encodePacked(keySignature);

        socialRecoveryModule.executeReocvery(
            address(soulWallet),
            abi.encode(newOwners),
            abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt),
            guardianSig
        );

        assertEq(soulWallet.isOwner(_newOwner.toBytes32()), true);
        assertEq(soulWallet.isOwner(_owner.toBytes32()), false);
    }

    function test_updateGuardianRevert() public {
        deployWallet();
        soulWalletInstence.entryPoint().depositTo{value: 5 ether}(address(soulWallet));
        vm.startBroadcast(_ownerPrivateKey);
        address[] memory guardians = new address[](1);
        guardians[0] = _newGuardian;
        guarianData = GuardianData(guardians, 1, 0);

        bytes32 newGuardianHash = keccak256(abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt));

        Execution[] memory executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        executions[0].data = abi.encodeWithSignature("updateGuardian(bytes32)", newGuardianHash);

        bytes memory callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);

        PackedUserOperation memory userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));

        vm.warp(block.timestamp + 1 days);

        uint256 nonce = socialRecoveryModule.walletNonce(address(soulWallet));
        bytes32[] memory newOwners = new bytes32[](1);
        newOwners[0] = address(_newOwner).toBytes32();

        bytes32 structHash = keccak256(
            abi.encode(_TYPE_HASH_SOCIAL_RECOVERY, address(soulWallet), nonce, keccak256(abi.encodePacked(newOwners)))
        );

        bytes32 typedDataHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        // should be revert using old guardian
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_guardianPrivateKey, typedDataHash);
        bytes memory keySignature = abi.encodePacked(v, s, r);
        bytes memory guardianSig = abi.encodePacked(keySignature);
        vm.expectRevert();
        socialRecoveryModule.executeReocvery(
            address(soulWallet),
            abi.encode(newOwners),
            abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt),
            guardianSig
        );

        assertEq(soulWallet.isOwner(_newOwner.toBytes32()), false);
        assertEq(soulWallet.isOwner(_owner.toBytes32()), true);
    }

    function test_updateGuardian_call_multiple() public {
        deployWallet();
        soulWalletInstence.entryPoint().depositTo{value: 5 ether}(address(soulWallet));
        vm.startBroadcast(_ownerPrivateKey);
        address[] memory guardians = new address[](1);
        guardians[0] = _newGuardian;
        guarianData = GuardianData(guardians, 1, 0);

        bytes32 newGuardianHash = keccak256(abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt));

        Execution[] memory executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        executions[0].data = abi.encodeWithSignature("updateGuardian(bytes32)", newGuardianHash);

        bytes memory callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);

        PackedUserOperation memory userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));
        ISocialRecovery.SocialRecoveryInfo memory info = socialRecoveryModule.getSocialRecoveryInfo(address(soulWallet));
        assertEq(info.pendingGuardianHash, newGuardianHash);

        executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        bytes32 guardianHash = keccak256(abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt));
        executions[0].data = abi.encodeWithSignature("updateGuardian(bytes32)", guardianHash);

        callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);

        userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));
        info = socialRecoveryModule.getSocialRecoveryInfo(address(soulWallet));

        assertEq(info.pendingGuardianHash, guardianHash);
    }

    function test_cancel_updateGuardian() public {
        deployWallet();
        soulWalletInstence.entryPoint().depositTo{value: 5 ether}(address(soulWallet));
        vm.startBroadcast(_ownerPrivateKey);
        address[] memory guardians = new address[](1);
        guardians[0] = _newGuardian;
        guarianData = GuardianData(guardians, 1, 0);

        bytes32 newGuardianHash = keccak256(abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt));

        Execution[] memory executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        executions[0].data = abi.encodeWithSignature("updateGuardian(bytes32)", newGuardianHash);

        bytes memory callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);

        PackedUserOperation memory userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));

        ISocialRecovery.SocialRecoveryInfo memory info = socialRecoveryModule.getSocialRecoveryInfo(address(soulWallet));
        assertEq(info.pendingGuardianHash, newGuardianHash);

        executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        executions[0].data = abi.encodeWithSignature("cancelUpdateGuardian()");

        callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);

        userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));

        vm.warp(block.timestamp + 1 days);

        uint256 nonce = socialRecoveryModule.walletNonce(address(soulWallet));
        bytes32[] memory newOwners = new bytes32[](1);
        newOwners[0] = address(_newOwner).toBytes32();

        bytes32 structHash = keccak256(
            abi.encode(_TYPE_HASH_SOCIAL_RECOVERY, address(soulWallet), nonce, keccak256(abi.encodePacked(newOwners)))
        );

        bytes32 typedDataHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        // should be revert using old guardian
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_guardianPrivateKey, typedDataHash);
        bytes memory keySignature = abi.encodePacked(v, s, r);
        bytes memory guardianSig = abi.encodePacked(keySignature);
        vm.expectRevert();
        socialRecoveryModule.executeReocvery(
            address(soulWallet),
            abi.encode(newOwners),
            abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt),
            guardianSig
        );

        assertEq(soulWallet.isOwner(_newOwner.toBytes32()), false);
        assertEq(soulWallet.isOwner(_owner.toBytes32()), true);
    }

    function test_updateGuardianSafePeriod() public {
        deployWallet();
        soulWalletInstence.entryPoint().depositTo{value: 5 ether}(address(soulWallet));
        vm.startBroadcast(_ownerPrivateKey);
        address[] memory guardians = new address[](1);
        guardians[0] = _guardian;
        guarianData = GuardianData(guardians, 1, 0);

        Execution[] memory executions = new Execution[](1);
        executions[0].target = address(socialRecoveryModule);
        executions[0].value = 0;
        executions[0].data = abi.encodeWithSignature("updateGuardianSafePeriod(uint256)", 2 days);

        bytes memory callData = abi.encodeWithSignature("executeBatch((address,uint256,bytes)[])", executions);
        vm.warp(block.timestamp + 1 days);

        PackedUserOperation memory userOperation = UserOperationHelper.newUserOp({
            sender: address(soulWallet),
            nonce: soulWalletInstence.entryPoint().getNonce(address(soulWallet), 0),
            initCode: hex"",
            callData: callData,
            callGasLimit: 1900000,
            verificationGasLimit: 1000000,
            preVerificationGas: 300000,
            maxFeePerGas: 10000,
            maxPriorityFeePerGas: 10000,
            paymasterAndData: hex""
        });
        userOperation.signature =
            signUserOp(userOperation, _ownerPrivateKey, address(soulWalletInstence.soulWalletDefaultValidator()));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);

        ops[0] = userOperation;

        soulWalletInstence.entryPoint().handleOps(ops, payable(_owner));

        ISocialRecovery.SocialRecoveryInfo memory info = socialRecoveryModule.getSocialRecoveryInfo(address(soulWallet));
        assertEq(info.pendingGuardianSafePeriod, 2 days);

        vm.warp(block.timestamp + 1 days);

        uint256 nonce = socialRecoveryModule.walletNonce(address(soulWallet));
        bytes32[] memory newOwners = new bytes32[](1);
        newOwners[0] = address(_newOwner).toBytes32();

        bytes32 structHash = keccak256(
            abi.encode(_TYPE_HASH_SOCIAL_RECOVERY, address(soulWallet), nonce, keccak256(abi.encodePacked(newOwners)))
        );

        bytes32 typedDataHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_guardianPrivateKey, typedDataHash);
        bytes memory keySignature = abi.encodePacked(v, s, r);
        bytes memory guardianSig = abi.encodePacked(keySignature);
        socialRecoveryModule.executeReocvery(
            address(soulWallet),
            abi.encode(newOwners),
            abi.encode(guarianData.guardians, guarianData.threshold, guarianData.salt),
            guardianSig
        );

        assertEq(soulWallet.isOwner(_newOwner.toBytes32()), true);
        assertEq(soulWallet.isOwner(_owner.toBytes32()), false);
        info = socialRecoveryModule.getSocialRecoveryInfo(address(soulWallet));
        assertEq(info.guardianSafePeriod, 2 days);
    }

    function signUserOp(PackedUserOperation memory op, uint256 _key, address _validator)
        private
        view
        returns (bytes memory signature)
    {
        bytes32 hash = soulWalletInstence.entryPoint().getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, hash.toEthSignedMessageHash());
        bytes memory opSig;
        bytes memory signatureData = abi.encodePacked(r, s, v);
        uint8 signType = 0;
        bytes4 signatureLength = bytes4(uint32(1 + signatureData.length));
        opSig = abi.encodePacked(_validator, signatureLength, signType, signatureData);
        signature = opSig;
    }
}
