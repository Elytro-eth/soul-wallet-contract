// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "../interfaces/ISocialRecovery.sol";
import "../../../interfaces/ISoulWallet.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

abstract contract BaseSocialRecovery is ISocialRecovery, EIP712 {
    using ECDSA for bytes32;

    uint256 internal constant _GUARDIAN_PERIOD_MIN = 1 seconds;
    uint256 internal constant _GUARDIAN_PERIOD_MAX = 30 days;

    event ApproveHash(address indexed guardian, bytes32 hash);
    event RejectHash(address indexed guardian, bytes32 hash);

    event GuardianChanged(address indexed wallet, bytes32 guardianHash);
    event GuardianSafePeriodChanged(address indexed wallet, uint256 guardianSafePeriod);
    event GuardianUpdated(address indexed wallet, bytes32 guardianHash, uint256 effectAt);
    event UpdateGuardianCanceled(address indexed wallet);
    event UpdateGuardianSafePeriod(address indexed wallet, uint256 guardianSafePeriod, uint256 effectAt);
    event RecoveryExecuted(address indexed wallet, uint256 nonce, bytes rawOwners);

    error UN_EXPECTED_OPERATION_STATE(address wallet, bytes32 recoveryId, bytes32 expectedStates);
    error HASH_ALREADY_APPROVED();
    error GUARDIAN_SIGNATURE_INVALID();
    error NOT_INITIALIZED();
    error INVALID_TIME_RANGE();
    error HASH_ALREADY_REJECTED();

    mapping(address => SocialRecoveryInfo) socialRecoveryInfo;
    mapping(bytes32 => uint256) approvedHashes;
    uint256 internal constant _DONE_TIMESTAMP = uint256(1);

    bytes32 private constant _TYPE_HASH_SOCIAL_RECOVERY =
        keccak256("SocialRecovery(address wallet,uint256 nonce, bytes32[] newOwner)");

    function walletNonce(address wallet) public view override returns (uint256 _nonce) {
        return socialRecoveryInfo[wallet].nonce;
    }

    function updateGuardian(bytes32 newGuardianHash) external {
        address wallet = _msgSender();
        _autoSetupGuardian(wallet);
        SocialRecoveryInfo storage _socialRecoveryInfo = socialRecoveryInfo[wallet];
        _socialRecoveryInfo.pendingGuardianHash = newGuardianHash;
        uint256 _guardianActivateAt = uint256(block.timestamp) + _socialRecoveryInfo.guardianSafePeriod;
        _socialRecoveryInfo.guardianActivateAt = _guardianActivateAt;
        emit GuardianUpdated(wallet, newGuardianHash, _guardianActivateAt);
    }

    function updateGuardianSafePeriod(uint256 newGuardianSafePeriod) external {
        address wallet = _msgSender();
        _autoSetupGuardian(wallet);
        _guardianSafePeriodGuard(newGuardianSafePeriod);
        SocialRecoveryInfo storage _socialRecoveryInfo = socialRecoveryInfo[wallet];
        _socialRecoveryInfo.pendingGuardianSafePeriod = newGuardianSafePeriod;
        uint256 _guardianSafePeriodActivateAt = uint256(block.timestamp) + _socialRecoveryInfo.guardianSafePeriod;
        _socialRecoveryInfo.guardianSafePeriodActivateAt = _guardianSafePeriodActivateAt;
        emit UpdateGuardianSafePeriod(wallet, newGuardianSafePeriod, _guardianSafePeriodActivateAt);
    }

    function cancelUpdateGuardian() external {
        address wallet = _msgSender();
        _autoSetupGuardian(wallet);
        SocialRecoveryInfo storage _socialRecoveryInfo = socialRecoveryInfo[wallet];
        _socialRecoveryInfo.pendingGuardianHash = bytes32(0);
        _socialRecoveryInfo.guardianActivateAt = 0;
        emit UpdateGuardianCanceled(wallet);
    }

    modifier onlyInitialized(address wallet) {
        if (socialRecoveryInfo[wallet].guardianSafePeriod == 0) {
            revert NOT_INITIALIZED();
        }
        _;
    }

    function _guardianSafePeriodGuard(uint256 safePeriodGuard) private pure {
        if (safePeriodGuard < _GUARDIAN_PERIOD_MIN || safePeriodGuard > _GUARDIAN_PERIOD_MAX) {
            revert INVALID_TIME_RANGE();
        }
    }

    function _autoSetupGuardian(address wallet) private onlyInitialized(wallet) {
        SocialRecoveryInfo storage _socialRecoveryInfo = socialRecoveryInfo[wallet];
        require(_socialRecoveryInfo.guardianSafePeriod > 0);

        uint256 nowTime = uint256(block.timestamp);
        if (_socialRecoveryInfo.guardianActivateAt > 0 && _socialRecoveryInfo.guardianActivateAt <= nowTime) {
            bytes32 _pendingGuardianHash = _socialRecoveryInfo.pendingGuardianHash;
            _socialRecoveryInfo.guardianHash = _pendingGuardianHash;
            _socialRecoveryInfo.guardianActivateAt = 0;
            _socialRecoveryInfo.pendingGuardianHash = bytes32(0);
            emit GuardianChanged(wallet, _pendingGuardianHash);
        }
        if (
            _socialRecoveryInfo.guardianSafePeriodActivateAt > 0
                && _socialRecoveryInfo.guardianSafePeriodActivateAt <= nowTime
        ) {
            _guardianSafePeriodGuard(_socialRecoveryInfo.pendingGuardianSafePeriod);
            uint256 _pendingGuardianSafePeriod = _socialRecoveryInfo.pendingGuardianSafePeriod;
            _socialRecoveryInfo.guardianSafePeriod = _pendingGuardianSafePeriod;
            _socialRecoveryInfo.guardianSafePeriodActivateAt = 0;
            _socialRecoveryInfo.pendingGuardianSafePeriod = 0;
            emit GuardianSafePeriodChanged(wallet, _pendingGuardianSafePeriod);
        }
    }

    /**
     * @dev Considering that not all contract are EIP-1271 compatible
     */
    function approveHash(bytes32 hash) external {
        bytes32 key = _approveKey(msg.sender, hash);
        if (approvedHashes[key] == 1) {
            revert HASH_ALREADY_APPROVED();
        }
        approvedHashes[key] = 1;
        emit ApproveHash(msg.sender, hash);
    }

    function rejectHash(bytes32 hash) external {
        bytes32 key = _approveKey(msg.sender, hash);
        if (approvedHashes[key] == 0) {
            revert HASH_ALREADY_REJECTED();
        }
        approvedHashes[key] = 0;
        emit RejectHash(msg.sender, hash);
    }

    function executeReocvery(
        address wallet,
        bytes calldata newRawOwners,
        bytes calldata rawGuardian,
        bytes calldata guardianSignature
    ) external override {
        _autoSetupGuardian(wallet);

        bytes32 guardianHash = _getGuardianHash(rawGuardian);
        _checkGuardianHash(wallet, guardianHash);
        uint256 currentNonce = walletNonce(wallet);
        _verifyGuardianSignature(wallet, currentNonce, newRawOwners, rawGuardian, guardianSignature);

        _recoveryOwner(wallet, newRawOwners);

        _increaseNonce(wallet);
        emit RecoveryExecuted(wallet, currentNonce, newRawOwners);
    }

    function _recoveryOwner(address wallet, bytes calldata newRawOwners) internal {
        bytes32[] memory owners = abi.decode(newRawOwners, (bytes32[]));
        ISoulWallet soulwallet = ISoulWallet(payable(wallet));
        soulwallet.resetOwners(owners);
    }

    function _verifyGuardianSignature(
        address wallet,
        uint256 nonce,
        bytes calldata newRawOwners,
        bytes calldata rawGuardian,
        bytes calldata guardianSignature
    ) internal view {
        address[] memory newOwners = abi.decode(newRawOwners, (address[]));
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(_TYPE_HASH_SOCIAL_RECOVERY, wallet, nonce, keccak256(abi.encodePacked(newOwners))))
        );
        GuardianData memory guardianData = _parseGuardianData(rawGuardian);
        uint256 guardiansLen = guardianData.guardians.length;

        // for extreme cases
        if (guardianData.threshold > guardiansLen) guardianData.threshold = guardiansLen;

        /*
        keySignature structure:
        ┌──────────────┬──────────────┬──────────────┬──────────────┐
        │              │              │              │              │
        │   signature1 │   signature2 │      ...     │   signatureN │
        │              │              │              │              │
        └──────────────┴──────────────┴──────────────┴──────────────┘

        one signature structure:
        ┌──────────┬──────────────┬──────────┬────────────────┐
        │          │              │          │                │
        │    v     │       s      │   r      │  dynamic data  │
        │  bytes1  │bytes4|bytes32│  bytes32 │     dynamic    │
        │  (must)  │  (optional)  │(optional)│   (optional)   │
        └──────────┴──────────────┴──────────┴────────────────┘

        data logic description:
            v = 0
                EIP-1271 signature
                s: bytes4 Length of signature data
                r: no set
                dynamic data: signature data

            v = 1
                approved hash
                r: no set
                s: no set

            v = 2
                skip
                s: bytes4 skip times
                r: no set

            v > 2
                EOA signature
                r: bytes32
                s: bytes32

        ==============================================================
        Note: Why is the definition of 's' unstable (bytes4|bytes32)?
              If 's' is defined as bytes32, it incurs lower read costs( shr(224, calldataload() -> calldataload() ). However, to prevent arithmetic overflow, all calculations involving 's' need to be protected against overflow, which leads to higher overhead.
              If, in certain cases, 's' is defined as bytes4 (up to 4GB), there is no need to perform overflow prevention under the current known block gas limit.
              Overall, it is more suitable for both Layer1 and Layer2.
     */
        uint8 v;
        uint256 cursor = 0;

        uint256 skipCount = 0;
        uint256 guardianSignatureLen = guardianSignature.length;
        for (uint256 i = 0; i < guardiansLen;) {
            if (cursor >= guardianSignatureLen) break;
            bytes calldata signatures = guardianSignature[cursor:];
            assembly ("memory-safe") {
                v := byte(0, calldataload(signatures.offset))
            }

            if (v == 0) {
                /*
                v = 0
                    EIP-1271 signature
                    s: bytes4 Length of signature data
                    r: no set
                    dynamic data: signature data
             */
                uint256 cursorEnd;
                assembly ("memory-safe") {
                    // read 's' as bytes4
                    let sigLen := shr(224, calldataload(add(signatures.offset, 1)))

                    cursorEnd := add(5, sigLen) // see Note line 223
                    cursor := add(cursor, cursorEnd)
                }

                bytes calldata dynamicData = signatures[5:cursorEnd];
                {
                    (bool success, bytes memory result) = guardianData.guardians[i].staticcall(
                        abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, dynamicData)
                    );
                    require(
                        success && result.length == 32
                            && abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector),
                        "contract signature invalid"
                    );
                }
            } else if (v == 1) {
                /*
                v = 1
                    approved hash
                    r: no set
                    s: no set
             */
                bytes32 key = _approveKey(guardianData.guardians[i], digest);
                require(approvedHashes[key] == 1, "hash not approved");
                unchecked {
                    cursor += 1; // see Note line 223
                }
            } else if (v == 2) {
                /*
                v = 2
                    skip
                    s: bytes4 skip times
                    r: no set
             */
                assembly ("memory-safe") {
                    // read 's' as bytes4
                    let skipTimes := shr(224, calldataload(add(signatures.offset, 1)))

                    i := add(i, skipTimes) // see Note line 223
                    skipCount := add(skipCount, add(skipTimes, 1))
                    cursor := add(cursor, 5)
                }
            } else {
                /*
                v > 2
                    EOA signature
             */
                bytes32 s;
                bytes32 r;
                assembly ("memory-safe") {
                    s := calldataload(add(signatures.offset, 1))
                    r := calldataload(add(signatures.offset, 33))

                    cursor := add(cursor, 65) // see Note line 223
                }
                require(guardianData.guardians[i] == ECDSA.recover(digest, v, r, s), "guardian signature invalid");
            }
            unchecked {
                i++; // see Note line 223
            }
        }
        if (guardiansLen - skipCount < guardianData.threshold) {
            revert GUARDIAN_SIGNATURE_INVALID();
        }
    }

    function _approveKey(address sender, bytes32 hash) private pure returns (bytes32 key) {
        key = keccak256(abi.encode(sender, hash));
    }

    function _checkGuardianHash(address wallet, bytes32 guardianHash) internal view {
        if (socialRecoveryInfo[wallet].guardianHash != guardianHash) {
            revert("Invalid guardian hash");
        }
    }
    /**
     * @notice This function is executed during module uninstallation.
     * @dev Even during uninstallation, the nonce data is not cleared to prevent replay of historical data once reinstall this moudule agian.
     * The nonce is permanently incrementing. Other variables can be reset.
     * @param wallet The address of the wallet for which the social recovery info is to be cleared.
     */

    function _clearWalletSocialRecoveryInfo(address wallet) internal {
        _increaseNonce(wallet);
        socialRecoveryInfo[wallet].guardianHash = bytes32(0);
        socialRecoveryInfo[wallet].pendingGuardianHash = bytes32(0);
        socialRecoveryInfo[wallet].guardianActivateAt = 0;
        socialRecoveryInfo[wallet].guardianSafePeriod = 0;
        socialRecoveryInfo[wallet].pendingGuardianSafePeriod = 0;
        socialRecoveryInfo[wallet].guardianSafePeriodActivateAt = 0;
    }

    function _setGuardianHash(address wallet, bytes32 guardianHash) internal {
        socialRecoveryInfo[wallet].guardianHash = guardianHash;
    }

    function _setGuardianSafePeriod(address wallet, uint256 guardianSafePeriod) internal {
        socialRecoveryInfo[wallet].guardianSafePeriod = guardianSafePeriod;
    }

    function _getGuardianHash(bytes calldata rawGuardian) internal pure returns (bytes32 guardianHash) {
        return keccak256(rawGuardian);
    }

    function _msgSender() internal view virtual returns (address payable) {
        return payable(msg.sender);
    }

    function _increaseNonce(address wallet) internal {
        uint256 _newNonce = walletNonce(wallet) + 1;
        socialRecoveryInfo[wallet].nonce = _newNonce;
    }

    /**
     * @param   wallet  the address to recover
     * @param   nonce  Add a nonce for the hash operation. When recovery is cancelled or the guardian is modified, the nonce can automatically invalidate the previous operation
     * @return  bytes32  return recoveryId
     */
    function hashOperation(address wallet, uint256 nonce, bytes memory data) internal view virtual returns (bytes32) {
        return keccak256(abi.encode(wallet, nonce, data, address(this), block.chainid));
    }

    function _encodeStateBitmap(OperationState operationState) internal pure returns (bytes32) {
        return bytes32(1 << uint8(operationState));
    }

    function _parseGuardianData(bytes calldata rawGuardian) internal pure returns (GuardianData memory) {
        (address[] memory guardians, uint256 threshold, uint256 salt) =
            abi.decode(rawGuardian, (address[], uint256, uint256));
        return GuardianData({guardians: guardians, threshold: threshold, salt: salt});
    }
}
