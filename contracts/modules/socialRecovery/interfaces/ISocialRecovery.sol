// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

interface ISocialRecovery {
    struct SocialRecoveryInfo {
        bytes32 guardianHash;
        uint256 nonce;
        // guardian next
        bytes32 pendingGuardianHash;
        // `guardian next` effective time
        uint256 guardianActivateAt;
        // guardian safe period (in seconds)
        uint256 guardianSafePeriod;
        // guardian safe period next
        uint256 pendingGuardianSafePeriod;
        // `guardian safe period next` effective time
        uint256 guardianSafePeriodActivateAt;
    }

    function walletNonce(address wallet) external view returns (uint256 _nonce);

    function updateGuardianSafePeriod(uint256 newGuardianSafePeriod) external;
    function updateGuardian(bytes32 newGuardianHash) external;
    function executeReocvery(
        address wallet,
        bytes calldata newRawOwners,
        bytes calldata rawGuardian,
        bytes calldata guardianSignature
    ) external;

    enum OperationState {
        Unset,
        Waiting,
        Ready,
        Done
    }

    struct GuardianData {
        address[] guardians;
        uint256 threshold;
        uint256 salt;
    }
}
