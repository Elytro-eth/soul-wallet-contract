// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "../../account-abstraction/contracts/interfaces/IEntryPoint.sol";

library AccountStorage {
    bytes32 private constant ACCOUNT_SLOT =
        keccak256("soulwallet.contracts.AccountStorage");
    address internal constant SENTINEL_OWNERS = address(0x1);

    struct Layout {
        /// ┌───────────────────┐
        /// │     base data     │
        mapping(address => address) owners;
        uint256 ownerCount;
        uint256[50] __gap_0;
        /// └───────────────────┘

        mapping(address => address) modules;
        mapping(address => mapping(bytes4 => bytes4)) moduleSelectors;

        //#TODO
    }

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = ACCOUNT_SLOT;
        assembly {
            l.slot := slot
        }
    }
}
