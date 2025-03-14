// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


contract TestHotAuth {

    uint128 public seed;

    constructor() {
        seed = 0;
    }

    /**
     * @notice Verifies that the message hash can be signed by HOT Validators.
     * @param msg_hash The hash of the message to verify.
     * @param userPayload: (uint128 status) encoded in ABI. status < 100 raise error. status % 2 == 0 return false.
     * @return True if the message hash can be signed; false otherwise.
     *
     * @dev Used by HOT Validators to verify messages before signing.
     */
    function hot_verify(
        bytes32 msg_hash,
        bytes memory _walletId,
        bytes memory userPayload,
        bytes memory _metadata
    ) public view returns (bool) {
        (uint128 status) = abi.decode(
            userPayload,
            (uint128)
        );
        require(status > 100, "Invalid status");
        if ((status + seed) % 2 == 0) {
            return false;
        }
        return true;
    }

    function setSeed(uint128 _seed) public {
        seed = _seed;
    }
}
