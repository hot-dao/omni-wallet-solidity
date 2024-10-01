// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMetaWallet {
    event NewTransfer(uint128 nonce, uint128 amount, bytes contract_id, bytes receiver);

    function MAX_UINT64() external pure returns (uint64);

    function NONCE_TS_SHIFT() external pure returns (uint128);

    function WITHDRAW_DELAY_SECONDS() external pure returns (uint128);

    function REFUND_DELAY_SECONDS() external pure returns (uint128);

    function NATIVE_TOKEN() external pure returns (address);

    function owner() external view returns (address);

    function verifyAddress() external view returns (address);

    function chainId() external view returns (uint64);

    function nonceMax() external view returns (uint128);

    function minTimestamp() external view returns (uint256);

    function maxTimestamp() external view returns (uint256);

    function fees() external view returns (uint256);

    function deposits(uint128) external view returns (bytes32);

    function usedNonces(uint128) external view returns (bool);

    function withdrawToken(address tokenAddress, uint256 amount) external;

    function withdrawEth(uint256 amount) external;

    function withdrawFees() external;

    function changeOwner(address newOwner) external;

    function close() external;

    function changeVerifyAddress(address _verifyAddress) external;

    function withdraw(
        uint128 nonce,
        address contract_id,
        address receiver_id,
        uint128 amount,
        bytes memory signature
    ) external payable;

    function deposit(
        bytes memory receiver,
        address contract_id,
        uint128 amount
    ) external payable;

    function deposit(bytes memory receiver) external payable;

    function hot_verify(
        bytes32 msg_hash,
        bytes memory _walletId,
        bytes memory userPayload,
        bytes memory _metadata
    ) external view returns (bool);

    function getRefundMessageHash(uint128 nonce) external view returns (bytes32);

    function getMessageRaw(
        uint128 nonce,
        bytes memory contract_id,
        bytes memory receiver_id,
        uint128 amount
    ) external view returns (bytes memory);
}
