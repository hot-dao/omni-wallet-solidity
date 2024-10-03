// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/**
 * @title Omni Token Wallet
 * @dev This contract was audited by Hacken (https://hacken.io) on 24/09/2024.
 *
 * Audited by: Hacken
 * Date: 24/09/2024
 * Audit: https://example.com/audit-report
 */

import "OpenZeppelin/openzeppelin-contracts@4.7.3/contracts/token/ERC20/utils/SafeERC20.sol";
import "OpenZeppelin/openzeppelin-contracts@4.7.3/contracts/token/ERC20/IERC20.sol";
import "OpenZeppelin/openzeppelin-contracts@4.7.3/contracts/utils/cryptography/ECDSA.sol";
import "./RlpEncode.sol";

contract MetaWallet {
    using SafeERC20 for IERC20;

    uint64 public constant MAX_UINT64 = 2 ** 64 - 1;
    uint128 public constant NONCE_TS_SHIFT = 1000000000000;

    uint128 public constant WITHDRAW_DELAY_SECONDS = 500;
    uint128 public constant REFUND_DELAY_SECONDS = 600;

    address constant NATIVE_TOKEN = address(0);

    address public owner;
    address public verifyAddress;
    uint64 public chainId;
    uint128 public nonceMax;

    uint256 public minTimestamp;
    uint256 public maxTimestamp;
    uint256 public fees;

    mapping(uint128 => bytes32) public deposits;

    mapping(uint128 => bool) public usedNonces;

    event NewTransfer(uint128 nonce, uint128 amount, bytes contract_id, bytes receiver);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function.");
        _;
    }

    /**
     * @notice Withdraw ERC20 tokens from the contract to the owner's address.
     * @dev Only callable by the owner.
     * @param tokenAddress The address of the ERC20 token to withdraw.
     * @param amount The amount of tokens to withdraw.
     */
    function withdrawToken(address tokenAddress, uint256 amount)
    public
    onlyOwner
    {
        IERC20(tokenAddress).safeTransfer(owner, amount);
    }

    /**
     * @notice Withdraw Ether from the contract to the owner's address.
     * @dev Only callable by the owner.
     * @param amount The amount of Ether to withdraw (in wei).
     */
    function withdrawEth(uint256 amount) public onlyOwner {
        (bool success,) = payable(owner).call{value: amount}("");
        require(success, "Transfer failed.");
    }

    /**
     * @notice Withdraw accumulated fees from the contract to the owner's address.
     * @dev Only callable by the owner. Resets the fees to zero after withdrawal.
     */
    function withdrawFees() public onlyOwner {
        (bool success,) = payable(owner).call{value: fees}("");
        require(success, "Transfer failed.");
        fees = 0;
    }

    /**
     * @notice Transfer ownership of the contract to a new address.
     * @dev Only callable by the current owner.
     * @param newOwner The address of the new owner.
     */
    function changeOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    /**
     * @notice Close the contract by setting the maximum timestamp to the current time.
     * @dev Only callable by the owner. Prevents new deposits after closure.
     */
    function close() public onlyOwner {
        maxTimestamp = block.timestamp;
    }

    /**
     * @notice Fallback function to receive Ether.
     */
    receive() external payable {}

    /**
     * @notice Initializes the MetaWallet contract.
     * @param _verifyAddress The address used to verify signatures.
     * @param _chainId The chain ID of the blockchain network.
     */
    constructor(
        address _verifyAddress,
        uint64 _chainId
    ) payable {
        owner = msg.sender;
        verifyAddress = _verifyAddress;
        chainId = _chainId;
        minTimestamp = block.timestamp;
        maxTimestamp = MAX_UINT64;
        fees = 0;
    }

    /**
     * @notice Change the address used for signature verification.
     * @dev Only callable by the owner.
     * @param _verifyAddress The new address to use for verifying signatures.
     */
    function changeVerifyAddress(address _verifyAddress) public onlyOwner {
        verifyAddress = _verifyAddress;
    }

    /**
     * @notice Execute a withdrawal from the contract to the specified receiver.
     * @param nonce The unique nonce associated with the withdrawal.
     * @param contract_id The address of the token contract (use address(0) for native token).
     * @param receiver_id The address of the receiver.
     * @param amount The amount to withdraw.
     * @param signature The signature proving authorization for the withdrawal.
     *
     * @dev Verifies the provided signature and ensures that the nonce is valid.
     *      Increments the fees by the amount of Ether sent with the transaction.
     */
    function withdraw(
        uint128 nonce,
        address contract_id,
        address receiver_id,
        uint128 amount,
        bytes memory signature
    ) public payable {
        uint128 nonce_ts = nonce / NONCE_TS_SHIFT;
        require(nonce_ts > minTimestamp, "Nonce timestamp too low");
        require(nonce_ts < maxTimestamp, "Nonce timestamp too high");
        require(
            nonce_ts > uint128(block.timestamp) - WITHDRAW_DELAY_SECONDS,
            "Nonce time is expired, you can make a refund"
        ); // this transfer can only be refunded

        require(!usedNonces[nonce], "Nonce already used");
        require(
            verify(
                nonce,
                abi.encodePacked(contract_id),
                abi.encodePacked(receiver_id),
                amount,
                signature
            ),
            "Invalid signature"
        );
        usedNonces[nonce] = true;
        if (contract_id == NATIVE_TOKEN) {
            (bool success,) = payable(receiver_id).call{value: amount}("");
            require(success, "Transfer failed.");
        } else {
            IERC20(contract_id).safeTransfer(receiver_id, amount);
        }
        fees += msg.value;
    }

    /**
     * @notice Deposit tokens into the contract on behalf of a receiver.
     * @param receiver The receiver's identifier (in bytes).
     * @param contract_id The address of the token contract.
     * @param amount The amount of tokens to deposit.
     *
     * @dev Transfers tokens from the sender to the contract and records the deposit.
     *      Increments the fees by the amount of Ether sent with the transaction.
     */
    function deposit(
        bytes memory receiver,
        address contract_id,
        uint128 amount
    ) public payable {
        require(block.timestamp < maxTimestamp, "Contract is closed");

        IERC20(contract_id).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );
        uint128 nonce = uint128(block.timestamp) * NONCE_TS_SHIFT + nonceMax;
        emit NewTransfer(nonce, amount, abi.encodePacked(contract_id), receiver);

        bytes32 origMessageHash = getMessageHash(
            nonce,
            abi.encodePacked(contract_id),
            receiver,
            amount
        );

        deposits[nonce] = origMessageHash;
        nonceMax += 1;
        fees += msg.value;
    }

    /**
     * @notice Deposit Ether into the contract on behalf of a receiver.
     * @param receiver The receiver's identifier (in bytes).
     *
     * @dev Records the deposit of Ether and emits a NewTransfer event.
     */
    function deposit(bytes memory receiver) public payable {
        require(block.timestamp < maxTimestamp, "Contract is closed");
        uint128 nonce = uint128(block.timestamp) * NONCE_TS_SHIFT + nonceMax;

        bytes32 origMessageHash = getMessageHash(
            nonce,
            abi.encodePacked(NATIVE_TOKEN),
            receiver,
            uint128(msg.value)
        );

        deposits[nonce] = origMessageHash;
        nonceMax += 1;
        emit NewTransfer(nonce, uint128(msg.value), abi.encodePacked(NATIVE_TOKEN), receiver);
    }

    /**
     * @notice Verifies that the message hash can be signed by HOT Validators.
     * @param msg_hash The hash of the message to verify.
     * @param userPayload: (uint128 nonce, uint8 type_) encoded in ABI. Type_ = 0 for deposit, 1 for refund
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
        (uint128 nonce, uint8 type_) = abi.decode(
            userPayload,
            (uint128, uint8)
        );

        if (type_ == 0) {
            // Verify deposit: valid and exists
            require(deposits[nonce] == msg_hash, "Deposit hash mismatch");
        } else {
            // Verify refund: nonce is old to deposit, not expired for refund, was not used and hash is valid
            require(!usedNonces[nonce], "Nonce already used");

            uint128 nonce_ts = nonce / NONCE_TS_SHIFT;
            require(nonce_ts > minTimestamp, "Nonce time is too low");
            require(nonce_ts < maxTimestamp, "Nonce time is too high");
            require(
                nonce_ts < uint128(block.timestamp) - REFUND_DELAY_SECONDS,
                "Nonce time is not expired"
            ); // this transfer can be refunded

            bytes32 origMessageHash = getRefundMessageHash(nonce);
            require(origMessageHash == msg_hash, "Refund hash mismatch");
        }
        return true;
    }

    /**
     * @notice Verifies the signature of a message.
     * @param nonce The unique nonce associated with the message.
     * @param contract_id The encoded contract address.
     * @param receiver_id The encoded receiver address.
     * @param amount The amount involved in the transaction.
     * @param signature The signature to verify.
     * @return True if the signature is valid; false otherwise.
     *
     * @dev Uses ECDSA to recover the signer's address and compares it with the verifyAddress.
     */
    function verify(
        uint128 nonce,
        bytes memory contract_id,
        bytes memory receiver_id,
        uint128 amount,
        bytes memory signature
    ) internal view returns (bool) {
        bytes32 messageHash = getMessageHash(
            nonce,
            contract_id,
            receiver_id,
            amount
        );
        return ECDSA.recover(messageHash, signature) == verifyAddress;
    }

    /**
     * @notice Generates the SHA-256 hash of the raw message data.
     * @param nonce The unique nonce associated with the message.
     * @param contract_id The encoded contract address.
     * @param receiver_id The encoded receiver address.
     * @param amount The amount involved in the transaction.
     * @return The SHA-256 hash of the message data.
     */
    function getMessageHash(
        uint128 nonce,
        bytes memory contract_id,
        bytes memory receiver_id,
        uint128 amount
    ) internal view returns (bytes32) {
        return sha256(getMessageRaw(nonce, contract_id, receiver_id, amount));
    }

    /**
     * @notice Generates the SHA-256 hash of the raw refund message data.
     * @param nonce The unique nonce associated with the refund.
     * @return The SHA-256 hash of the refund message data.
     */
    function getRefundMessageHash(uint128 nonce)
    public
    view
    returns (bytes32)
    {
        return sha256(getRefundMessageRaw(nonce));
    }

    /**
     * @notice Constructs the raw data for a refund message.
     * @param nonce The unique nonce associated with the refund.
     * @return The RLP-encoded raw refund message data.
     */
    function getRefundMessageRaw(uint128 nonce)
    internal
    view
    returns (bytes memory)
    {
        bytes[] memory rlpList = new bytes[](2);
        rlpList[0] = RLPEncode.encodeUint(nonce, 16);
        rlpList[1] = RLPEncode.encodeUint(chainId, 8);
        return RLPEncode.encodeList(rlpList);
    }

    /**
     * @notice Constructs the raw data for a message.
     * @param nonce The unique nonce associated with the message.
     * @param contract_id The encoded contract address.
     * @param receiver_id The encoded receiver address.
     * @param amount The amount involved in the transaction.
     * @return The RLP-encoded raw message data.
     */
    function getMessageRaw(
        uint128 nonce,
        bytes memory contract_id,
        bytes memory receiver_id,
        uint128 amount
    ) public view returns (bytes memory) {
        bytes[] memory rlpList = new bytes[](5);
        rlpList[0] = RLPEncode.encodeUint128(nonce, 16);
        rlpList[1] = RLPEncode.encodeUint64(chainId, 8);
        rlpList[2] = RLPEncode.encodeBytes(contract_id);
        rlpList[3] = RLPEncode.encodeBytes(receiver_id);
        rlpList[4] = RLPEncode.encodeUint128(amount, 16);

        return RLPEncode.encodeList(rlpList);
    }
}