import hashlib

import pytest
import rlp
from brownie import MetaWallet, MockERC20, accounts, network, Wei, chain  # noqa: F401
from eth_abi import encode
from eth_keys import keys
from rlp.sedes import BigEndianInt, Binary


class DepositProof(rlp.Serializable):
    fields = [
        ("nonce", BigEndianInt(16)),
        ("chain_id", BigEndianInt(8)),
        ("contract_id_bytes", Binary()),
        ("receiver_id_bytes", Binary()),
        ("amount", BigEndianInt(16)),
    ]


class RefundProof(rlp.Serializable):
    fields = [
        ("nonce", BigEndianInt(16)),
        ("chain_id", BigEndianInt(8)),
    ]


private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
NONCE_TS_SHIFT = 1000000000000
NATIVE_TOKEN = "0x0000000000000000000000000000000000000000"


def test_meta_wallet_deploy():
    owner = accounts[0]
    verify_address = accounts[1]
    chain_id = network.chain.id
    current_time = chain.time()
    meta_wallet = MetaWallet.deploy(verify_address.address, chain_id, {"from": owner})

    assert meta_wallet.owner() == owner.address
    assert meta_wallet.verifyAddress() == verify_address.address
    assert meta_wallet.chainId() == chain_id
    assert meta_wallet.minTimestamp() >= current_time
    assert meta_wallet.maxTimestamp() == 2**64 - 1


def test_deposit_eth():
    owner = accounts[0]
    verify_address = accounts[1]
    receiver = b"\x12\x34\x56\x78"
    chain_id = network.chain.id
    meta_wallet = MetaWallet.deploy(verify_address.address, chain_id, {"from": owner})

    deposit_amount = Wei("1 ether")
    tx = meta_wallet.deposit(receiver, {"from": owner, "value": deposit_amount})

    event = tx.events["NewTransfer"]
    assert event["amount"] == deposit_amount
    assert event["contract_id"] == NATIVE_TOKEN


def test_withdraw_eth():
    owner = accounts[0]
    chain_id = network.chain.id

    private_key = keys.PrivateKey(private_key_bytes=bytes.fromhex(private_key_hex))
    verify_address = private_key.public_key.to_checksum_address()

    meta_wallet = MetaWallet.deploy(
        verify_address, chain_id, {"from": owner, "value": "10 ether"}
    )
    chain.sleep(600)
    chain.mine()

    deposit_amount = 1_000
    receiver_account = accounts[1]
    nonce = chain.time() * NONCE_TS_SHIFT

    proof = DepositProof(
        nonce,
        chain_id,
        bytes.fromhex(NATIVE_TOKEN[2:]),
        bytes.fromhex(receiver_account.address[2:]),
        int(deposit_amount),
    )
    encoded_data = rlp.encode(proof)
    proof_hash = hashlib.sha256(encoded_data).digest()
    signature = private_key.sign_msg_hash(proof_hash)

    r = int.from_bytes(signature[:32], byteorder="big")
    s = int.from_bytes(signature[32:64], byteorder="big")
    v = signature[64] + 27
    signature_bytes = (
        r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big") + bytes([v])
    )

    balance_before = receiver_account.balance()

    meta_wallet.withdraw(
        nonce,
        NATIVE_TOKEN,
        receiver_account.address,
        deposit_amount,
        signature_bytes,
        {"from": owner, "value": 1},
    )
    balance_after = receiver_account.balance()

    assert balance_after - balance_before == deposit_amount

    with pytest.raises(Exception):
        random_signature = bytes(65)
        meta_wallet.withdraw(
            nonce,
            NATIVE_TOKEN,
            receiver_account.address,
            deposit_amount,
            random_signature,
            {"from": owner, "value": 1},
        )


def test_deposit_token():
    owner = accounts[0]
    verify_address = accounts[1]
    receiver = b"\x12\x34\x56\x78"
    chain_id = network.chain.id
    meta_wallet = MetaWallet.deploy(verify_address.address, chain_id, {"from": owner})

    token = MockERC20.deploy("Test Token", "TTK", 18, int(1e21), {"from": owner})
    token.transfer(owner, int(1e20), {"from": owner})

    token.approve(meta_wallet.address, int(1e20), {"from": owner})

    deposit_amount = int(1e18)
    tx = meta_wallet.deposit(receiver, token.address, deposit_amount, {"from": owner})

    event = tx.events["NewTransfer"]
    assert event["amount"] == deposit_amount
    assert event["contract_id"] == token.address


def test_withdraw_token():
    owner = accounts[0]
    chain_id = network.chain.id

    private_key = keys.PrivateKey(private_key_bytes=bytes.fromhex(private_key_hex))
    verify_address = private_key.public_key.to_checksum_address()

    meta_wallet = MetaWallet.deploy(
        verify_address, chain_id, {"from": owner, "value": "10 ether"}
    )

    token = MockERC20.deploy("Test Token", "TTK", 18, int(1e21), {"from": owner})
    token.transfer(owner, int(1e20), {"from": owner})
    token.approve(meta_wallet.address, int(1e20), {"from": owner})
    deposit_amount = int(1e18)  # 1 TTK
    receiver_bytes = b"\x12\x34\x56\x78"
    meta_wallet.deposit(receiver_bytes, token.address, deposit_amount, {"from": owner})
    chain.sleep(600)
    chain.mine()

    deposit_amount = 1_000
    receiver_account = accounts[1]
    nonce = chain.time() * NONCE_TS_SHIFT

    proof = DepositProof(
        nonce,
        chain_id,
        bytes.fromhex(token.address[2:]),
        bytes.fromhex(receiver_account.address[2:]),
        int(deposit_amount),
    )
    encoded_data = rlp.encode(proof)
    proof_hash = hashlib.sha256(encoded_data).digest()
    signature = private_key.sign_msg_hash(proof_hash)

    r = int.from_bytes(signature[:32], byteorder="big")
    s = int.from_bytes(signature[32:64], byteorder="big")
    v = signature[64] + 27
    signature_bytes = (
        r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big") + bytes([v])
    )

    balance_before = token.balanceOf(meta_wallet.address)

    meta_wallet.withdraw(
        nonce,
        token.address,
        receiver_account.address,
        deposit_amount,
        signature_bytes,
        {"from": owner},
    )
    balance_after = token.balanceOf(meta_wallet.address)
    assert balance_before - balance_after == deposit_amount


def test_only_owner_functions():
    owner = accounts[0]
    non_owner = accounts[1]
    verify_address = accounts[2]
    meta_wallet = MetaWallet.deploy(
        verify_address.address,
        network.chain.id,
        {"from": owner, "value": Wei("1 ether")},
    )

    with pytest.raises(Exception):
        meta_wallet.withdrawEth(Wei("1 ether"), {"from": non_owner})

    with pytest.raises(Exception):
        meta_wallet.withdrawFees({"from": non_owner})

    with pytest.raises(Exception):
        meta_wallet.changeOwner(non_owner.address, {"from": non_owner})

    meta_wallet.withdrawEth(Wei("1 ether"), {"from": owner})
    meta_wallet.withdrawFees({"from": owner})
    meta_wallet.changeOwner(non_owner.address, {"from": owner})


def test_hot_verify():
    owner = accounts[0]
    private_key = keys.PrivateKey(private_key_bytes=bytes.fromhex(private_key_hex))
    verify_address = private_key.public_key.to_checksum_address()
    meta_wallet = MetaWallet.deploy(
        verify_address,
        network.chain.id,
        {"from": owner, "value": Wei("1 ether")},
    )
    chain.sleep(10)
    chain.mine()

    nonce = chain.time() * NONCE_TS_SHIFT
    refund_hash = hashlib.sha256(rlp.encode(RefundProof(nonce, network.chain.id))).digest()

    # Refund invalid - too early
    encoded_nonce = encode(["uint128", "uint8"], [nonce, 1])
    with pytest.raises(Exception):
        meta_wallet.hot_verify(
            refund_hash, bytes(0), encoded_nonce, bytes(0), {"from": owner}
        )

    chain.sleep(1000)
    chain.mine()

    # Refund success
    meta_wallet.hot_verify(refund_hash, bytes(0), encoded_nonce, bytes(0), {"from": owner})


def test_close_contract():
    owner = accounts[0]
    verify_address = accounts[1]
    meta_wallet = MetaWallet.deploy(
        verify_address.address,
        network.chain.id,
        {"from": owner, "value": Wei("1 ether")},
    )

    meta_wallet.close({"from": owner})

    with pytest.raises(Exception):
        meta_wallet.deposit(b"\x12\x34", {"from": owner, "value": Wei("1 ether")})

    token = MockERC20.deploy("Test Token", "TTK", 18, int(1e21), {"from": owner})
    token.transfer(owner, int(1e20), {"from": owner})
    token.approve(meta_wallet.address, int(1e20), {"from": owner})
    with pytest.raises(Exception):
        meta_wallet.deposit(b"\x12\x34", token.address, 1e18, {"from": owner})
