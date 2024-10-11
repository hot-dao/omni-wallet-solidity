from brownie import Contract, accounts
from eth_account import Account
from eth_account.messages import SignableMessage, encode_defunct


def main():
    account = accounts.load("deploy-viewer")  # Load the account stored securely
    message = "[BscScan.com 10/10/2024 19:42:48] I, hereby verify that I am the owner/creator of the address [0x42351e68420D16613BBE5A7d8cB337A9969980b4]"
    message_bytes = message.encode('utf-8')
    sm = encode_defunct(text=message)
    signature = Account.sign_message(sm, account.private_key)
    print(f"Signed message: {signature.signature.hex()}")
