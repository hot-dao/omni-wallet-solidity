from brownie import TestHotAuth, accounts, network, Contract


def main():
    account = accounts.load("hachaton-acc")  # Load the account stored securely

    wallet = TestHotAuth.at("0xc9D4Ad7C99e3B321bCE1dd683D80B668bec28F33")
    tx = wallet.setSeed(1, {"from": account})
    print(tx.txid)
    return
    print(f"Deploying from account: {account}")
    wallet = TestHotAuth.deploy({"from": account}, publish_source=True)
    print(f"TestHotAuth deployed at {wallet.address}")
