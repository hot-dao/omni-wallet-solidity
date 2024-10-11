from brownie import MetaWallet, accounts, network, Contract

VERIFY_ADDRESS = "0x1Fc58d71FC672227d4aECa7576F5f94371748234"


def main():
    account = accounts.load("deploy-viewer")  # Load the account stored securely
    print(f"Deploying from account: {account}")
    chain_id = network.chain.id
    wallet = MetaWallet.deploy(
        VERIFY_ADDRESS, chain_id, {"from": account}, publish_source=True
    )
    print(f"MetaWallet deployed at {wallet.address}")

    meta_wallet = MetaWallet.at(wallet.address)

    print(meta_wallet.changeOwner("0x3f6a9f20a20f8FC678683f175E88B0a7D7C63D50", {"from": account}))
