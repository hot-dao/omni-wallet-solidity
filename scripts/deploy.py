from brownie import MetaWallet, accounts, network, Contract

VERIFY_ADDRESS = "0x1Fc58d71FC672227d4aECa7576F5f94371748234"


def main():
    account = accounts.load("deployer")  # Load the account stored securely
    print(f"Deploying from account: {account}")
    chain_id = network.chain.id
    wallet = MetaWallet.deploy(
        VERIFY_ADDRESS, chain_id, {"from": account}, publish_source=True
    )
    print(f"MetaWallet deployed at {wallet.address}")
