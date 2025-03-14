from brownie import MetaWallet, accounts, network, Contract

VERIFY_ADDRESS = "0x1Fc58d71FC672227d4aECa7576F5f94371748234"


def main():
    account = accounts.load("deploy-viewer")  # Load the account stored securely
    print(f"Deploying from account: {account}")
    chain_id = network.chain.id
    gas_price = 10000000000  # 50 gwei in wei as an integer

    wallet = MetaWallet.deploy(
        VERIFY_ADDRESS, chain_id, {"from": account, "gas_price": gas_price}, publish_source=True
    )
    print(f"MetaWallet deployed at {wallet.address}")

    # meta_wallet = MetaWallet.at(wallet.address)
    meta_wallet = MetaWallet.at("0x42351e68420D16613BBE5A7d8cB337A9969980b4")

    print(meta_wallet.changeOwner("0x3f6a9f20a20f8FC678683f175E88B0a7D7C63D50", {"from": account, "gas_price": gas_price}))
