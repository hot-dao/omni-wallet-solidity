from brownie import Contract
from brownie import MetaWallet


def main():
    contract_address = "0x279B4fe359746C96Cb9F6B676A2f832A959f3755"
    contract = Contract.from_abi("MetaWallet", contract_address, MetaWallet.abi)
    MetaWallet.publish_source(contract)
    Contract.from_explorer(contract_address)
    print(f"Contract at {contract_address} has been verified")
