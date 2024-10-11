from brownie import Contract
from brownie import MetaWallet


def main():
    contract_address = "0x19494579c265CDF290bC3BD61402AaF3823DF42d"
    contract = Contract.from_abi("MetaWallet", contract_address, MetaWallet.abi)
    MetaWallet.publish_source(contract)
    Contract.from_explorer(contract_address)
    print(f"Contract at {contract_address} has been verified")
