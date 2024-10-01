// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "OpenZeppelin/openzeppelin-contracts@4.7.3/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 _initialSupply) ERC20(_name, _symbol)  {
        _mint(msg.sender, _initialSupply);
    }
}
