// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MyToken is ERC20 {
    constructor() ERC20("MyToken", "MT") {
        _mint(msg.sender, 1000000 * (10 ** uint256(decimals())));
    }
}