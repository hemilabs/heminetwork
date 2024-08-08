// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract L1ReadBalances {
  mapping(string => uint256) balances;

  function setBitcoinAddressBalance(string calldata btcAddress, uint256 balance) public {
    // protect, ensure coming from CrossDomainMessenger
    balances[btcAddress] = balance;
    return;
  }

  function getBitcoinAddressBalance(string calldata btcAddress) public view returns (uint256) {
    uint256 balance = balances[btcAddress];
    return balance;
  }
} 
