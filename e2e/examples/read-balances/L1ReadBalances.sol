// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract L1ReadBalances {
  mapping(string => uint256) balances;
  mapping(string => uint) lastUpdated;

  function setBitcoinAddressBalance(string calldata btcAddress, uint256 balance, uint blockHeight) public {
    // if you do this in real life, add some security checks to ensure the call is coming from the expected
    // party.  this is for example purposes only
    balances[btcAddress] = balance;
    lastUpdated[btcAddress] = blockHeight;
  }

  function getBitcoinAddressBalance(string calldata btcAddress) public view returns (uint256, uint) {
    return (balances[btcAddress], lastUpdated[btcAddress]);
  }
} 
