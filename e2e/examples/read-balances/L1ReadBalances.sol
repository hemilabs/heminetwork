// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface CrossDomainMessenger {
    function sendMessage(address _target, bytes memory _message, uint32 _minGasLimit) external payable;
}

contract L1ReadBalances {
  function getBitcoinAddressBalance(string calldata btcAddress) public view returns (uint256 balance) {
    CrossDomainMessenger cdm = CrossDomainMessenger('0xe50ea86676B29448a4e586511d8920105cEd1159');
    uint256 balance = cdm.sendMessage(address('blahblahblahreplaceme'), _message, _minGasLimit);
    return balance;
  }
}
