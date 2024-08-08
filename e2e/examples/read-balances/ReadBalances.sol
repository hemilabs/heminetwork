// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface CrossDomainMessenger {
    function sendMessage(address _target, bytes calldata _message, uint32 _minGasLimit) external;
}

interface L1ReadBalances {
  function setBitcoinAddressBalance(string calldata btcAddress, uint256 balance) external;
} 

contract ReadBalances {
  function getBitcoinAddressBalance(string calldata btcAddress) public view returns (uint256 balance) {
    bytes memory converted = bytes(btcAddress);
    (bool ok, bytes memory out) = address(0x40).staticcall(converted);
    require(ok, "Static call to btcBalAddr precompile (0x40) contract failed");
    
    return uint64(bytes8(out));
  }

  function sendBitcoinAddressBalanceToL1(address l1ReadBalancesAddress, string calldata btcAddress) public {
    uint256 balance = getBitcoinAddressBalance(btcAddress);
    CrossDomainMessenger cdm = CrossDomainMessenger(0x4200000000000000000000000000000000000007);



    cdm.sendMessage(
      l1ReadBalancesAddress, 
      abi.encodeCall(L1ReadBalances.setBitcoinAddressBalance, 
      (
        btcAddress,
        balance
      )),
      1000000
    );
  } 
}
