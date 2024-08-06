// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ReadBalances {
  function getBitcoinAddressBalance(string calldata btcAddress) public view returns (uint256 balance) {
    bytes memory converted = bytes(btcAddress);
    (bool ok, bytes memory out) = address(0x40).staticcall(converted);
    require(ok, "Static call to btcBalAddr precompile (0x40) contract failed");
    
    return uint64(bytes8(out));
  }
}
