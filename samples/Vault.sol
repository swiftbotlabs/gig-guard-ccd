// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external {
        require(tx.origin == msg.sender, "no contracts");
        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
