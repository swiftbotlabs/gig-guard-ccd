// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SafeVault {
    mapping(address => uint256) public bal;
    bool private locked;
    modifier nonReentrant() { require(!locked, "reentrant"); locked = true; _; locked = false; }
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external nonReentrant {
        uint256 amount = bal[msg.sender];
        bal[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}
