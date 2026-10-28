// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EtherStore
 * @notice Classic vulnerable vault exhibiting reentrancy in withdraw().
 * State variable `balances[msg.sender]` is zeroed AFTER the external call,
 * allowing recursive calls to drain contract funds.
 */
contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance to withdraw");

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
