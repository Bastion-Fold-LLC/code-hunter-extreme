// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title GuardedVault
 * @notice Clean, secure vault following Checks-Effects-Interactions pattern.
 * State balance is zeroed BEFORE any external interaction, preventing reentrancy.
 */
contract GuardedVault {
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "ReentrancyGuard: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance to withdraw");

        // Effect before Interaction
        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
