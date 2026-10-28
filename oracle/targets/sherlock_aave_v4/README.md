# Aave V4 Bug Bounty
- **Platform:** SHERLOCK
- **Program URL:** https://audits.sherlock.xyz/bug-bounties/300
- **Payout:** Paid Cash/USD (Up to ,500,000)
- **No Free Submissions:** Strictly PAID bounty / audit pool

## In-Scope Code & Assets
- [https://github.com/aave-dao/aave-address-book/blob/main/src/AaveV4Ethereum.sol](https://github.com/aave-dao/aave-address-book/blob/main/src/AaveV4Ethereum.sol)
- [https://github.com/aave-dao/aave-address-book/](https://github.com/aave-dao/aave-address-book/)
- [https://github.com/aave-dao/aave-address-book/blob/main/src/AaveV4Avalanche.sol](https://github.com/aave-dao/aave-address-book/blob/main/src/AaveV4Avalanche.sol)
- [https://github.com/aave/aave-v4/blob/main/docs/overview.md](https://github.com/aave/aave-v4/blob/main/docs/overview.md)

## Overview
Contests
Leaderboards
Bug Bounties
Featured
Settings
Help Center
Logout
CodeHunterExtreme

Watson

0x52Cef6e0...e2b4c899

Public Profile

Settings

Medium

0

Solo

0

Total

High

0

Solo

0

Total

$0

Total Earnings

#-

Ranking

Bug Bounties

Aave V4
Aave V4
Details

Scope

My Submission

Aave V4 Bounty Program

Aave V4 introduces a Hub-and-Spoke architecture, where the Hub manages shared liquidity and Spokes implement asset-specific supply and borrow logic. Spokes are modular components that can connect to one or more Hubs, routing user actions (supply, withdraw, borrow, repay) based on reserve configuration and capacity constraints.

The protocol retains core functionality from previous versions while extending the design to support additional mechanisms such as collateral-level risk premiums, reinvestment strategies, and more flexible risk configuration, enabling support for more heterogeneous assets and scalable system behavior.

Severity and Rewards

Vulnerabilities are classified using two factors: Impact and Likelihood. The combination of these factors determines the severity and guides the reward amount.

Severity Levels

Vulnerabilities will be classified according to the following severity levels:

Critical
Direct theft of user funds (at least 100,000 USD at risk)
Permanent freezing of user funds (>100,000 USD)
Protocol insolvency due to accounting errors
Unauthorized minting of tokens (>100 USD worth of tokens can be minted).
Permanent modification of protocol 
