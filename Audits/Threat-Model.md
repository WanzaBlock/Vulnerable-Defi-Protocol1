# Threat Model: Vulnerable DeFi Protocol

## Executive Summary

This document outlines the threat landscape for a DeFi protocol consisting of three core components:
- **VulnerableVault**: ERC-4626-style vault for asset management
- **VulnerableRewardsDistributor**: Staking rewards mechanism
- **VulnerableGovernance**: On-chain governance system

**SECURITY NOTE**: These contracts are DELIBERATELY VULNERABLE for educational purposes and must NEVER be deployed to mainnet.

---

## 1. Asset Classification

### Critical Assets
| Asset | Location | Value | Impact if Compromised |
|-------|----------|-------|----------------------|
| User deposits | VulnerableVault | Variable (ETH equiv) | Complete loss of user funds |
| Staked tokens | RewardsDistributor | Variable | Loss of staked capital |
| Reward tokens | RewardsDistributor | Fixed pool | Unauthorized distribution |
| Governance power | Governance contract | N/A | Malicious proposal execution |
| Admin privileges | All contracts | N/A | Full protocol control |

### Data Assets
- User balances and shares
- Voting records
- Reward calculations
- Fee accumulations

---

## 2. Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│                  Users (EOAs)                   │
│  • Depositors  • Stakers  • Voters             │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│            Smart Contract Layer                 │
│  ┌──────────────┐  ┌──────────────┐            │
│  │ Vault        │  │ Rewards      │            │
│  │              │  │ Distributor  │            │
│  └──────────────┘  └──────────────┘            │
│  ┌──────────────────────────────────┐          │
│  │      Governance                  │          │
│  └──────────────────────────────────┘          │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│            External Contracts                   │
│  • ERC-20 Tokens  • Flash Loan Providers       │
└─────────────────────────────────────────────────┘
```

### Trust Assumptions
1. **Users trust** the protocol contracts to secure their funds
2. **Contracts trust** external ERC-20 tokens behave correctly
3. **Protocol assumes** users won't collude for attacks
4. **Admin expected** to act in protocol's best interest (VIOLATED by lack of access controls)

---

## 3. Attack Vectors by Component

### 3.1 VulnerableVault

#### Attack Vector 1: Reentrancy Attack
**Severity**: CRITICAL  
**CVSS Score**: 10.0

**Attack Flow**:
```
1. Attacker deploys malicious ERC-20 token
2. Attacker deposits malicious token to vault
3. During withdraw(), malicious token's transfer() calls back to vault
4. Attacker calls withdraw() again before shares are burned
5. Attacker receives assets multiple times for same shares
```

**Vulnerable Code**:
```solidity
function withdraw(uint256 shares) external returns (uint256 assets) {
    assets = convertToAssets(shares);
    // VULNERABILITY: External call before state update
    require(asset.transfer(msg.sender, assets), "Transfer failed");
    _burn(msg.sender, shares);  // State updated AFTER external call
    totalAssets -= assets;
}
```

**Exploitability**: High - requires malicious token or compromised token contract  
**Impact**: Complete drain of vault assets  
**Detection**: Monitor for multiple withdrawals in single transaction

#### Attack Vector 2: First Depositor / Inflation Attack
**Severity**: HIGH  
**CVSS Score**: 8.5

**Attack Flow**:
```
1. Attacker is first depositor, deposits 1 wei
2. Attacker receives 1 share
3. Attacker donates large amount (e.g., 10e18) via donateToVault()
4. Share price now: 10e18 assets per 1 share
5. Victim deposits 20e18
6. Victim receives: (20e18 * 1) / 10e18 = 2 shares (SHOULD BE 20e18)
7. Attacker withdraws, stealing victim's funds
```

**Vulnerable Code**:
```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
    if (supply == 0) return assets;  // First depositor gets 1:1
    return (assets * supply) / totalAssets;  // Manipulable denominator
}

function donateToVault(uint256 amount) external {
    totalAssets += amount;  // Direct manipulation allowed
}
```

**Exploitability**: High - requires capital but simple to execute  
**Impact**: Loss of victim deposits proportional to attack investment  
**Detection**: Monitor first deposits and unusual donation patterns

#### Attack Vector 3: Precision Loss / Rounding Exploits
**Severity**: MEDIUM  
**CVSS Score**: 6.5

**Attack Details**:
- Integer division rounds down
- Small deposits can result in 0 shares minted
- Attacker can repeatedly deposit small amounts, receiving assets without burning shares

**Vulnerable Code**:
```solidity
// If assets * supply < totalAssets, result rounds to 0
return (assets * supply) / totalAssets;
```

#### Attack Vector 4: Access Control Bypass
**Severity**: CRITICAL  
**CVSS Score**: 9.8

**Attack Flow**:
```
1. Anyone can call collectFees() and steal accumulated fees
2. Anyone can call setPerformanceFee() and set to 100% (10000 bp)
3. Anyone can call emergencyWithdraw() and drain vault
```

**Vulnerable Functions**:
```solidity
function collectFees() external {
    // No access control!
    uint256 feeAmount = (totalAssets * performanceFee) / 10000;
    asset.transfer(msg.sender, feeAmount);
}

function emergencyWithdraw() external {
    // Anyone can drain!
    asset.transfer(msg.sender, asset.balanceOf(address(this)));
}
```

**Exploitability**: Trivial - anyone can call  
**Impact**: Complete loss of vault funds  
**Detection**: Monitor for unauthorized admin function calls

---

### 3.2 VulnerableRewardsDistributor

#### Attack Vector 5: Flash Loan Voting Power Manipulation
**Severity**: CRITICAL  
**CVSS Score**: 9.5

**Attack Flow**:
```
1. Attacker takes flash loan for staking tokens
2. Stakes tokens in same transaction
3. Calls claim() to receive inflated rewards
4. Unstakes and repays flash loan
5. Net profit: Rewards - flash loan fee
```

**Vulnerable Code**:
```solidity
function earned(address account) public view returns (uint256) {
    return (balances[account] * (rewardPerToken() - userRewardPerTokenPaid[account])) / 1e18;
}
// Uses current balance, not time-weighted
```

**Exploitability**: High - requires flash loan access  
**Impact**: Theft of reward pool  
**Detection**: Monitor for stake/claim/unstake in same block

#### Attack Vector 6: Reentrancy in claim()
**Severity**: HIGH  
**CVSS Score**: 8.0

**Attack Flow**:
```
1. Attacker calls claim() with malicious token
2. Malicious token's transfer() calls back to claim()
3. rewards[attacker] not yet set to 0
4. Attacker claims multiple times
```

**Vulnerable Code**:
```solidity
function claim() external {
    uint256 reward = rewards[msg.sender];
    require(rewardToken.transfer(msg.sender, reward), "Transfer failed");
    rewards[msg.sender] = 0;  // State update AFTER external call
}
```

#### Attack Vector 7: Reward Rate Manipulation
**Severity**: HIGH  
**CVSS Score**: 7.8

**Attack Details**:
- Anyone can call setRewardRate() 
- Attacker can set rate to maximum before claiming
- Attacker can set rate to 0 to grief other users

**Vulnerable Code**:
```solidity
function setRewardRate(uint256 newRate) external {
    rewardRate = newRate;  // No access control!
}
```

---

### 3.3 VulnerableGovernance

#### Attack Vector 8: Flash Loan Governance Attack
**Severity**: CRITICAL  
**CVSS Score**: 9.0

**Attack Flow**:
```
1. Attacker borrows governance tokens via flash loan
2. Creates malicious proposal (e.g., transfer all funds to attacker)
3. Votes on proposal with borrowed tokens
4. Proposal passes due to inflated voting power
5. Executes proposal immediately (no timelock)
6. Returns flash loan
```

**Vulnerable Code**:
```solidity
function castVote(uint256 proposalId, bool support) external {
    uint256 votes = governanceToken.balanceOf(msg.sender);  // Current balance!
    // No snapshot, no timelock before execution
}
```

**Exploitability**: High if governance tokens available via flash loans  
**Impact**: Complete protocol takeover  
**Detection**: Monitor for large token transfers before votes

#### Attack Vector 9: No Timelock Protection
**Severity**: HIGH  
**CVSS Score**: 8.2

**Attack Details**:
- Proposals execute immediately after voting ends
- No time for users to exit before malicious execution
- No time for security review

**Vulnerable Code**:
```solidity
function execute(uint256 proposalId) external {
    require(block.number > proposal.endBlock, "Voting not ended");
    // Immediate execution - no delay!
    proposal.target.call(proposal.data);
}
```

#### Attack Vector 10: Zero Quorum Requirement
**Severity**: MEDIUM  
**CVSS Score**: 6.0

**Attack Details**:
- Quorum set to 0 by default
- Single token holder can pass proposals
- Anyone can change quorum to 0

**Vulnerable Code**:
```solidity
uint256 public quorum = 0;  // No minimum participation

function setQuorum(uint256 newQuorum) external {
    quorum = newQuorum;  // Anyone can set to 0!
}
```

---

## 4. Attack Chain Scenarios

### Scenario 1: Total Protocol Drain
```
1. Attacker calls setPerformanceFee(10000) on Vault [No access control]
2. Attacker calls collectFees() to steal all assets [No access control]
3. OR attacker calls emergencyWithdraw() [No access control]
Result: 100% loss of user funds
Time: Single transaction
Cost to attacker: Gas fees only
```

### Scenario 2: Governance Takeover → Fund Drain
```
1. Attacker flash loans governance tokens
2. Creates proposal to call emergencyWithdraw() on Vault
3. Votes with flash loan tokens (passes with 1 vote due to zero quorum)
4. Executes immediately (no timelock)
5. Drains vault to attacker address
6. Returns flash loan
Result: 100% loss of user funds
Time: Single transaction
Cost to attacker: Flash loan fee
```

### Scenario 3: Inflation Attack → Reentrancy
```
1. Attacker deposits 1 wei as first depositor
2. Donates 100 ETH to inflate share price
3. Victim deposits 50 ETH, receives 0.5 shares (precision loss)
4. Attacker uses reentrancy to withdraw multiple times
5. Drains remaining funds
Result: 100% loss including victim's deposit
Time: Multiple transactions
Cost to attacker: 100 ETH (recoverable)
```

---

## 5. Mitigations Summary

| Vulnerability | Fix | Implementation |
|--------------|-----|----------------|
| Reentrancy | ReentrancyGuard + CEI pattern | Use OpenZeppelin's ReentrancyGuard, update state before external calls |
| First depositor | Virtual shares | Add VIRTUAL_SHARES constant, modify share calculations |
| Precision loss | Higher precision math | Use fixed-point arithmetic with 1e18 multiplier |
| Access control | Ownable + modifiers | Implement onlyOwner, role-based access control |
| Flash loan voting | Vote snapshots | Use EIP-5805 checkpointing, require staking period |
| No timelock | Timelock contract | Add 2-day delay between queue and execution |
| Zero quorum | Minimum quorum | Enforce minimum participation requirement |

---

## 6. Security Recommendations

### Immediate (P0)
1. ✅ Add ReentrancyGuard to all state-changing functions
2. ✅ Implement proper access controls (Ownable/AccessControl)
3. ✅ Add timelock to governance
4. ✅ Implement vote snapshots

### Short-term (P1)
5. ✅ Add virtual shares to vault
6. ✅ Implement minimum stake period
7. ✅ Remove donation function
8. ✅ Add quorum requirements

### Long-term (P2)
9. Consider upgradeability pattern (with proper security)
10. Implement pause mechanism for emergencies
11. Add multi-sig for admin operations
12. Comprehensive monitoring and alerting

---

## 7. Testing Requirements

### Unit Tests Required
- [ ] Reentrancy attack scenarios
- [ ] Access control on all protected functions
- [ ] Flash loan attack simulations
- [ ] Precision loss edge cases
- [ ] First depositor attacks

### Integration Tests Required
- [ ] Multi-contract attack chains
- [ ] Governance proposal lifecycle
- [ ] Cross-contract reentrancy
- [ ] Economic attack simulations

### Fuzzing Targets
- Share calculation functions
- Reward distribution logic
- Voting power calculations
- Edge cases in arithmetic

---

## 8. Monitoring & Detection

### On-chain Indicators
- Multiple calls to same function in single tx (reentrancy)
- First deposit followed by large donation (inflation)
- Large token transfers before votes (flash loan)
- Unauthorized admin function calls (access control)
- Stake/unstake in same block (flash loan)

### Off-chain Monitoring
- TVL sudden drops
- Abnormal share price movements  
- Unusual governance activity
- Flash loan usage patterns

---
