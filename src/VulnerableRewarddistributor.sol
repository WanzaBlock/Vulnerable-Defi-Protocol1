// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title VulnerableRewardsDistributor
 * @notice DELIBERATELY VULNERABLE - DO NOT USE IN PRODUCTION
 * @dev Contains vulnerabilities:
 * 1. Reentrancy in claim()
 * 2. Integer overflow/underflow (if using older Solidity)
 * 3. Unchecked external calls
 * 4. Front-running vulnerability
 * 5. Reward calculation manipulation
 */
contract VulnerableRewardsDistributor {
    IERC20 public immutable rewardToken;
    IERC20 public immutable stakingToken;

    uint256 public rewardRate; // Rewards per second
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;

    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public balances;

    uint256 public totalStaked;

    // VULNERABILITY: No access control
    address public owner;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);

    constructor(address _stakingToken, address _rewardToken, uint256 _rewardRate) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        rewardRate = _rewardRate;
        owner = msg.sender;
        lastUpdateTime = block.timestamp;
    }

    /**
     * @notice VULNERABILITY: Reward calculation can be manipulated
     */
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }

        // VULNERABILITY: Can be manipulated by flash loan attacks
        return rewardPerTokenStored +
            (((block.timestamp - lastUpdateTime) * rewardRate * 1e18) / totalStaked);
    }

    /**
     * @notice VULNERABILITY: Can be front-run
     */
    function earned(address account) public view returns (uint256) {
        // VULNERABILITY: No protection against stale data
        return (balances[account] *
            (rewardPerToken() - userRewardPerTokenPaid[account])) / 1e18 +
            rewards[account];
    }

    /**
     * @notice Update reward state
     */
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;

        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    /**
     * @notice VULNERABILITY: No reentrancy protection
     */
    function stake(uint256 amount) external updateReward(msg.sender) {
        require(amount > 0, "Cannot stake 0");

        // VULNERABILITY: State updated after external call
        stakingToken.transferFrom(msg.sender, address(this), amount);

        totalStaked += amount;
        balances[msg.sender] += amount;

        emit Staked(msg.sender, amount);
    }

    /**
     * @notice VULNERABILITY 1: Reentrancy in claim
     * @dev External call before state update
     */
    function claim() external updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");

        // VULNERABILITY: External call BEFORE state update
        require(rewardToken.transfer(msg.sender, reward), "Transfer failed");

        // State update happens AFTER external call - allows reentrancy!
        rewards[msg.sender] = 0;

        emit RewardPaid(msg.sender, reward);
    }

    /**
     * @notice VULNERABILITY: Unchecked return value
     */
    function withdraw(uint256 amount) external updateReward(msg.sender) {
        require(amount > 0, "Cannot withdraw 0");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        totalStaked -= amount;

        // VULNERABILITY: Return value not checked
        stakingToken.transfer(msg.sender, amount);

        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @notice VULNERABILITY 4: No access control
     */
    function setRewardRate(uint256 newRate) external {
        // VULNERABILITY: Anyone can set the reward rate!
        rewardRate = newRate;
    }

    /**
     * @notice VULNERABILITY 5: Flash loan attack vector
     * @dev Allows manipulation of totalStaked within a single transaction
     */
    function emergencyWithdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // VULNERABILITY: No reward calculation, can be exploited with flash loans
        balances[msg.sender] = 0;
        totalStaked -= balance;

        // User loses rewards but can manipulate totalStaked for others
        stakingToken.transfer(msg.sender, balance);
    }

    /**
     * @notice VULNERABILITY: No access control on funding
     */
    function notifyRewardAmount(uint256 reward) external {
        // VULNERABILITY: Anyone can add rewards and manipulate calculations
        require(rewardToken.transferFrom(msg.sender, address(this), reward), "Transfer failed");
    }
}
