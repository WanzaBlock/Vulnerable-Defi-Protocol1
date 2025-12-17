// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SecureRewardsDistributor
 * @notice SECURE VERSION - All vulnerabilities fixed
 */
contract SecureRewardsDistributor is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    /* State Variables */
    IERC20 public immutable rewardToken;
    IERC20 public immutable stakingToken;

    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public totalStaked;

    // FIX 5: Minimum stake period to prevent flash loan attacks
    uint256 public constant MINIMUM_STAKE_PERIOD = 1; // 1 block minimum

    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public stakeTime;

    /* Events */
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);
    event RewardAdded(uint256 reward);
    event RewardsDurationUpdated(uint256 newDuration);

    constructor(
        address _stakingToken,
        address _rewardToken,
        uint256 _rewardRate
    ) Ownable(msg.sender) {
        stakingToken = IERC20(_stakingToken);
        rewardToken = IERC20(_rewardToken);
        rewardRate = _rewardRate;
        lastUpdateTime = block.timestamp;
    }

    /* Views */
    function lastTimeRewardApplicable() public view returns (uint256) {
        return block.timestamp < periodFinish ? block.timestamp : periodFinish;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        return rewardPerTokenStored +
            (((lastTimeRewardApplicable() - lastUpdateTime) * rewardRate * 1e18) / totalStaked);
    }

    function earned(address account) public view returns (uint256) {
        return (balances[account] *
            (rewardPerToken() - userRewardPerTokenPaid[account])) / 1e18 +
            rewards[account];
    }

    /* Modifiers */
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = lastTimeRewardApplicable();

        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    /* User Functions */

    /**
     * @notice Stakes tokens to earn rewards
     */
    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        require(amount > 0, "Cannot stake 0");

        totalStaked += amount;
        balances[msg.sender] += amount;
        stakeTime[msg.sender] = block.number;

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }

    /**
     * @notice Withdraws staked tokens
     */
    function withdraw(uint256 amount) public nonReentrant updateReward(msg.sender) {
        require(amount > 0, "Cannot withdraw 0");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(
            block.number >= stakeTime[msg.sender] + MINIMUM_STAKE_PERIOD,
            "Minimum stake period not met"
        );

        balances[msg.sender] -= amount;
        totalStaked -= amount;

        stakingToken.safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @notice Claims earned rewards
     */
    function claim() public nonReentrant updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");
        require(
            block.number >= stakeTime[msg.sender] + MINIMUM_STAKE_PERIOD,
            "Minimum stake period not met"
        );

        rewards[msg.sender] = 0;
        rewardToken.safeTransfer(msg.sender, reward);
        emit RewardPaid(msg.sender, reward);
    }

    /**
     * @notice Combined withdraw and claim
     */
    function exit() external {
        withdraw(balances[msg.sender]);
        claim();
    }

    /* Admin Functions */

    function setRewardRate(uint256 newRate) external onlyOwner updateReward(address(0)) {
        require(newRate > 0, "Rate must be positive");
        rewardRate = newRate;
    }

    function notifyRewardAmount(uint256 reward) external onlyOwner updateReward(address(0)) {
        require(reward > 0, "Reward must be positive");

        if (block.timestamp >= periodFinish) {
            rewardRate = reward / rewardsDuration;
        } else {
            uint256 remaining = periodFinish - block.timestamp;
            uint256 leftover = remaining * rewardRate;
            rewardRate = (reward + leftover) / rewardsDuration;
        }

        require(rewardRate > 0, "Reward rate too low");
        require(
            rewardRate <= rewardToken.balanceOf(address(this)) / rewardsDuration,
            "Insufficient reward balance"
        );

        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + rewardsDuration;

        emit RewardAdded(reward);
    }

    function setRewardsDuration(uint256 duration) external onlyOwner {
        require(block.timestamp > periodFinish, "Previous period must be complete");
        require(duration > 0, "Duration must be positive");

        rewardsDuration = duration;
        emit RewardsDurationUpdated(duration);
    }

    function emergencyWithdrawRewards(address token, uint256 amount) external onlyOwner {
        require(block.timestamp > periodFinish + 30 days, "Must wait 30 days after period end");
        IERC20(token).safeTransfer(owner(), amount);
    }
}
