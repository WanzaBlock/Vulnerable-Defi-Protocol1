// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";



/**
 * @title VulnerableVault
 * @notice DELIBERATELY VULNERABLE - DO NOT USE IN PRODUCTION
 * @dev This vault contains intentional vulnerabilities for educational purposes:
 * 1. Reentrancy vulnerability in withdraw()
 * 2. Share price manipulation via donation attack
 * 3. Precision loss in share calculations
 * 4. Missing access controls on critical functions
 * 5. Flash loan attack surface
 */
contract VulnerableVault is ERC20 {
    IERC20 public immutable asset;
    uint256 public totalAssets;

    // VULNERABILITY: No access control
    address public admin;
    uint256 public performanceFee = 100; // 1% in basis points

    event Deposit(address indexed sender, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, uint256 assets, uint256 shares);
    event FeesCollected(uint256 amount);

    constructor(
        address _asset,
        string memory _name,
        string memory _symbol
    ) ERC20(_name, _symbol) {
        asset = IERC20(_asset);
        admin = msg.sender;
    }

    /**
     * @notice VULNERABILITY 1: Reentrancy
     * @dev External call before state update allows reentrancy
     */
    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "Cannot deposit 0");

        shares = convertToShares(assets);

        // VULNERABILITY: External call before state update
        require(asset.transferFrom(msg.sender, address(this), assets), "Transfer failed");

        // State updated AFTER external call
        totalAssets += assets;
        _mint(msg.sender, shares);

        emit Deposit(msg.sender, assets, shares);
    }

    /**
     * @notice VULNERABILITY 1: Reentrancy + VULNERABILITY 2: Share price manipulation
     * @dev Allows reentrancy and can be exploited for share price manipulation
     */
    function withdraw(uint256 shares) external returns (uint256 assets) {
        require(shares > 0, "Cannot withdraw 0");
        require(balanceOf(msg.sender) >= shares, "Insufficient shares");

        assets = convertToAssets(shares);

        // VULNERABILITY: State updated AFTER external call - enables reentrancy
        require(asset.transfer(msg.sender, assets), "Transfer failed");

        // Burn happens after transfer - reentrancy possible
        _burn(msg.sender, shares);
        totalAssets -= assets;

        emit Withdraw(msg.sender, assets, shares);
    }

    /**
     * @notice VULNERABILITY 3: Precision loss
     * @dev Integer division can lead to rounding down, exploitable in low liquidity
     */
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();

        // VULNERABILITY: First depositor attack - can manipulate share price
        if (supply == 0) {
            return assets; // 1:1 ratio for first deposit
        }

        // VULNERABILITY: Precision loss - division before multiplication
        // shares = assets * totalSupply / totalAssets
        return (assets * supply) / totalAssets;
    }

    /**
     * @notice VULNERABILITY 3: Precision loss
     */
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) {
            return shares;
        }

        // VULNERABILITY: Precision loss in division
        return (shares * totalAssets) / supply;
    }

    /**
     * @notice VULNERABILITY 4: Missing access control
     * @dev Anyone can call this and steal fees
     */
    function collectFees() external {
        // VULNERABILITY: No access control - anyone can call this!
        uint256 feeAmount = (totalAssets * performanceFee) / 10000;

        if (feeAmount > 0) {
            totalAssets -= feeAmount;
            require(asset.transfer(msg.sender, feeAmount), "Fee transfer failed");
            emit FeesCollected(feeAmount);
        }
    }

    /**
     * @notice VULNERABILITY 4: Missing access control
     * @dev No onlyAdmin modifier
     */
    function setPerformanceFee(uint256 newFee) external {
        // VULNERABILITY: No access control check
        require(newFee <= 10000, "Fee too high");
        performanceFee = newFee;
    }

    /**
     * @notice VULNERABILITY 5: Flash loan vulnerability
     * @dev Vault balance can be manipulated within a transaction
     */
    function donateToVault(uint256 amount) external {
        // VULNERABILITY: Direct donation increases totalAssets without minting shares
        // This can be used to manipulate share price
        require(asset.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        totalAssets += amount;
    }

    /**
     * @notice Emergency withdraw - VULNERABILITY 4: No access control
     */
    function emergencyWithdraw() external {
        // VULNERABILITY: No access control - anyone can drain the vault!
        uint256 balance = asset.balanceOf(address(this));
        require(asset.transfer(msg.sender, balance), "Transfer failed");
        totalAssets = 0;
    }
}
