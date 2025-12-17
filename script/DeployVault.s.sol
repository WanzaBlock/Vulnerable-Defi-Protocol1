// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "src/VulnerableVault.sol";

contract DeployVault is Script {
    function run() external {
        vm.startBroadcast();

        // Use a dummy address for compilation, or deploy a mock
        address assetToken = address(0x1);
        string memory name = "Vault Shares";
        string memory symbol = "vSHARES";

        // Pass the three required arguments
        new VulnerableVault(assetToken, name, symbol);

        vm.stopBroadcast();
    }
}
