// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Script, console2} from "forge-std/Script.sol";
import {ThreatReportRegistry} from "../src/ThreatReportRegistry.sol";

/// @notice Deploys ThreatReportRegistry and grants the reporter and reviewer roles.
/// Usage (see scripts/deploy.sh, which supplies the anvil test key for chain 31337 only):
///   REPORTER=0x.. REVIEWER=0x.. forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast
contract Deploy is Script {
    function run() external returns (ThreatReportRegistry registry) {
        address reporter = vm.envAddress("REPORTER");
        address reviewer = vm.envAddress("REVIEWER");
        vm.startBroadcast();
        registry = new ThreatReportRegistry();
        registry.setReporter(reporter, true);
        registry.setReviewer(reviewer, true);
        vm.stopBroadcast();
        console2.log("ThreatReportRegistry deployed at", address(registry));
    }
}
