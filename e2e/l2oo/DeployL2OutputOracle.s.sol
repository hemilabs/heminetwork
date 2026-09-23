// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

import { Proxy } from "src/universal/Proxy.sol";
import { L2OutputOracle } from "./L2OutputOracle.sol";

/// @notice Deploys an L2OutputOracle behind a Proxy and initializes it.  All
///         parameters are read from the environment, see e2e/deploy-l2oo.sh.
///         The resulting addresses are written to deployments/l2oo.json.
contract DeployL2OutputOracle is Script {
    function run() external {
        uint256 submissionInterval = vm.envUint("L2OO_SUBMISSION_INTERVAL");
        uint256 l2BlockTime = vm.envUint("L2OO_L2_BLOCK_TIME");
        uint256 startingBlockNumber = vm.envUint("L2OO_STARTING_BLOCK_NUMBER");
        uint256 startingTimestamp = vm.envUint("L2OO_STARTING_TIMESTAMP");
        address proposer = vm.envAddress("L2OO_PROPOSER");
        address challenger = vm.envAddress("L2OO_CHALLENGER");
        uint256 finalizationPeriodSeconds = vm.envUint("L2OO_FINALIZATION_PERIOD_SECONDS");

        uint256 deployerKey = vm.envUint("ADMIN_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        L2OutputOracle impl = new L2OutputOracle();

        // The deployer is the proxy admin so that it may call
        // upgradeToAndCall directly.
        Proxy proxy = new Proxy(deployer);
        proxy.upgradeToAndCall(
            address(impl),
            abi.encodeCall(
                L2OutputOracle.initialize,
                (
                    submissionInterval,
                    l2BlockTime,
                    startingBlockNumber,
                    startingTimestamp,
                    proposer,
                    challenger,
                    finalizationPeriodSeconds
                )
            )
        );

        vm.stopBroadcast();

        L2OutputOracle oracle = L2OutputOracle(address(proxy));
        require(oracle.proposer() == proposer, "DeployL2OutputOracle: proposer mismatch");
        require(
            oracle.submissionInterval() == submissionInterval, "DeployL2OutputOracle: submission interval mismatch"
        );

        console.log("L2OutputOracle implementation:", address(impl));
        console.log("L2OutputOracle proxy:", address(proxy));

        string memory key = "l2oo";
        vm.serializeAddress(key, "l2OutputOracleImpl", address(impl));
        string memory json = vm.serializeAddress(key, "l2OutputOracleProxy", address(proxy));
        vm.writeJson(json, "deployments/l2oo.json");
    }
}
