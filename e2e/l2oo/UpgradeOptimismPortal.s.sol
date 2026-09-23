// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

import { StorageSetter } from "src/universal/StorageSetter.sol";
import { ISystemConfig } from "interfaces/L1/ISystemConfig.sol";
import { ISuperchainConfig } from "interfaces/L1/ISuperchainConfig.sol";

import { L2OutputOracle } from "./L2OutputOracle.sol";
import { OptimismPortal } from "./OptimismPortal.sol";

/// @notice The parts of the ProxyAdmin that are used here.
interface IProxyAdminUpgrade {
    function owner() external view returns (address);
    function upgradeAndCall(address payable _proxy, address _implementation, bytes memory _data) external payable;
}

/// @notice The config getters shared by OptimismPortal2 and OptimismPortal.
interface IPortalConfig {
    function systemConfig() external view returns (ISystemConfig);
    function superchainConfig() external view returns (ISuperchainConfig);
}

/// @notice Upgrades the OptimismPortalProxy deployed by op-deployer from
///         OptimismPortal2, which proves withdrawals against dispute games,
///         to the legacy OptimismPortal, which proves withdrawals against the
///         L2OutputOracle.  The proxy is kept so the rollup config, the
///         L1CrossDomainMessenger and the L1StandardBridge need no changes.
///
///         The storage layouts are compatible: OptimismPortal2 keeps the
///         legacy slots as spacers.  Only the initialized version in slot 0
///         has to be cleared, OptimismPortal2 is initialized with a
///         reinitializer version that makes the legacy initializer revert.
contract UpgradeOptimismPortal is Script {
    /// @notice EIP-1967 admin slot.
    bytes32 internal constant PROXY_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    function run() external {
        address payable portalProxy = payable(vm.envAddress("OPTIMISM_PORTAL_PROXY"));
        L2OutputOracle l2Oracle = L2OutputOracle(vm.envAddress("L2OO_PROXY"));

        uint256 deployerKey = vm.envUint("ADMIN_PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        IProxyAdminUpgrade proxyAdmin =
            IProxyAdminUpgrade(address(uint160(uint256(vm.load(portalProxy, PROXY_ADMIN_SLOT)))));
        require(proxyAdmin.owner() == deployer, "UpgradeOptimismPortal: deployer does not own the ProxyAdmin");

        // keep the configuration of the portal that is being replaced
        ISystemConfig systemConfig = IPortalConfig(portalProxy).systemConfig();
        ISuperchainConfig superchainConfig = IPortalConfig(portalProxy).superchainConfig();

        vm.startBroadcast(deployerKey);

        StorageSetter storageSetter = new StorageSetter();
        OptimismPortal impl = new OptimismPortal();

        proxyAdmin.upgradeAndCall(
            portalProxy,
            address(storageSetter),
            abi.encodeWithSignature("setBytes32(bytes32,bytes32)", bytes32(0), bytes32(0))
        );

        proxyAdmin.upgradeAndCall(
            portalProxy, address(impl), abi.encodeCall(OptimismPortal.initialize, (l2Oracle, systemConfig, superchainConfig))
        );

        vm.stopBroadcast();

        OptimismPortal portal = OptimismPortal(portalProxy);
        require(portal.l2Oracle() == l2Oracle, "UpgradeOptimismPortal: l2Oracle mismatch");
        require(portal.systemConfig() == systemConfig, "UpgradeOptimismPortal: systemConfig mismatch");
        require(portal.superchainConfig() == superchainConfig, "UpgradeOptimismPortal: superchainConfig mismatch");

        console.log("OptimismPortal implementation:", address(impl));
        console.log("OptimismPortal proxy:", address(portalProxy));
        console.log("OptimismPortal version:", portal.version());
    }
}
