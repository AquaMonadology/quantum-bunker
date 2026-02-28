// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/QuantumBunker.sol";

contract DeployScript is Script {
    function run() external {
        bytes32 initRoot = vm.envBytes32("INIT_ROOT");
        bytes32 seqAnchor = vm.envBytes32("SEQ_ANCHOR");
        bytes32 daAnchor = vm.envBytes32("DA_ANCHOR");
        bytes32 guardAnchor = vm.envBytes32("GUARD_ANCHOR");

        address[] memory tokens = new address[](0);

        vm.startBroadcast();
        QuantumBunkerV3_8 bunker =
            new QuantumBunkerV3_8(initRoot, seqAnchor, daAnchor, guardAnchor, tokens);
        vm.stopBroadcast();

        console.log("QuantumBunker deployed at:", address(bunker));
    }
}
