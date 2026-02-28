// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/QuantumBunker.sol";

/// @dev Minimal ERC20 for testing withdrawals.
contract MockERC20 {
    string public name = "Mock";
    string public symbol = "MCK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

/// @dev Receiver contract (has code, passes withdrawTo check).
contract Receiver {
    receive() external payable {}
}

contract QuantumBunkerTest is Test {
    QuantumBunkerV3_8 public bunker;
    MockERC20 public token;
    Receiver public receiver;

    // Hash chain links: link[0] is the deepest preimage, link[N] is the anchor.
    // To reveal link[i], hash(link[i]) must equal the current anchor.
    // We build chains of depth 10 for testing.
    bytes32[11] seqChain;
    bytes32[11] daChain;
    bytes32[11] guardChain;

    uint256 seqIdx;
    uint256 daIdx;
    uint256 guardIdx;

    function setUp() public {
        // Warp past initial halt cooldown (lastHaltTimestamp=0, HALT_COOLDOWN=1 day)
        vm.warp(2 days);

        // Build hash chains: chain[10] = anchor, chain[9] is first reveal, etc.
        seqChain[0] = keccak256("seq_seed");
        daChain[0] = keccak256("da_seed");
        guardChain[0] = keccak256("guard_seed");

        for (uint256 i = 1; i <= 10; i++) {
            seqChain[i] = keccak256(abi.encode(seqChain[i - 1]));
            daChain[i] = keccak256(abi.encode(daChain[i - 1]));
            guardChain[i] = keccak256(abi.encode(guardChain[i - 1]));
        }

        seqIdx = 9; // next reveal index
        daIdx = 9;
        guardIdx = 9;

        address[] memory tokens = new address[](1);
        token = new MockERC20();
        tokens[0] = address(token);

        bunker = new QuantumBunkerV3_8(
            bytes32(uint256(1)), // initRoot
            seqChain[10], // seqAnchor
            daChain[10], // daAnchor
            guardChain[10], // guardAnchor
            tokens
        );

        receiver = new Receiver();

        // Fund bunker for ETH withdrawals
        vm.deal(address(bunker), 100 ether);
        // Fund watchdog pool
        vm.deal(address(this), 100 ether);
        bunker.fundWatchdog{value: 10 ether}();
    }

    // ═══════════════════ HELPERS ═══════════════════

    function _nextSeqReveal() internal returns (bytes32) {
        return seqChain[seqIdx--];
    }

    function _nextDaReveal() internal returns (bytes32) {
        return daChain[daIdx--];
    }

    function _nextGuardReveal() internal returns (bytes32) {
        return guardChain[guardIdx--];
    }

    function _popcount(uint256 x) internal pure returns (uint256 c) {
        while (x != 0) {
            x &= x - 1;
            c++;
        }
    }

    function _commitAndAdvance(bytes32 commitment) internal {
        bunker.commit(commitment);
        vm.roll(block.number + 1);
    }

    function _submitRoot(bytes32 newRoot, bytes32 daHash) internal {
        bytes32 reveal = _nextSeqReveal();
        bytes32 c = keccak256(abi.encode(reveal, newRoot, daHash));
        _commitAndAdvance(c);
        bunker.revealAndUpdate(reveal, newRoot, daHash);
    }

    function _publishChunk(bytes memory chunk, bytes32 rootRef) internal {
        bytes32 daReveal = _nextDaReveal();
        bytes32 chunkHash = keccak256(chunk);
        bytes32 dc = keccak256(abi.encode(chunkHash, rootRef, daReveal));
        _commitAndAdvance(dc);
        bunker.publishDA(chunk, rootRef, daReveal);
    }

    function _sealDA(bytes32 rootRef) internal {
        bytes32 daReveal = _nextDaReveal();
        bytes32 sealTag = keccak256("SEAL");
        bytes32 sc = keccak256(abi.encode(sealTag, rootRef, daReveal));
        _commitAndAdvance(sc);
        bunker.sealDA(rootRef, daReveal);
    }

    // ═══════════════════ COMMIT-REVEAL ═══════════════════

    function test_commit_stores_block_number() public {
        bytes32 c = keccak256("test");
        bunker.commit(c);
        assertEq(bunker.commits(c), block.number);
    }

    function test_commit_duplicate_reverts() public {
        bytes32 c = keccak256("test");
        bunker.commit(c);
        vm.expectRevert("DUPLICATE");
        bunker.commit(c);
    }

    function test_pruneCommit_before_expiry_reverts() public {
        bytes32 c = keccak256("test");
        bunker.commit(c);
        vm.roll(block.number + 100);
        vm.expectRevert("NOT_EXPIRED");
        bunker.pruneCommit(c);
    }

    function test_pruneCommit_after_expiry_succeeds() public {
        bytes32 c = keccak256("test");
        bunker.commit(c);
        vm.roll(block.number + 7201);
        bunker.pruneCommit(c);
        assertEq(bunker.commits(c), 0);
    }

    function test_pruneCommit_nonexistent_reverts() public {
        vm.expectRevert("NO_COMMIT");
        bunker.pruneCommit(keccak256("nonexistent"));
    }

    // ═══════════════════ SEQUENCER (CHAIN #1) ═══════════════════

    function test_revealAndUpdate_sets_pending() public {
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        _submitRoot(newRoot, daHash);

        assertEq(bunker.pendingRoot(), newRoot);
        assertEq(bunker.pendingDaHash(), daHash);
        assertFalse(bunker.pendingHalted());
    }

    function test_revealAndUpdate_bad_chain_reverts() public {
        bytes32 reveal = keccak256("wrong");
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        bytes32 c = keccak256(abi.encode(reveal, newRoot, daHash));
        _commitAndAdvance(c);
        vm.expectRevert("BAD_CHAIN");
        bunker.revealAndUpdate(reveal, newRoot, daHash);
    }

    function test_revealAndUpdate_same_block_reverts() public {
        bytes32 reveal = _nextSeqReveal();
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        bytes32 c = keccak256(abi.encode(reveal, newRoot, daHash));
        bunker.commit(c);
        // Don't advance block
        vm.expectRevert("SAME_BLOCK");
        bunker.revealAndUpdate(reveal, newRoot, daHash);
    }

    function test_revealAndUpdate_no_commit_reverts() public {
        bytes32 reveal = _nextSeqReveal();
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        vm.expectRevert("NO_COMMIT");
        bunker.revealAndUpdate(reveal, newRoot, daHash);
    }

    function test_revealAndUpdate_during_halt_cooldown_reverts() public {
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        _submitRoot(newRoot, daHash);

        // Halt
        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        // Try to submit new root during cooldown
        bytes32 reveal2 = _nextSeqReveal();
        bytes32 newRoot2 = keccak256("root2");
        bytes32 daHash2 = keccak256("da2");
        bytes32 c2 = keccak256(abi.encode(reveal2, newRoot2, daHash2));
        _commitAndAdvance(c2);
        vm.expectRevert("HALT_COOLING");
        bunker.revealAndUpdate(reveal2, newRoot2, daHash2);
    }

    // ═══════════════════ DA PUBLICATION (CHAIN #2) ═══════════════════

    function test_publishDA_stores_chunk() public {
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        _submitRoot(newRoot, daHash);

        bytes memory chunk = hex"deadbeef";
        _publishChunk(chunk, newRoot);

        assertEq(bunker.chunkCount(newRoot), 1);
        assertEq(bunker.chunkHashes(newRoot, 0), keccak256(chunk));
    }

    function test_publishDA_empty_chunk_reverts() public {
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        _submitRoot(newRoot, daHash);

        bytes32 daReveal = _nextDaReveal();
        bytes32 chunkHash = keccak256("");
        bytes32 dc = keccak256(abi.encode(chunkHash, newRoot, daReveal));
        _commitAndAdvance(dc);
        vm.expectRevert("EMPTY_CHUNK");
        bunker.publishDA("", newRoot, daReveal);
    }

    function test_publishDA_wrong_root_reverts() public {
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash = keccak256("da1");
        _submitRoot(newRoot, daHash);

        bytes memory chunk = hex"deadbeef";
        bytes32 daReveal = _nextDaReveal();
        bytes32 wrongRoot = keccak256("wrong");
        bytes32 chunkHash = keccak256(chunk);
        bytes32 dc = keccak256(abi.encode(chunkHash, wrongRoot, daReveal));
        _commitAndAdvance(dc);
        vm.expectRevert("WRONG_ROOT");
        bunker.publishDA(chunk, wrongRoot, daReveal);
    }

    function test_publishDA_after_seal_reverts() public {
        bytes32 newRoot = keccak256("root1");
        bytes32 daHash; // we'll compute this

        // First publish a chunk to get rolling hash for daHash
        bytes memory chunk = hex"deadbeef";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));
        daHash = rollingHash;

        _submitRoot(newRoot, daHash);
        _publishChunk(chunk, newRoot);
        _sealDA(newRoot);

        // Try to publish after seal
        bytes memory chunk2 = hex"cafe";
        bytes32 daReveal2 = _nextDaReveal();
        bytes32 chunkHash2 = keccak256(chunk2);
        bytes32 dc2 = keccak256(abi.encode(chunkHash2, newRoot, daReveal2));
        _commitAndAdvance(dc2);
        vm.expectRevert("DA_SEALED");
        bunker.publishDA(chunk2, newRoot, daReveal2);
    }

    function test_sealDA_sets_sealed() public {
        bytes32 newRoot = keccak256("root1");
        bytes memory chunk = hex"deadbeef";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));

        _submitRoot(newRoot, rollingHash);
        _publishChunk(chunk, newRoot);
        _sealDA(newRoot);

        assertTrue(bunker.daSealed(newRoot));
    }

    function test_sealDA_no_data_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        bytes32 daReveal = _nextDaReveal();
        bytes32 sealTag = keccak256("SEAL");
        bytes32 sc = keccak256(abi.encode(sealTag, newRoot, daReveal));
        _commitAndAdvance(sc);
        vm.expectRevert("NO_DATA");
        bunker.sealDA(newRoot, daReveal);
    }

    function test_sealDA_double_seal_reverts() public {
        bytes32 newRoot = keccak256("root1");
        bytes memory chunk = hex"deadbeef";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));

        _submitRoot(newRoot, rollingHash);
        _publishChunk(chunk, newRoot);
        _sealDA(newRoot);

        bytes32 daReveal2 = _nextDaReveal();
        bytes32 sealTag = keccak256("SEAL");
        bytes32 sc2 = keccak256(abi.encode(sealTag, newRoot, daReveal2));
        _commitAndAdvance(sc2);
        vm.expectRevert("ALREADY_SEALED");
        bunker.sealDA(newRoot, daReveal2);
    }

    // ═══════════════════ GUARDIAN (CHAIN #3) ═══════════════════

    function test_guardian_halt() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        assertTrue(bunker.pendingHalted());
    }

    function test_guardian_halt_no_pending_reverts() public {
        bytes32 guardReveal = _nextGuardReveal();
        vm.expectRevert("NO_PENDING");
        bunker.haltPendingRoot(guardReveal);
    }

    function test_guardian_double_halt_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        bytes32 guardReveal2 = _nextGuardReveal();
        vm.expectRevert("ALREADY_HALTED");
        bunker.haltPendingRoot(guardReveal2);
    }

    function test_guardian_bad_chain_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        vm.expectRevert("BAD_GUARDIAN");
        bunker.haltPendingRoot(keccak256("wrong"));
    }

    function test_guardian_halt_sets_cooldown() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        assertEq(bunker.lastHaltTimestamp(), block.timestamp);
    }

    // ═══════════════════ WATCHDOG ═══════════════════

    function test_fundWatchdog() public {
        uint256 poolBefore = bunker.watchdogPool();
        bunker.fundWatchdog{value: 1 ether}();
        assertEq(bunker.watchdogPool(), poolBefore + 1 ether);
    }

    function test_fundWatchdog_zero_reverts() public {
        vm.expectRevert("ZERO_VALUE");
        bunker.fundWatchdog{value: 0}();
    }

    function test_respondChallenge_no_pending_reverts() public {
        vm.expectRevert("NO_PENDING");
        bunker.respondChallenge(hex"deadbeef");
    }

    function test_respondChallenge_halted_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));
        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        vm.expectRevert("HALTED");
        bunker.respondChallenge(hex"deadbeef");
    }

    function test_respondChallenge_unsealed_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        vm.expectRevert("DA_NOT_SEALED");
        bunker.respondChallenge(hex"deadbeef");
    }

    // ═══════════════════ FINALIZATION ═══════════════════

    function test_finalizeRoot_no_pending_reverts() public {
        vm.expectRevert("NO_PENDING");
        bunker.finalizeRoot();
    }

    function test_finalizeRoot_halted_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));
        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        vm.expectRevert("HALTED");
        bunker.finalizeRoot();
    }

    function test_finalizeRoot_too_early_reverts() public {
        bytes32 newRoot = keccak256("root1");
        _submitRoot(newRoot, keccak256("da1"));

        vm.expectRevert("TOO_EARLY");
        bunker.finalizeRoot();
    }

    // ═══════════════════ WITHDRAWAL ═══════════════════

    function test_withdraw_unsupported_token_reverts() public {
        address fakeToken = address(0xdead);
        vm.expectRevert("UNSUPPORTED");
        bunker.withdraw(
            address(this),
            fakeToken,
            1 ether,
            keccak256(abi.encode(bytes32(uint256(42)))),
            address(receiver),
            bytes32(uint256(42)),
            new bytes32[](0)
        );
    }

    function test_withdraw_eoa_blocked() public {
        address eoa = address(0x1234);
        vm.expectRevert("EOA_BLOCKED");
        bunker.withdraw(
            address(this),
            address(0),
            1 ether,
            keccak256(abi.encode(bytes32(uint256(42)))),
            eoa,
            bytes32(uint256(42)),
            new bytes32[](0)
        );
    }

    function test_withdraw_bad_credential_reverts() public {
        vm.expectRevert("BAD_CRED");
        bunker.withdraw(
            address(this),
            address(0),
            1 ether,
            keccak256(abi.encode(bytes32(uint256(99)))), // credentialHash for 99
            address(receiver),
            bytes32(uint256(42)), // wrong preimage
            new bytes32[](0)
        );
    }

    // ═══════════════════ FULL E2E FLOW ═══════════════════

    function test_full_lifecycle_eth_withdrawal() public {
        // --- Setup withdrawal params ---
        bytes32 pqPreimage = keccak256("user_secret");
        bytes32 credentialHash = keccak256(abi.encode(pqPreimage));
        address owner = address(0xBEEF);
        uint256 balance = 1 ether;

        // --- Build Merkle leaf ---
        bytes32 leaf = keccak256(
            abi.encodePacked(
                bytes1(0x00),
                abi.encode(
                    block.chainid,
                    address(bunker),
                    owner,
                    address(0),
                    balance,
                    credentialHash,
                    address(receiver)
                )
            )
        );

        // Root = leaf (single-leaf tree, no proof needed... but we need a proper root).
        // For a single leaf, root == leaf with empty proof.
        bytes32 newRoot = leaf;

        // --- Build DA ---
        bytes memory chunk = hex"aabbccdd";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));
        bytes32 daHash = rollingHash;

        // --- Phase 1: Submit root ---
        _submitRoot(newRoot, daHash);
        assertEq(bunker.pendingRoot(), newRoot);

        // --- Phase 2: Publish DA + seal ---
        _publishChunk(chunk, newRoot);
        _sealDA(newRoot);
        assertTrue(bunker.daSealed(newRoot));
        assertEq(bunker.daRollingHash(newRoot), daHash);

        // --- Phase 3: Watchdog challenges ---
        // We only have 1 chunk, so we need 1 unique chunk and 10 epochs.
        // Respond in different epochs.
        uint256 startBlock = block.number;
        uint256 epochSize = bunker.EPOCH_SIZE();

        for (uint256 epoch = 0; epoch < 10; epoch++) {
            vm.roll(startBlock + epoch * epochSize + 1);
            // Try responding - may fail with ALREADY_RESPONDED if same prevrandao
            vm.prevrandao(bytes32(uint256(epoch * 1000 + 1)));
            try bunker.respondChallenge(chunk) {}
            catch {}
        }

        // Ensure we have enough unique chunks and epochs
        // Since there's only 1 chunk, uniqueChunks should be 1 (== chunkCount)
        // and we need 10 epochs
        assertTrue(bunker.uniqueChunks(newRoot) >= 1);

        // Keep trying different epochs until we have enough
        for (uint256 i = 10; i < 300; i++) {
            if (_popcount(bunker.epochBitmap(newRoot)) >= 10) break;
            vm.roll(startBlock + i * epochSize + 1);
            vm.prevrandao(bytes32(uint256(i * 7919 + 3)));
            try bunker.respondChallenge(chunk) {}
            catch {}
        }

        // --- Phase 5: Finalize ---
        vm.warp(block.timestamp + 7 days + 1);
        bunker.finalizeRoot();
        assertEq(bunker.finalizedRoot(), newRoot);

        // --- Phase 6: Withdraw ETH ---
        uint256 receiverBalBefore = address(receiver).balance;
        bunker.withdraw(
            owner, address(0), balance, credentialHash, address(receiver), pqPreimage, new bytes32[](0)
        );
        assertEq(address(receiver).balance, receiverBalBefore + balance);
    }

    function test_withdraw_double_claim_reverts() public {
        // Reuse the full flow to finalize, then try claiming twice.
        bytes32 pqPreimage = keccak256("user_secret_2");
        bytes32 credentialHash = keccak256(abi.encode(pqPreimage));
        address owner = address(0xCAFE);
        uint256 balance = 0.5 ether;

        bytes32 leaf = keccak256(
            abi.encodePacked(
                bytes1(0x00),
                abi.encode(
                    block.chainid,
                    address(bunker),
                    owner,
                    address(0),
                    balance,
                    credentialHash,
                    address(receiver)
                )
            )
        );

        bytes32 newRoot = leaf;
        bytes memory chunk = hex"11223344";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));

        _submitRoot(newRoot, rollingHash);
        _publishChunk(chunk, newRoot);
        _sealDA(newRoot);

        uint256 startBlock = block.number;
        uint256 epochSize = bunker.EPOCH_SIZE();
        for (uint256 i = 0; i < 300; i++) {
            if (
                bunker.uniqueChunks(newRoot) >= 1
                    && _popcount(bunker.epochBitmap(newRoot)) >= 10
            ) break;
            vm.roll(startBlock + i * epochSize + 1);
            vm.prevrandao(bytes32(uint256(i * 13 + 7)));
            try bunker.respondChallenge(chunk) {}
            catch {}
        }

        vm.warp(block.timestamp + 7 days + 1);
        bunker.finalizeRoot();

        // First withdrawal succeeds
        bunker.withdraw(
            owner, address(0), balance, credentialHash, address(receiver), pqPreimage, new bytes32[](0)
        );

        // Second withdrawal reverts
        vm.expectRevert("CLAIMED");
        bunker.withdraw(
            owner, address(0), balance, credentialHash, address(receiver), pqPreimage, new bytes32[](0)
        );
    }

    function test_erc20_withdrawal() public {
        bytes32 pqPreimage = keccak256("erc20_secret");
        bytes32 credentialHash = keccak256(abi.encode(pqPreimage));
        address owner = address(0xF00D);
        uint256 balance = 1000e18;

        // Mint tokens to bunker
        token.mint(address(bunker), balance);

        bytes32 leaf = keccak256(
            abi.encodePacked(
                bytes1(0x00),
                abi.encode(
                    block.chainid,
                    address(bunker),
                    owner,
                    address(token),
                    balance,
                    credentialHash,
                    address(receiver)
                )
            )
        );

        bytes32 newRoot = leaf;
        bytes memory chunk = hex"e4c20da1a0";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));

        _submitRoot(newRoot, rollingHash);
        _publishChunk(chunk, newRoot);
        _sealDA(newRoot);

        uint256 startBlock = block.number;
        uint256 epochSize = bunker.EPOCH_SIZE();
        for (uint256 i = 0; i < 300; i++) {
            if (
                bunker.uniqueChunks(newRoot) >= 1
                    && _popcount(bunker.epochBitmap(newRoot)) >= 10
            ) break;
            vm.roll(startBlock + i * epochSize + 1);
            vm.prevrandao(bytes32(uint256(i * 17 + 3)));
            try bunker.respondChallenge(chunk) {}
            catch {}
        }

        vm.warp(block.timestamp + 7 days + 1);
        bunker.finalizeRoot();

        bunker.withdraw(
            owner,
            address(token),
            balance,
            credentialHash,
            address(receiver),
            pqPreimage,
            new bytes32[](0)
        );

        assertEq(token.balanceOf(address(receiver)), balance);
    }

    // ═══════════════════ MERKLE VERIFICATION ═══════════════════

    function test_merkle_two_leaf_tree() public {
        bytes32 pqPreimage = keccak256("merkle_user");
        bytes32 credentialHash = keccak256(abi.encode(pqPreimage));
        address owner = address(0xAAAA);
        uint256 balance = 2 ether;

        bytes32 leafA = keccak256(
            abi.encodePacked(
                bytes1(0x00),
                abi.encode(
                    block.chainid,
                    address(bunker),
                    owner,
                    address(0),
                    balance,
                    credentialHash,
                    address(receiver)
                )
            )
        );

        bytes32 leafB = keccak256("other_leaf");

        // Sorted pair hash
        bytes32 root;
        if (leafA <= leafB) {
            root = keccak256(abi.encode(leafA, leafB));
        } else {
            root = keccak256(abi.encode(leafB, leafA));
        }

        // DA setup
        bytes memory chunk = hex"ae4c1eda1a";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));

        _submitRoot(root, rollingHash);
        _publishChunk(chunk, root);
        _sealDA(root);

        uint256 startBlock = block.number;
        uint256 epochSize = bunker.EPOCH_SIZE();
        for (uint256 i = 0; i < 300; i++) {
            if (
                bunker.uniqueChunks(root) >= 1
                    && _popcount(bunker.epochBitmap(root)) >= 10
            ) break;
            vm.roll(startBlock + i * epochSize + 1);
            vm.prevrandao(bytes32(uint256(i * 31 + 11)));
            try bunker.respondChallenge(chunk) {}
            catch {}
        }

        vm.warp(block.timestamp + 7 days + 1);
        bunker.finalizeRoot();

        // Withdraw with Merkle proof containing sibling
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafB;

        bunker.withdraw(owner, address(0), balance, credentialHash, address(receiver), pqPreimage, proof);
        assertEq(address(receiver).balance, 2 ether);
    }

    // ═══════════════════ AUTO-FINALIZE ═══════════════════

    function test_auto_finalize_on_new_root() public {
        // Submit and fully prepare root1
        bytes32 root1 = keccak256("auto_root_1");
        bytes memory chunk = hex"a0101010";
        bytes32 chunkHash = keccak256(chunk);
        bytes32 rollingHash = keccak256(abi.encode(bytes32(0), chunkHash));

        _submitRoot(root1, rollingHash);
        _publishChunk(chunk, root1);
        _sealDA(root1);

        uint256 startBlock = block.number;
        uint256 epochSize = bunker.EPOCH_SIZE();
        for (uint256 i = 0; i < 300; i++) {
            if (
                bunker.uniqueChunks(root1) >= 1
                    && _popcount(bunker.epochBitmap(root1)) >= 10
            ) break;
            vm.roll(startBlock + i * epochSize + 1);
            vm.prevrandao(bytes32(uint256(i * 41 + 5)));
            try bunker.respondChallenge(chunk) {}
            catch {}
        }

        vm.warp(block.timestamp + 7 days + 1);

        // Now submit root2 — should auto-finalize root1
        bytes32 root2 = keccak256("auto_root_2");
        _submitRoot(root2, keccak256("da2"));

        assertEq(bunker.finalizedRoot(), root1);
        assertEq(bunker.pendingRoot(), root2);
    }

    // ═══════════════════ EDGE CASES ═══════════════════

    function test_receive_ether() public {
        uint256 balBefore = address(bunker).balance;
        (bool ok,) = address(bunker).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(bunker).balance, balBefore + 1 ether);
    }

    function test_supported_tokens_set_in_constructor() public {
        assertTrue(bunker.supportedTokens(address(0)));
        assertTrue(bunker.supportedTokens(address(token)));
        assertFalse(bunker.supportedTokens(address(0xdead)));
    }

    function test_constants() public view {
        assertEq(bunker.CHALLENGE_WINDOW(), 7 days);
        assertEq(bunker.HALT_COOLDOWN(), 1 days);
        assertEq(bunker.MAX_MERKLE_DEPTH(), 64);
        assertEq(bunker.COMMIT_EXPIRY(), 7200);
        assertEq(bunker.MAX_CHUNK_BYTES(), 750_000);
        assertEq(bunker.MIN_VERIF_CAP(), 100);
        assertEq(bunker.COVERAGE_BPS(), 1000);
        assertEq(bunker.BPS_DENOM(), 10000);
        assertEq(bunker.MAX_CHUNKS_PER_ROOT(), 4096);
        assertEq(bunker.MIN_EPOCHS(), 10);
        assertEq(bunker.EPOCH_COUNT(), 256);
        assertEq(bunker.EPOCH_SIZE(), 2520);
        assertEq(bunker.VERIFICATION_REWARD(), 0.001 ether);
    }

    function test_rolling_hash_integrity() public {
        bytes32 newRoot = keccak256("rolling_root");
        _submitRoot(newRoot, keccak256("placeholder"));

        bytes memory chunk1 = hex"aa";
        bytes memory chunk2 = hex"bb";

        _publishChunk(chunk1, newRoot);
        bytes32 expected1 = keccak256(abi.encode(bytes32(0), keccak256(chunk1)));
        assertEq(bunker.daRollingHash(newRoot), expected1);

        _publishChunk(chunk2, newRoot);
        bytes32 expected2 = keccak256(abi.encode(expected1, keccak256(chunk2)));
        assertEq(bunker.daRollingHash(newRoot), expected2);
    }

    function test_halt_cooldown_allows_after_1_day() public {
        bytes32 newRoot = keccak256("cooldown_root");
        _submitRoot(newRoot, keccak256("da"));

        bytes32 guardReveal = _nextGuardReveal();
        bunker.haltPendingRoot(guardReveal);

        // Advance past cooldown
        vm.warp(block.timestamp + 1 days);

        // Should be able to submit new root
        bytes32 root2 = keccak256("post_cooldown");
        _submitRoot(root2, keccak256("da2"));
        assertEq(bunker.pendingRoot(), root2);
    }

    // Helper to allow receiving ETH
    receive() external payable {}
}
