// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title  Quantum Bunker v3.8 — Post-Quantum Emergency Withdrawal
/// @notice Emergency exit from L2 bridge when ECDSA breaks (Q-Day).
///         Zero ECC. One primitive: keccak256. Three hash chains.
///
/// @dev    GUARANTEES
///         (G1) All DA published on permanent L1 calldata.
///         (G2) Proportional sample of unique chunks re-published
///              across ≥10 temporal epochs (~3.5 days).
///         (G3) 7-day challenge window before finalization.
///         (G4) Guardian halt with 1-day cooldown per link (27 years).
///         (G5) Zero ECC dependency — survives Shor's algorithm.
///
/// @dev    NON-GUARANTEES
///         (N1) Semantic correctness of state diffs.
///         (N2) Third-party participation under high basefee —
///              permissionless watchdog viable only when
///              basefee × (21000 + 40×B) ≤ VERIFICATION_REWARD (EIP-7623);
///              EIP-7976 (Glamsterdam CFI, DRAFT, current spec: 15/60) worsens
///              this ~50%. Target B ≤ 2KB at 10 gwei, ≤ 300B at 30 gwei.
///         (N3) Fraud detection (probabilistic only).
///         (N4) Coverage of any specific chunk (random sampling).
///         (N5) Immunity to builder-level censorship.
///
/// @dev    LINEAGE — Same cryptographic pattern as Vitalik's quantum
///         emergency fork proposal (ethresear.ch, March 2024). Aligns with
///         EF Post-Quantum team strategy (Jan 2026): hash-based foundation.
///
/// @dev    29 patches. 90+ findings resolved. 16+ iterations.
contract QuantumBunkerV3_8 {
    using SafeERC20 for IERC20;

    // ═══════════════════ STATE ═══════════════════

    bytes32 public finalizedRoot;
    bytes32 public pendingRoot;
    bytes32 public pendingDaHash;
    uint256 public pendingTimestamp;
    uint256 public pendingBlock;
    bool public pendingHalted;
    uint256 public lastHaltTimestamp;
    bytes32 public sequencerAnchor;
    bytes32 public daAnchor;
    bytes32 public guardianAnchor;
    uint256 public watchdogPool;

    mapping(bytes32 => uint256) public commits;
    mapping(bytes32 => bytes32) public daRollingHash;
    mapping(bytes32 => bool) public daSealed;
    mapping(bytes32 => mapping(uint256 => bytes32)) public chunkHashes;
    mapping(bytes32 => uint256) public chunkCount;
    mapping(bytes32 => mapping(bytes32 => bool)) internal _challengeUsed;
    mapping(bytes32 => mapping(uint256 => uint256)) internal _seenChunks;
    mapping(bytes32 => uint256) public uniqueChunks;
    mapping(bytes32 => uint256) public epochBitmap;
    mapping(bytes32 => bool) public claimed;
    mapping(address => bool) public supportedTokens;

    // ═══════════════════ CONSTANTS ═══════════════════

    uint256 public constant CHALLENGE_WINDOW = 7 days;
    uint256 public constant HALT_COOLDOWN = 1 days;
    uint256 public constant MAX_MERKLE_DEPTH = 64;
    uint256 public constant COMMIT_EXPIRY = 7200;
    uint256 public constant MAX_CHUNK_BYTES = 750_000;
    bytes1 public constant LEAF_PREFIX = 0x00;
    uint256 public constant MIN_VERIF_CAP = 100;
    uint256 public constant COVERAGE_BPS = 1000;
    uint256 public constant BPS_DENOM = 10000;
    uint256 public constant MAX_CHUNKS_PER_ROOT = 4096;
    uint256 public constant MIN_EPOCHS = 10;
    uint256 public constant EPOCH_COUNT = 256;
    uint256 public constant EPOCH_SIZE = 2520;
    uint256 public constant VERIFICATION_REWARD = 0.001 ether;
    bytes32 private constant _SEAL_TAG = keccak256("SEAL");

    // ═══════════════════ EVENTS ═══════════════════

    event Committed(bytes32 indexed commitment, uint256 blockNumber);
    event CommitPruned(bytes32 indexed commitment);
    event RootUpdated(bytes32 indexed newRoot, bytes32 daHash);
    event DAChunkPublished(bytes32 indexed rootRef, uint256 idx, bytes32 rolling);
    event DASealed(bytes32 indexed rootRef, bytes32 finalHash);
    event RootHalted(bytes32 indexed root);
    event RootFinalized(bytes32 indexed root);
    event ChallengeResponded(bytes32 indexed root, uint256 chunkIdx, address responder);
    event WatchdogFunded(address indexed funder, uint256 amount);
    event Withdrawal(address indexed owner, address token, uint256 bal, address to);

    // ═══════════════════ CONSTRUCTOR ═══════════════════

    constructor(
        bytes32 _initRoot,
        bytes32 _seqAnchor,
        bytes32 _daAnchor,
        bytes32 _guardAnchor,
        address[] memory _tokens
    ) {
        finalizedRoot = _initRoot;
        sequencerAnchor = _seqAnchor;
        daAnchor = _daAnchor;
        guardianAnchor = _guardAnchor;
        supportedTokens[address(0)] = true;
        for (uint256 i = 0; i < _tokens.length; i++) {
            supportedTokens[_tokens[i]] = true;
        }
    }

    // ═══════════════════ UNIVERSAL COMMIT-REVEAL ═══════════════════

    function commit(bytes32 _c) external {
        require(commits[_c] == 0, "DUPLICATE");
        commits[_c] = block.number;
        emit Committed(_c, block.number);
    }

    function pruneCommit(bytes32 _c) external {
        uint256 b = commits[_c];
        require(b != 0, "NO_COMMIT");
        require(block.number > b + COMMIT_EXPIRY, "NOT_EXPIRED");
        delete commits[_c];
        emit CommitPruned(_c);
    }

    // ═══════════════════ CHAIN #1 — SEQUENCER ═══════════════════

    function revealAndUpdate(bytes32 reveal, bytes32 newRoot, bytes32 daHash) external {
        bytes32 c = keccak256(abi.encode(reveal, newRoot, daHash));
        require(commits[c] != 0, "NO_COMMIT");
        require(block.number > commits[c], "SAME_BLOCK");
        require(keccak256(abi.encode(reveal)) == sequencerAnchor, "BAD_CHAIN");
        require(block.timestamp >= lastHaltTimestamp + HALT_COOLDOWN, "HALT_COOLING");
        _tryAutoFinalize();
        delete commits[c];
        sequencerAnchor = reveal;
        pendingRoot = newRoot;
        pendingDaHash = daHash;
        pendingTimestamp = block.timestamp;
        pendingBlock = block.number;
        pendingHalted = false;
        emit RootUpdated(newRoot, daHash);
    }

    // ═══════════════════ CHAIN #2 — DATA AVAILABILITY ═══════════════════

    function publishDA(bytes calldata chunk, bytes32 rootRef, bytes32 daReveal) external {
        bytes32 chunkHash = keccak256(chunk);
        require(chunkHash != _SEAL_TAG, "RESERVED_HASH");
        bytes32 dc = keccak256(abi.encode(chunkHash, rootRef, daReveal));
        require(commits[dc] != 0, "NO_COMMIT");
        require(block.number > commits[dc], "SAME_BLOCK");
        require(keccak256(abi.encode(daReveal)) == daAnchor, "BAD_DA_CHAIN");
        require(rootRef == pendingRoot, "WRONG_ROOT");
        require(!daSealed[rootRef], "DA_SEALED");
        require(chunk.length > 0, "EMPTY_CHUNK");
        require(chunk.length <= MAX_CHUNK_BYTES, "CHUNK_TOO_BIG");
        uint256 idx = chunkCount[rootRef];
        require(idx < MAX_CHUNKS_PER_ROOT, "TOO_MANY_CHUNKS");
        delete commits[dc];
        daAnchor = daReveal;
        daRollingHash[rootRef] = keccak256(abi.encode(daRollingHash[rootRef], chunkHash));
        chunkHashes[rootRef][idx] = chunkHash;
        chunkCount[rootRef] = idx + 1;
        emit DAChunkPublished(rootRef, idx, daRollingHash[rootRef]);
    }

    function sealDA(bytes32 rootRef, bytes32 daReveal) external {
        bytes32 sc = keccak256(abi.encode(_SEAL_TAG, rootRef, daReveal));
        require(commits[sc] != 0, "NO_COMMIT");
        require(block.number > commits[sc], "SAME_BLOCK");
        require(keccak256(abi.encode(daReveal)) == daAnchor, "BAD_DA_CHAIN");
        require(rootRef == pendingRoot, "WRONG_ROOT");
        require(!daSealed[rootRef], "ALREADY_SEALED");
        require(daRollingHash[rootRef] != bytes32(0), "NO_DATA");
        delete commits[sc];
        daAnchor = daReveal;
        daSealed[rootRef] = true;
        emit DASealed(rootRef, daRollingHash[rootRef]);
    }

    // ═══════════════════ WATCHDOG ═══════════════════

    function respondChallenge(bytes calldata chunkData) external {
        bytes32 root = pendingRoot;
        require(root != bytes32(0), "NO_PENDING");
        require(!pendingHalted, "HALTED");
        require(daSealed[root], "DA_NOT_SEALED");
        uint256 cc = chunkCount[root];
        require(cc > 0, "NO_CHUNKS");
        bytes32 entropy = keccak256(abi.encode(root, block.prevrandao));
        require(!_challengeUsed[root][entropy], "ALREADY_RESPONDED");
        _challengeUsed[root][entropy] = true;
        uint256 idx = uint256(entropy) % cc;
        require(keccak256(chunkData) == chunkHashes[root][idx], "WRONG_CHUNK");

        bool progress = false;

        uint256 word = idx >> 8;
        uint256 bit = 1 << (idx & 0xFF);
        if ((_seenChunks[root][word] & bit) == 0) {
            _seenChunks[root][word] |= bit;
            uniqueChunks[root]++;
            progress = true;
        }

        uint256 epoch = (block.number - pendingBlock) / EPOCH_SIZE;
        if (epoch >= EPOCH_COUNT) epoch = EPOCH_COUNT - 1;
        uint256 epochBit = 1 << epoch;
        if ((epochBitmap[root] & epochBit) == 0) {
            epochBitmap[root] |= epochBit;
            progress = true;
        } else {
            epochBitmap[root] |= epochBit;
        }

        if (progress && watchdogPool >= VERIFICATION_REWARD) {
            watchdogPool -= VERIFICATION_REWARD;
            (bool ok,) = msg.sender.call{value: VERIFICATION_REWARD}("");
            if (!ok) watchdogPool += VERIFICATION_REWARD;
        }
        emit ChallengeResponded(root, idx, msg.sender);
    }

    function fundWatchdog() external payable {
        require(msg.value > 0, "ZERO_VALUE");
        watchdogPool += msg.value;
        emit WatchdogFunded(msg.sender, msg.value);
    }

    function _requiredVerifications(bytes32 root) internal view returns (uint256) {
        uint256 cc = chunkCount[root];
        uint256 proportional = (cc * COVERAGE_BPS) / BPS_DENOM;
        uint256 floor = cc < MIN_VERIF_CAP ? cc : MIN_VERIF_CAP;
        return proportional > floor ? proportional : floor;
    }

    // ═══════════════════ CHAIN #3 — GUARDIAN ═══════════════════

    function haltPendingRoot(bytes32 guardianReveal) external {
        require(!pendingHalted, "ALREADY_HALTED");
        require(pendingRoot != bytes32(0), "NO_PENDING");
        require(keccak256(abi.encode(guardianReveal)) == guardianAnchor, "BAD_GUARDIAN");
        guardianAnchor = guardianReveal;
        pendingHalted = true;
        lastHaltTimestamp = block.timestamp;
        emit RootHalted(pendingRoot);
    }

    // ═══════════════════ FINALIZATION ═══════════════════

    function finalizeRoot() external {
        bytes32 p = pendingRoot;
        require(p != bytes32(0), "NO_PENDING");
        require(!pendingHalted, "HALTED");
        require(block.timestamp >= pendingTimestamp + CHALLENGE_WINDOW, "TOO_EARLY");
        require(daSealed[p] && daRollingHash[p] == pendingDaHash, "DA_MISMATCH");
        require(uniqueChunks[p] >= _requiredVerifications(p), "LOW_COVERAGE");
        require(_popcount(epochBitmap[p]) >= MIN_EPOCHS, "LOW_EPOCH_COVERAGE");
        finalizedRoot = p;
        pendingRoot = bytes32(0);
        emit RootFinalized(p);
    }

    function _tryAutoFinalize() internal {
        bytes32 p = pendingRoot;
        if (
            p != bytes32(0) && !pendingHalted
                && block.timestamp >= pendingTimestamp + CHALLENGE_WINDOW && daSealed[p]
                && daRollingHash[p] == pendingDaHash
                && uniqueChunks[p] >= _requiredVerifications(p)
                && _popcount(epochBitmap[p]) >= MIN_EPOCHS
        ) {
            finalizedRoot = p;
            emit RootFinalized(p);
            pendingRoot = bytes32(0);
        }
    }

    // ═══════════════════ EMERGENCY WITHDRAWAL ═══════════════════

    function withdraw(
        address owner,
        address token,
        uint256 balance,
        bytes32 credentialHash,
        address withdrawTo,
        bytes32 pqPreimage,
        bytes32[] calldata merkleProof
    ) external {
        require(supportedTokens[token], "UNSUPPORTED");
        require(withdrawTo.code.length > 0, "EOA_BLOCKED");
        require(keccak256(abi.encode(pqPreimage)) == credentialHash, "BAD_CRED");
        bytes32 leaf = keccak256(
            abi.encodePacked(
                LEAF_PREFIX,
                abi.encode(
                    block.chainid, address(this), owner, token, balance, credentialHash, withdrawTo
                )
            )
        );
        require(_verifyMerkle(leaf, merkleProof, finalizedRoot), "BAD_PROOF");
        require(!claimed[leaf], "CLAIMED");
        claimed[leaf] = true;
        if (token == address(0)) {
            (bool ok,) = withdrawTo.call{value: balance}("");
            require(ok, "ETH_FAIL");
        } else {
            IERC20(token).safeTransfer(withdrawTo, balance);
        }
        emit Withdrawal(owner, token, balance, withdrawTo);
    }

    // ═══════════════════ INTERNAL ═══════════════════

    function _verifyMerkle(bytes32 leaf, bytes32[] calldata proof, bytes32 root)
        internal
        pure
        returns (bool)
    {
        require(proof.length <= MAX_MERKLE_DEPTH, "TOO_DEEP");
        bytes32 c = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            c = c <= proof[i]
                ? keccak256(abi.encode(c, proof[i]))
                : keccak256(abi.encode(proof[i], c));
        }
        return c == root;
    }

    function _popcount(uint256 x) internal pure returns (uint256 c) {
        while (x != 0) {
            x &= x - 1;
            c++;
        }
    }

    receive() external payable {}
}
