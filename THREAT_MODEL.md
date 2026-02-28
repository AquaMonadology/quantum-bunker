# Threat Model

## Honest Claim

This contract explicitly documents its boundaries. Overclaiming kills trust. If you're evaluating this contract, start here.

---

## N1 — Semantic Gap

A compromised sequencer can publish structurally valid but semantically fraudulent DA. The watchdog enforces **data availability**, not **data validity**. The contract cannot know whether a state diff is honest — only that the data is published, sampled, and publicly available for off-chain verification.

**Mitigation:** Social verification (A3). If DA is public and the state diff is fraudulent, the community can verify and the Guardian can halt.

## N2 — Calldata Economics

Under EIP-7623 (live, Pectra): floor 10/40 gas per zero/non-zero byte. EIP-7976 (DRAFT as of Feb 2026, current spec: 15/60) would worsen this ~50%.

Break-even: `VERIFICATION_REWARD / (21000 + floor_nonzero * B)`

| Chunk Size | Break-even (EIP-7623) | Break-even (EIP-7976 draft) |
|---|---|---|
| 300 B | ~30 gwei | ~25 gwei |
| 1 KB | ~16 gwei | ~12 gwei |
| 2 KB | ~10 gwei | ~7 gwei |

Beyond break-even: operator self-answer mode. **This is documented and expected, not a bug.**

If EIP-7976 parameters change before Glamsterdam, recalculate.

## N3 — Conditional Execution

A wrapper contract that checks `prevrandao` before executing can satisfy watchdog challenges selectively, only revealing data when the random index hits a "clean" chunk. This defeats probabilistic fraud detection entirely.

**Implication:** The watchdog is a dissemination tool, not a fraud detector. This is by design.

## N4 — Operational Dependency

The following are **security conditions**, not optional preferences:
- A10: Watchdog pool must be funded (~0.11 ETH/root)
- A11': Chunk size must respect basefee economics (<=2KB at 10 gwei)
- A12: Bot infrastructure must exist (or operator self-answers)

## N5 — Builder Censorship (PBS)

A cooperating block builder can delay `revealAndUpdate` by censoring the transaction. Expected delay per attempt: ~20s at 40% builder market share. Sustained censorship probability decays exponentially: P(1h) ~ 10^-120.

This is the structural cost of zero-ECC. Private transaction submission (Flashbots Protect, MEV Blocker) reduces but does not eliminate the surface.

## N6 — 2-Phase Liveness Cost

The universal commit-reveal mechanism converts every critical action into a 2-transaction protocol across >=2 blocks. This doubles inclusion dependency compared to a single-tx design.

**Trade-off:** Eliminates permanent liveness denial via mempool frontrunning (pre-commit cost was ~50K gas per griefed action).

## N7 — 27-Year Capacity is Arithmetic

The Guardian's 10K links x 1 day cooldown = 27.4 years. This is a cryptographic bound. The real bound is organizational: someone must operate the infrastructure.

## N8 — DA Chain Sizing

Chain #2 (10M links) supports ~2,441 full roots (4096 chunks each) or ~909K light roots (10 chunks). Sizing must be calibrated to expected root frequency at deployment.

## N9 — Orphan State

Overwritten or halted roots leave DA-related storage (chunkHashes, epochBitmap, seenChunks) permanently in contract state. Not reclaimable without gas-intensive cleanup loops. Acceptable for an emergency contract.

## N10 — withdrawTo Immutability

The destination address is fixed in the Merkle leaf at tree construction time. Must be an immutable contract (no proxy, no admin, no selfdestruct). If the receiver contract is compromised or self-destructed before Q-Day, funds going to that leaf are permanently locked.

## N11 — Watchdog Pool Funding

`fundWatchdog()` is donation-based. No auto-replenishment. Endowment at deployment is the recommended model: 200 ETH covers ~27 years at 1 root/week.

## N12 — MEV on respondChallenge

Front-running a watchdog response still delivers the chunk to L1 calldata — dissemination succeeds regardless of who captures the reward (G2 intact). However, systematic MEV extraction concentrates rewards among searchers, reducing permissionless bot diversity. This mirrors Aave liquidation dynamics.

## N13 — Asymptotic Sampling Tail

At 10% coverage of 4096 chunks, the last ~40 unique chunks require ~55 hours of L1 blocks (coupon collector tail). This is inherent to random sampling with replacement and completes within the 7-day challenge window with ~4.7 days of margin.

## N14 — Guardian Strategy Under Spam

A corrupt sequencer can post rapid roots via `revealAndUpdate` (each burning 1 chain link). Roots without sealed DA cannot finalize. The Guardian **MUST** implement "halt-first, evaluate-later" for any root with sealed DA it hasn't verified. `HALT_COOLDOWN` rate-limits the interaction to 1 root/day post-halt.
