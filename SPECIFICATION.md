# Quantum Bunker — Technical Specification

**v3.8 · February 2026**

---

## 1. Overview

Quantum Bunker is an emergency withdrawal contract that enables L2 bridge users to recover funds when elliptic-curve cryptography is broken by quantum computers. It uses a single cryptographic primitive — `keccak256` — to authenticate operators, verify data availability, and authorize withdrawals.

The contract is designed to be **walkaway-safe**: no governance, no admin keys, no upgrades. Once deployed, it operates autonomously for the duration of its hash chain capacity (27+ years).

---

## 2. Architecture

Three independent keccak256 hash chains serve distinct roles:

| Chain | Operator | Links | Purpose |
|---|---|---|---|
| #1 | Sequencer | 1,000,000 | Posts state roots with DA commitments |
| #2 | DA Publisher | 10,000,000 | Publishes data chunks to permanent L1 calldata |
| #3 | Guardian | 10,000 | Emergency halt (1 link = 1 day cooldown) |

**Hash chain mechanics:** Each chain is a sequence of keccak256 preimages. The contract stores the current anchor (tip). To authenticate, the operator reveals a value whose hash equals the anchor. The anchor advances; the link is consumed.

**Universal commit-reveal:** All three chains share a single commit mapping. Before revealing a chain link, the operator commits `keccak256(domain-specific preimage)` in block N, then reveals in block N+1 or later. This prevents mempool frontrunning.

**Domain separation:** Each chain type uses a structurally distinct preimage:
- Root: `keccak256(abi.encode(reveal, newRoot, daHash))`
- DA: `keccak256(abi.encode(keccak256(chunk), rootRef, daReveal))`
- Seal: `keccak256(abi.encode(SEAL_TAG, rootRef, daReveal))`

A guard prevents any chunk whose hash equals `SEAL_TAG` from being published, eliminating cross-domain collisions.

---

## 3. Lifecycle

### Phase 1: Root Submission
The sequencer commits and reveals a new state root bound to a DA hash. The previous pending root auto-finalizes if eligible. A 7-day challenge window begins.

### Phase 2: Data Publication
The DA publisher splits the state diff into chunks (<=750KB each, <=4096 total) and publishes each via committed transactions. Each chunk hash is folded into a rolling hash. After all chunks: seal DA, locking the set.

### Phase 3: Stochastic Verification
Any party calls `respondChallenge`. The contract uses `keccak256(root, block.prevrandao)` to select a random chunk index. The caller submits the chunk data; the contract verifies against the stored hash.

Rewards (0.001 ETH) are paid only when the response contributes **progress**: a new unique chunk index OR a new temporal epoch. This bounds the maximum payout per root.

### Phase 4: Guardian Oversight
The Guardian can halt any pending root by consuming one chain link. Each halt triggers a 1-day cooldown. The Guardian does not prove fraud; it buys time for social verification.

### Phase 5: Finalization
After 7 days, if: not halted, DA sealed and hash matches, >=10% unique chunks verified, >=10 temporal epochs covered — anyone can finalize.

### Phase 6: Withdrawal
Users prove balance via Merkle proof against finalized root. Authentication: `keccak256(pqPreimage) == credentialHash`. Funds sent to `withdrawTo` (immutable, sealed in leaf).

Leaf structure: `keccak256(LEAF_PREFIX || abi.encode(chainid, address(this), owner, token, balance, credentialHash, withdrawTo))`

---

## 4. Watchdog Economics

### Break-even Model
```
break_even_basefee = VERIFICATION_REWARD / (21000 + floor_nonzero * chunk_bytes)
```

| Chunk Size | Gas (EIP-7623) | Break-even |
|---|---|---|
| 300 B | 33K | ~30 gwei |
| 1 KB | 61K | ~16 gwei |
| 2 KB | 103K | ~10 gwei |
| 32 KB | 1.33M | ~0.75 gwei |

### Budget Model (per root, 500 chunks)
- Unique chunks needed: 100 (10%)
- Epochs needed: 10
- Max progress events: ~110
- Budget: **0.11 ETH/root**
- Annual (1 root/week): **5.7 ETH**
- Endowment (27 years): **~154 ETH**

### Three Modes
1. **Permissionless** — basefee < break-even. Bots participate for reward.
2. **Operator-Assisted** — basefee > break-even. Operator self-answers at cost.
3. **Self-Answer Only** — pool empty. Operator funds verification directly.

---

## 5. Cryptographic Lineage

The withdrawal mechanism implements hash-based preimage credential recovery — the same pattern proposed by Vitalik Buterin for Ethereum's quantum emergency fork (ethresear.ch, March 2024).

The Ethereum Foundation's PQ team (led by Thomas Coratger, January 2026) targets hash-based cryptography at the consensus layer via leanVM. The Bunker applies the same primitive at the application layer. Different scope, same foundation. Complementary.

---

## 6. Deployment Parameters

| Parameter | Guidance |
|---|---|
| Merkle tree | Include `block.chainid` + `address(this)` in every leaf. All leaves must be unique. |
| Chunk size | <=2 KB for 10 gwei target. <=300 B for 30 gwei. |
| Watchdog funding | ~0.11 ETH/root x frequency. Endowment model recommended. |
| Tokens | Exclude rebase tokens. Use wrapped versions (wstETH). |
| withdrawTo | Immutable contracts only. No proxy, admin, selfdestruct. |
| Guardian ops | Halt-first-evaluate-later for any unverified root with sealed DA. |
| Monitoring | Track respondChallenge profitability = f(basefee, chunk_size). |

---

## 7. Threat Model

See [THREAT_MODEL.md](./THREAT_MODEL.md) for the complete list of 14 documented limitations with mitigations.
