# Quantum Bunker

### Post-Quantum Emergency Withdrawal for Ethereum L2 Bridges

> When Shor breaks ECDSA, your L2 bridge funds are naked. This is the exit door.

---

**~340 lines of Solidity. Zero elliptic-curve crypto. One primitive: `keccak256`.**

Quantum Bunker is a post-quantum emergency withdrawal smart contract for Ethereum L2 bridges. Deployed on Ethereum L1, it lets users recover their bridged assets (ETH, ERC-20) when ECDSA is broken, using only hash-based authentication that quantum computers cannot crack.

No signatures. No pairings. No BLS. Just hashes.

---

## The Problem

Ethereum L2 bridges (Base, Optimism, Arbitrum) hold **billions** in locked funds on L1. Every withdrawal relies on ECDSA signatures. The day a quantum computer runs Shor's algorithm, every Ethereum private key becomes public. Bridge funds drain in minutes.

The Ethereum Foundation [formed a Post-Quantum team](https://www.theblock.co/post/386938/ethereum-foundation-forms-post-quantum-security-team-adds-1-million-research-prize) in January 2026. NIST [deprecates ECC-256 by 2030](https://csrc.nist.gov/projects/post-quantum-cryptography). The clock is ticking, but no Ethereum L2 bridge has a deployable escape hatch.

Until now.

---

## How It Works

```
┌─────────────────────────────────────────────────────┐
│                  QUANTUM BUNKER                      │
│                                                      │
│  Chain #1 ─ Sequencer (1M links)                    │
│  Posts new state roots + DA commitments              │
│                                                      │
│  Chain #2 ─ DA Publisher (10M links)                │
│  Publishes data chunks to L1 calldata (permanent)    │
│                                                      │
│  Chain #3 ─ Guardian (10K links)                    │
│  Emergency halt. 1 link = 1 day cooldown = 27 years  │
│                                                      │
│  Watchdog ─ Stochastic verification                  │
│  prevrandao → random chunk → re-publish on L1        │
│  Pays 0.001 ETH per new unique chunk or epoch        │
│                                                      │
│  Withdrawal ─ Hash-based credential recovery         │
│  keccak256(preimage) == credentialHash → funds out    │
│  withdrawTo sealed in Merkle leaf (quantum-safe)      │
└─────────────────────────────────────────────────────┘
```

**Three keccak256 hash chains.** Each operator (sequencer, DA publisher, guardian) authenticates by revealing chain link preimages. No signatures needed. A universal commit-reveal mechanism prevents mempool frontrunning across all three chains.

**Forced data dissemination.** The watchdog doesn't detect fraud — it forces repeated publication of DA chunks on permanent Ethereum L1 calldata across multiple days, so anyone can verify off-chain.

**Hash-based withdrawal.** Same cryptographic pattern as [Vitalik's quantum emergency fork proposal](https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901). Users prove ownership via `keccak256(preimage)` instead of ECDSA. Funds go to an immutable receiver contract sealed in the Merkle tree — even if an attacker sees your preimage, they can't redirect funds.

---

## Security Properties

| Guarantees | Non-Guarantees |
|---|---|
| All DA on permanent Ethereum L1 calldata | Semantic correctness of state diffs |
| 10% unique chunk sample across >=10 epochs | Fraud detection (probabilistic only) |
| 7-day challenge window | Permissionless watchdog under high basefee |
| Guardian halt (27 years capacity) | Coverage of any specific chunk |
| **Zero ECC dependency** | Immunity to builder censorship |

This contract is radically honest about what it can and cannot do. Read the [full specification](./SPECIFICATION.md) for the complete threat model.

---

## Economics

The watchdog's viability depends on chunk size and Ethereum L1 basefee:

| Chunk Size | Gas (EIP-7623) | Break-even basefee |
|---|---|---|
| 300 B | 33K | ~30 gwei |
| 1 KB | 61K | ~16 gwei |
| 2 KB | 103K | ~10 gwei |
| 32 KB | 1.33M | ~0.75 gwei |

Above break-even: operator self-answers (documented, not a bug). Budget per root: ~0.11 ETH. Annual budget at 1 root/week: ~5.7 ETH. Total endowment for 27 years: ~154 ETH. Trivial for a multi-billion dollar bridge.

---

## Lineage

This implements the same hash-based preimage recovery pattern described in:

- **Vitalik Buterin** — [Quantum emergency fork proposal](https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901) (ethresear.ch, March 2024)
- **Ethereum Foundation** — [Post-Quantum team](https://www.theblock.co/post/386938/ethereum-foundation-forms-post-quantum-security-team-adds-1-million-research-prize) led by Thomas Coratger (January 2026)
- **Justin Drake** — leanVM as cornerstone of PQ strategy (consensus layer); Bunker operates at application layer

Same primitive (`keccak256`), different scope. The EF fork protects Ethereum L1 assets. The Bunker protects Ethereum L2->L1 bridge assets. Complementary.

---

## Project Structure

```
├── src/
│   └── QuantumBunker.sol       # The contract (~340 lines)
├── test/
│   └── QuantumBunker.t.sol     # Foundry test suite
├── script/
│   └── Deploy.s.sol            # Deployment script
├── SPECIFICATION.md            # Full technical specification
├── THREAT_MODEL.md             # Complete threat model (N1-N14)
└── foundry.toml                # Foundry configuration
```

## Build & Test

```bash
# Install dependencies
forge install

# Build
forge build

# Run tests
forge test

# Run tests with verbosity
forge test -vvv
```

---

## Deploy Checklist

1. Include `block.chainid` + contract address in every Merkle leaf
2. Ensure all Merkle leaves are unique
3. Set chunk size target based on expected basefee regime
4. Fund watchdog pool (~0.11 ETH per root x frequency)
5. Exclude rebase tokens — use wrapped versions (wstETH not stETH)
6. `withdrawTo` must be immutable receiver contracts
7. Guardian must implement halt-first-evaluate-later policy

---

## Status

- 29 patches applied
- 90+ attack vectors analyzed
- 14 documented limitations (honest claim)
- Full [technical specification](./SPECIFICATION.md)
- **Not yet formally audited** — treat as experimental

**This contract needs a professional security audit before any production use.** If you're a security researcher and you find something, open an issue. If you're a bridge team and this interests you, reach out.

---

<p align="center">
  <i>Built for the day we hope never comes.</i>
</p>
