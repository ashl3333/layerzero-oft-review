# layerzero-oft-review

A Claude Code [skill](https://agentskills.io/specification) (and a stand-alone checklist) for security-reviewing **LayerZero v2 OFT / OFT Adapter** deployments across **EVM, Aptos Move, and Sui Move**.

## What this is

`SKILL.md` is a 14-section reviewer's checklist that covers:

- **DVN stack** — golden `k = requiredDVNCount + optionalDVNThreshold` formula, `LZDeadDVN` detection, current-vs-deprecated address tables (including Sui mainnet)
- **Send / Receive library** — default vs OApp-set, why "default" is not "safe"
- **Executor** — canonical addresses per chain, DoS attack surface
- **Enforced options** — gas + `msg.value` encoding/verification pitfalls
- **OApp Receiver / Composer access control** — the `lzReceive` / `lzCompose` checks LZ does NOT do for you
- **Governance / admin / delegate** — EVM owner, Aptos MSafe, **Sui `AdminCap` owner semantics**
- **Cross-chain supply reconciliation** — Single Lockbox Rule, `sharedDecimals` consistency, escrow vs Σ peer `totalSupply`
- **Peers + `allowInitializePath` + initialization gate**
- **Rate limit / blocklist / fee** — including `redirect_to_admin_if_blocklisted` semantics
- **Upgradeability** — EVM proxy, Aptos object code, **Sui `UpgradeCap` policies (COMPATIBLE / ADDITIVE / DEP_ONLY)**
- **Historical DoS patterns** — channel blocking, message-bundling safety, IFG
- **Report output template**
- **Tooling quick reference** — view-function cross-table for EVM/Aptos/Sui, common mainnet EIDs and addresses
- **Anti-patterns quick reference** — LayerZero official "Don'ts" plus historical incidents (KelpDAO rsETH, OtterSec Aptos Bridge finding, etc.)

Each section maps to LayerZero's official [Integration Checklist](https://docs.layerzero.network/v2/tools/integration-checklist) (see §0.5 cross-reference table).

## Bundled tool

`scripts/check-oft-dvn-config.sh` — audits a LayerZero OFT's DVN configuration on Ethereum mainnet and prints a PASS / EXPOSED verdict per pathway. Adapted from the version Blockaid released in the wake of the KelpDAO rsETH bridge incident (Apr 2026).

```bash
./scripts/check-oft-dvn-config.sh 0xYourOFTAddress
# Or pass explicit EIDs:
./scripts/check-oft-dvn-config.sh 0xYourOFTAddress 30102 30109
```

Requires [Foundry](https://getfoundry.sh) (`cast`). For non-Ethereum chains, override the `RECV_LIB` and `ETH_RPC_URL` env vars (look up the per-chain `ReceiveUln302` address from LZ deployments metadata).

## Installing as a Claude Code skill

Drop the contents of this repo into `~/.claude/skills/layerzero-oft-review/`:

```bash
mkdir -p ~/.claude/skills/layerzero-oft-review
cp SKILL.md ~/.claude/skills/layerzero-oft-review/
cp -r scripts ~/.claude/skills/layerzero-oft-review/
```

Then in Claude Code, whenever you ask to audit / review / inspect an OFT, OApp, ULN/DVN config, or related LayerZero v2 surface, the skill auto-activates.

## References

- LayerZero v2 docs: <https://docs.layerzero.network/v2>
- LayerZero deployments metadata: <https://metadata.layerzero-api.com/v1/metadata>
- Integration checklist: <https://docs.layerzero.network/v2/tools/integration-checklist>

## License

MIT
