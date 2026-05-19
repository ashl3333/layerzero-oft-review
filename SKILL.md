---
name: layerzero-oft-review
description: Security review checklist for LayerZero v2 OFT / OFT Adapter (EVM, Aptos Move, Sui Move). Triggers when user wants to audit / review / inspect an OFT, OApp, LayerZero bridge, ULN/DVN configuration, cross-chain token supply reconciliation, lzReceive/lzCompose access control, enforced options, single lockbox / decimals consistency, allowInitializePath, initialization gate; or evaluate a new project under a defi-sec-report repo. Covers DVN stack, send/receive library (default vs custom), Executor, enforced options, admin/delegate (EVM owner / Aptos MSafe / Sui AdminCap), rate limit, blocklist, escrow reconciliation, upgradeability (Solidity proxy / Aptos object code / Sui UpgradeCap), and more.
---

# LayerZero OFT Security Review Skill

Standard checklist for reviewing a LayerZero v2 OFT (Omnichain Fungible Token). Prefer **verifying via on-chain `view` functions yourself — do NOT trust the frontend / docs / GitHub repo alone**. Once deployed, mutable config on an OFT (DVN, library, peers, rate limit, blocklist) can be changed at any time by the admin.

> **Official cross-reference**: This skill mirrors the LayerZero official [Integration Checklist](https://docs.layerzero.network/v2/tools/integration-checklist) and extends it with multi-chain (Aptos / Sui) coverage and threat-model content. Each section has a §0.5 cross-reference index.
>
> Report style reference: `defi-sec-report/stargate-aptos-bnb/stargate-aptos-bnb-review.md` (prior example in the same repo).

---

## 0. Triage Checklist

Before starting, pin these facts down — all subsequent analysis depends on them:

| Item | Question to answer | How to check |
|---|---|---|
| Which platform? | EVM (Solidity) / Aptos Move / Sui Move — three very different models; lookup methods, trust models, and upgrade mechanisms all differ. Sui uses an owned `AdminCap` + a shared `OApp` object + the package ID as the peer. | Chain + look at source / module names |
| OFT or OFT Adapter? | On EVM, `token()` returning self → **pure OFT (mint/burn)**; returning a different ERC20 → **OFT Adapter (lock/release)**. On Aptos / Sui, a module name containing `oft_adapter_*` indicates adapter (Aptos uses `oft_adapter_fa`, Sui uses `oft_adapter_coin`). | view: `token()` / look at module names |
| Which chain is the "native" chain? | The adapter chain is native; the others are mint/burn. The supply-reconciliation baseline lives in the escrow on the native chain. | Deployment order, docs, `tvl()` |
| How many peers? | Each peer adds attack surface; cross-peer mint vulnerabilities have happened repeatedly. | `peers(eid)` (EVM) / `get_peer(eid)` (Aptos) / read the `peers` table on the `OApp` shared object (Sui) |
| Is it a Stargate Pool? | Stargate is an application on LZ with a unified liquidity pool — don't conflate. A pure OApp does not route through Stargate. | Inspect contract source / docs |
| Is the LZ Endpoint address correct? | The EVM v2 endpoint on most major chains is `0x1a44076050125825900e736c501f859c50fe728c`; Aptos is `0xe60045e2...4f43c`; Sui (EID 30378) is `0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac`. Anything else is suspicious. | view: `endpoint()` / look at the OFT call target |

Fill the above into Section 1 "Basic Info Table" of the report.

---

## 0.5 Mapping to the LayerZero Official Integration Checklist

While reviewing, walk through the table below to make sure every item in the official Quick Checklist has a conclusion (✅ / ⚠ / 🔴):

| Official item | Section in this skill |
|---|---|
| **Peers set on all pathways (bidirectional)** | §7 |
| **DVN configuration set on all pathways** | §1 |
| **Executor configuration set on all pathways** | §3 |
| **Enforced options configured for gas/value** | §4 |
| **Mock and test functions removed** | §4.5 (implementation-layer grep) |
| **Ownership and delegate addresses verified** | §5 |
| **Using latest LayerZero packages** | §4.5 |
| **Libraries explicitly set (no reliance on defaults)** | §2 |
| **Message safety checks (single action / IFG)** | §4.5, §10 |
| **`msg.value` checks in `lzReceive`/`lzCompose`** | §4 + §4.5 |
| **Single Lockbox Adapter Rule / decimals consistency** | §6.0 |
| **`allowInitializePath` and initialization gate** | §7.2 |
| **Authority transfer order (delegate before owner)** | §5.3 |

> Anti-patterns quick reference: see §14.

---

## 1. DVN (Decentralized Verifier Network) — Most Important

The DVN is the real trust root of LayerZero v2. **All required DVNs must sign + optional DVNs must hit the threshold before a packet verifies**. An attacker who controls the keys of every required DVN can forge any `_credit` and drain the escrow.

### 1.0 Golden Formula (EXPOSED Verdict)

```
k = requiredDVNCount + optionalDVNThreshold

k <= 1  ->  EXPOSED  (compromise of a single DVN forges packets -> entire escrow lost)
k = 2   ->  Minimum acceptable (LZ default)
k >= 3  ->  Good
```

Historic precedent: **KelpDAO rsETH bridge incident (Apr 2026)** — one pathway was configured with `required=1, optional=0` (k=1); after one DVN was compromised, the attacker forged cross-chain mint messages. After the fact, Blockaid released `check-oft-dvn-config.sh`, which scans every pathway of an OFT for k-value (bundled into this skill, see §12).

When reviewing an OFT, the **first action** is to run this script (or, for non-Ethereum chains, manually read the ULN config), list the k-value for every peer, and flag any k ≤ 1 in red.

### 1.1 Required Checks

For "every peer path" (both send and receive directions), read:

```
endpoint.getConfig(oapp, lib, eid, configType=2 /* ULN */)
-> UlnConfig {
    confirmations,              // finality blocks to wait on source chain
    requiredDVNCount,           // all must sign
    optionalDVNCount,
    optionalDVNThreshold,       // number of optionals required
    requiredDVNs[],             // address list
    optionalDVNs[]
}
```

**Shortcut: on EVM you can hit the library directly without going through the endpoint** (no need to look up the effective lib first):
```
ReceiveUln302.getUlnConfig(oapp, srcEid) -> same UlnConfig struct
SendUln302.getUlnConfig(oapp, dstEid)
```

Aptos version: `endpoint::get_config(oapp, lib, eid, config_type=2)` → same UlnConfig.

### 1.2 Red Flags

| Situation | Severity | Notes |
|---|---|---|
| **k ≤ 1** (`requiredDVNCount + optionalDVNThreshold <= 1`) | 🔴 **Critical** | Same as KelpDAO rsETH. Any pathway tripping this should prompt pausing the adapter. |
| Any required DVN address marked `deprecated: true` in LZ metadata | 🔴 High | Old addresses can be retired at any time → packets get stuck. Demand admin upgrade to current version. |
| Only 1 required DVN | 🔴 High | Single point of failure; leak of that DVN's key = escrow gone. LZ default recommendation is at least 2-of-2 required. |
| Required DVN includes `LZDeadDVN` (e.g. `0xe9b5...0ee6D9C` and similar known placeholder addresses) | 🔴 High | The "dead DVN" LZ stuffs into unconfigured paths; it never signs → packets stuck forever. This means the OApp **hasn't set its DVN — it's relying on default**, and the default for that path is empty. |
| Required DVN count ≥ 1 but optional threshold = 0 | 🟠 Medium | If any required DVN goes offline, packets DoS with no backup. Recommend adding 1-of-N optional fallback. |
| Send and receive DVN sets are asymmetric | 🟠 Medium | The same trust assumption should hold in both directions; otherwise one direction is weaker than the other. |
| All required DVNs are operated by the same party (e.g. all LayerZero Labs) | 🟠 Medium | Nominally N-of-N, actually 1 trust source. The real question is the operator independence of the DVNs. |
| `confirmations` set too low (below the chain's consensus safety window) | 🟡—🔴 | Reorg attack risk. Full default table in §1.4. |
| Config equals default | 🟡 Depends | The default may not be optimised for this specific path (see §2). |

### 1.3 DVN Address Verification

Don't just look at hex addresses — cross-check against LayerZero deployment metadata:
- All-chain metadata: <https://metadata.layerzero-api.com/v1/metadata> (or the LayerZero deployments repo)
- Each DVN has a `canonicalName`, `deprecated` marker, `endpointAcl`, etc.
- Quick jq to pull DVNs for a chain: `curl -s https://metadata.layerzero-api.com/v1/metadata | jq '."<chainKey>".dvns'` (chainKey examples: `ethereum`, `bsc`, `aptos`, `sui`).

In the report, label every DVN with `(operator, current/deprecated)`, e.g.:
- `0xa2ceb887...ababbde8` (**BitGo, current**)
- `0xdf8f0a53...078d8da` (**LayerZero Labs, deprecated** ⚠)

#### Sui mainnet DVN current reference (from metadata, May 2026)

| Operator | current address | deprecated address (🔴 if OFT still uses) |
|---|---|---|
| LayerZero Labs | `0x52aa1290...e2df6878b0ed2213d94d3c827309aeae685` | `0xc3f25fb1...e2f20d5a76a7fd9264340b4af949fd38b` |
| Mysten Labs | `0x3efa9a92...f7c437d13515796d2842376e97ce82cba` | `0xef6da181...ae0f0f545522278ffc6d15fa3b01ed` |
| Nethermind | `0x0c12321e...199a8f31a4cea3a417ce72477f6dfebb` | `0x0557fbac...4956a7ce1ad280a47f00d6c3126e2ff6` |
| Horizen | `0x92128a5e...41b37faf705ceb3d9d9a4e5c306fbf91` | `0x9edc19a8...457106e14179842a9c6c3fe0a87db6d59f` |
| BitGo | `0x825963b9...e069e5bd28e720b9ec00b06dc995cb3ab53708dbb62912367` | — |
| Luganodes | `0xb5c7e0ad...60bdc2af6d39af3de088f06bdccb35ecfd7d9465579cb55` | — |
| Nansen | `0x8c4e6f80...82f9fb46d26e8763c77982a299cc427e6f136012398760a` | — |
| B-Harvest | `0x4a9cb9e7...e04f0416ef41d3828d4a9598deb4da0fc7edb86a3976fbe` | — |
| P2P | `0x38f0cf09...140df4a57f904e4c851deeb747ec4f737a00564a6cda2551` | — |
| Deutsche Telekom | `0x6d593b3f...58ad01d21de6bd4673535f83cceda8a4287cb187eafaac464` | — |
| Canary | `0xfa35508c...341113f8f9397e5f41750b833af87d0c945a6f5682887f0` | — |

(Full addresses: run `curl ... | jq '."sui".dvns'`.)

### 1.4 Confirmations vs Official Defaults

`confirmations` is the number of blocks to wait on the source chain before a DVN is allowed to sign. **Too low → reorg attack risk** (DVNs sign packets that won't finalize, but the dst chain has already minted); **too high → UX latency** (users wait forever).

#### LayerZero official defaults (V1 published table, mostly carried over to V2)

| Chain | default | Notes |
|---|---|---|
| Ethereum | **15** | PoS slot ~12s → ~3 min |
| BSC | **20** | ~3s × 20 = 60s |
| Avalanche | **12** | ~2s × 12 |
| **Polygon** | **512** | History of PoS reorgs — requires significantly more than other chains |
| Arbitrum | **20** | L2 — L1 finality is the real finality, but short-term sequencer reorg risk is small |
| Optimism | **20** | Same as Arbitrum |
| Base | **10** | Same OP stack |
| Scroll | **5** | |
| Mantle | **2** | (V1 table; V2 may have adjusted) |
| Fantom | **5** | |
| Celo / Gnosis / Klaytn / Metis | **5** | |
| zkSync / zkPolygon | **20** | |
| Aptos | **260** (de-facto V2 norm) | V1 docs said 500,000 but that's outdated; V2 OApps generally use 260 (~40s); **try `0` to confirm default**. |
| **Sui** | (query metadata / benchmark against active OApps like USDT0) | Sui finality ~3s (checkpoint), no reorgs under BFT consensus; usually a single-digit number of checkpoints is enough |
| Solana | (query LZ scan for active OApps on that EID) | Not covered in the V1 table |

V1 full table: <https://docs.layerzero.network/v1/developers/evm/technical-reference/mainnet/default-config>

#### Interpreting OApp value vs default

| Observed value vs default | Interpretation | Severity |
|---|---|---|
| = default | ✅ Consistent with official | — |
| < default but still ≥ chain consensus safety window | 🟡 OApp trading a bit of reorg buffer for UX; acceptable but call it out in the report | 🟢 Low |
| < default AND < chain consensus safety window (e.g. Ethereum < 12) | 🔴 High | Reorg attack window |
| = 0 | 🟡 Equivalent to using LZ default; **trust root floats with LZ default** — when LZ raises the default the OApp follows | 🟡 Medium |
| >> default | 🟢 Conservative; slower UX | 🟢 Low |
| Asymmetric across send/receive (different value each direction) | ⚠ Note: the source `confirmations` in the send config of one chain should equal the receive config on the counterparty; mismatch indicates the two OApps are out of sync on upgrades | 🟡 Medium |

#### How to find the "real V2 default"

LZ V2 docs intentionally don't publish a per-chain default table (so OApps configure their own). In practice, three ways to discover the default:
1. **Read `endpoint.defaultUlnConfig(eid)`** (or the same-named function on the corresponding library) — most authoritative.
2. **Use LZ scan, find an OApp on that EID with all-zero settings**, and observe the effective config.
3. **Compare against major OApps on the same chain (USDT0, Ethena, etc.)**: they generally use default or very close to it.

Report style: for each pathway, list "OApp value / LZ default / verdict" in three columns.

### 1.5 Quantified Threat Model

The report must explicitly write:
- **N-of-M meaning**: k required DVNs → **collusion of k private keys can forge a packet**; **any one DVN refusing to sign = DoS**.
- Bidirectional attack surface: src-chain DVN signs incorrectly → dst chain gets minted; if dst-chain DVN set differs, attack vectors differ.

---

## 2. Send / Receive Library (default or not)

The LayerZero v2 endpoint maintains a send library and a receive library pointer per (oapp, eid). Each can be:
- **Default** (the library LZ has designated for that path officially, usually `SendUln302` / `ReceiveUln302`)
- **OApp-set** (set by the OApp delegate via `endpoint.setSendLibrary` / `setReceiveLibrary`)

### 2.1 Required Checks

```solidity
// EVM
endpoint.getSendLibrary(oapp, dstEid)            // does not signal default — returns effective lib directly
endpoint.getReceiveLibrary(oapp, srcEid)         // returns (lib, isDefault)
endpoint.isDefaultSendLibrary(oapp, dstEid)      // explicit check for default
endpoint.defaultSendLibrary(eid)
endpoint.defaultReceiveLibrary(eid)
```

```move
// Aptos
endpoint::get_effective_send_library(oapp, eid)
endpoint::get_effective_receive_library(oapp, eid)   // returns (lib, is_default)
endpoint::get_default_send_library(eid)
endpoint::get_default_receive_library(eid)
```

```move
// Sui — read endpoint_v2 shared object via devInspect or PTB.
// Note: on Sui mainnet sendUln302 and receiveUln302 share the same package address:
//   0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0
// They share a Move package but remain two logical libraries.
endpoint_v2::endpoint_v2::get_effective_send_library(endpoint, oapp_pkg, dst_eid)
endpoint_v2::endpoint_v2::get_effective_receive_library(endpoint, oapp_pkg, src_eid)
endpoint_v2::endpoint_v2::get_default_send_library(endpoint, eid)
```

### 2.2 Red Flags

| Situation | Severity | Notes |
|---|---|---|
| Effective lib != `SendUln302` / `ReceiveUln302` (LZ v2 standard ULN) | 🟠 Medium — 🔴 High | Possibly a **custom / non-audited library**. Any non-ULN302 must be traced to source to inspect verify logic. There are historical OFTs that broke after switching libraries. |
| Send uses default but receive uses OApp-set (or vice versa) | 🟡 Medium | Asymmetric — investigate why only one direction was overridden. |
| Library is `BlockedMessageLib` (e.g. `0x...dead`) | 🟠 Medium | Effectively disables that pathway. Possibly an intentional pause, but if the deployment claims it is usable then there's an inconsistency. |
| Uses default lib + default DVN, but default DVN contains `LZDeadDVN` | 🔴 High | Equivalent to no configuration → sends/receives fail. New OFT deployments commonly fall into this trap (especially when adding a new peer but forgetting `setConfig`). |
| Library is a deprecated version (after LZ upgrades from ULN302 → ULN302a/b the older lib may be retired) | 🟠 Medium | Same logic as deprecated DVNs. |

### 2.3 "Default Config" is Not "Safe Config"

**Important concept correction**: many people think "using default = not changed = safe". In reality:
- For an (oapp, eid) pair where the OApp has set nothing, LZ returns the default; the default is what LZ sets uniformly **for that eid path**.
- But the default may use newer DVNs, **or** may not be set at all for cold / newly-added paths (= `LZDeadDVN` placeholder).
- Using default = **outsourcing your trust root to LZ official** (when LZ upgrades the default DVN, the OApp follows automatically). For risk-sensitive projects, the recommendation is for the OApp to set its own DVN + library to "freeze the trust assumption".
- Conversely, once the OApp sets its own config, it won't follow LZ when LZ upgrades the default → easy to end up with deprecated DVNs (see §1.2).

In the report, explicitly state one of:
- "**Both ends override the default**, using OApp-customised ULN config" — or —
- "**Following LZ default**, trust root follows LZ official" — or —
- "**One end overridden, the other end default**" (treat as config inconsistency).

---

## 3. Executor

The Executor is responsible for calling `lzReceive` on the destination chain. Compromise leads to DoS but **does not directly forge packet contents** (that requires DVNs).

```solidity
endpoint.getConfig(oapp, lib, eid, configType=1 /* EXECUTOR */)
-> ExecutorConfig { maxMessageSize, executor }
```

Red flags:
- Executor is not the LZ Labs canonical executor AND not self-managed by the project — unknown origin.
- `maxMessageSize` abnormally large (>10_000) — possible DoS vector; LZ default is 10_000.
- Custom executor: check whether it has access control, and whether anyone can trigger lzReceive.

LZ Labs canonical executor reference (commonly used):
- BSC: `0x3ebD570ed38B1b3b4BC886999fcF507e9D584859`
- Aptos: `0x15a5bbf1eb7998a22c9f23810d424abe40bd59ddd8e6ab7e59529853ebed41c4`
- **Sui**: `0xde7fe1a6648d587fcc991f124f3aa5b6389340610804108094d5c5fbf61d1989`
- Other chains: look up LZ deployments metadata.

---

## 4. Enforced Options

The OApp can set "enforced minimum options" per `(eid, msgType)` (currently mostly `lzReceive` gas limit). Not setting it or setting too low → packet OOG → stuck.

```solidity
oapp.enforcedOptions(eid, msgType=1 /* SEND */)
oapp.enforcedOptions(eid, msgType=2 /* SEND_AND_CALL */)
```

Red flags:
- Not set → users carry their own `extraOptions` at `send` time; if the dapp frontend passes insufficient gas → stuck. LZ strongly recommends at least setting type 1 `lzReceive` gas.
- `_lzReceive` internally calls expensive logic (e.g. swap, external call) but enforced gas <200k → easy OOG.
- Composer path not set — after receiving, composing to another contract gets stuck.

### 4.1 `msg.value` Encoding and Verification

When `_lzReceive` / `lzCompose` needs to forward native value (ETH / APT / SUI) on the destination chain, enforced options alone aren't enough — the option only tells the Executor "I will bring this much value", the **OApp must verify the value is actually sufficient** itself, otherwise an attacker can send a zero-value packet to trigger partial execution.

```solidity
// 1. Sender: encode msg.value into the payload
bytes memory payload = abi.encode(receiver, amount, msgValue);
_lzSend(dstEid, payload, options, fee, refundAddress);

// 2. Receiver: verify
function _lzReceive(Origin calldata, bytes32, bytes calldata _message, address, bytes calldata) internal override {
    (address receiver, uint256 amount, uint256 expectedValue) = abi.decode(_message, (address, uint256, uint256));
    require(msg.value >= expectedValue, "insufficient value");   // <- required check
    // ...
}
```

Red flags:
- `_lzReceive` receives value but **does not require msg.value >= expected** → executor can short-pay, the downstream call reverts and the channel jams.
- Solana OFT uses **static** enforced options to carry ATA creation cost → first transfer to an uninitialised account requires extra value, but later transfers don't; a fixed value either wastes or under-pays.
- Enforced options carry a large amount of native value but no refund path → value stuck in the OApp.

---

## 4.5 OApp Receiver / Composer Implementation Layer

If the project uses the official LZ `OAppReceiver` base, access control is built in. For **custom receivers** or **lzCompose** (the Composer interface has **no** built-in checks from LZ), this section is mandatory.

### 4.5.1 `_lzReceive` access control (custom OAppReceiver)

```solidity
function lzReceive(Origin calldata _origin, bytes32 _guid, bytes calldata _message, address _executor, bytes calldata _extraData) external payable {
    require(msg.sender == address(endpoint), "!endpoint");              // <- required check 1: only endpoint can call
    require(_origin.sender == peers[_origin.srcEid], "!peer");          // <- required check 2: srcEid matches peer, not forged
    // ... business logic
}
```

Red flags:
- Missing `msg.sender == endpoint` → any EOA can call `lzReceive` directly to forge arbitrary packets, **the entire LZ trust root is bypassed**. Multiple historical exploits.
- Missing `_origin.sender == peer` check → if any peer chain is compromised, it can impersonate other peers.
- `_origin.srcEid` not whitelisted → any LZ-supported eid can send packets in.

### 4.5.2 `lzCompose` access control (must be added by hand)

```solidity
function lzCompose(address _from, bytes32 _guid, bytes calldata _message, address _executor, bytes calldata _extraData) external payable {
    require(msg.sender == address(endpoint), "!endpoint");   // <- required check
    require(_from == address(oApp), "!oApp");                // <- required check: source OApp is the expected one
    // ... compose logic
}
```

The `ILayerZeroComposer` interface has **no** built-in checks; the project must add them. Missing them = any EOA can call `lzCompose` directly to manipulate compose state.

### 4.5.3 Pre-launch Grep

| Item | Command | Why |
|---|---|---|
| Mock / test functions left in | `grep -rE 'mock\|MOCK\|setDebug\|cheat\|forceMint' src/` | Boilerplate copied from the LZ example repo often leaves high-privilege fns like `_mintForTest` |
| `_disableInitializers()` | `grep -n '_disableInitializers' src/**.sol` | For upgradeable contracts, the implementation must call this in its constructor, otherwise the implementation can be init'd by an attacker who can then `selfdestruct` (old OZ) or pollute storage |
| Hardcoded EID / endpoint | `grep -nE '0x1a44076050125825900e736c501f859c50fe728c\|uint32\(3010[0-9]\)' src/` | Should go through an admin-restricted setter, not hardcoded — otherwise can't migrate when LZ upgrades the endpoint or adds new chains |
| Package version | Check `package.json` / `Move.toml` for `@layerzerolabs/*` — should be latest; don't **copy** source code from the LZ examples repo into your repo, use the published package | A copied version goes stale and won't keep up with LZ upgrades to ULN / endpoint interfaces |

---

## 5. Governance / Admin / Delegate

A LayerZero OApp has two privileged roles:
- **owner / admin**: application-layer config (setPeer, enforcedOptions, rate limit, blocklist).
- **delegate**: endpoint-layer config (setConfig changes DVN / library).

Typically admin == delegate; **this amplifies the impact of a single point of compromise** (R4-level risk).

### 5.1 Required Checks

```solidity
oft.owner()                           // EVM
endpoint.delegates(oapp)              // EVM
```
```move
oapp_core::get_admin(oapp)            // Aptos
oapp_core::get_delegate(oapp)         // Aptos
```

**Sui's permission model is different** — there's no `msg.sender`; instead it uses **owned capability objects**:
- `AdminCap` is an owned object; whoever holds that object is the admin.
- Similarly, the delegate on Sui is "the address holding a particular capability object".
- How to check:
  ```bash
  # 1. Read the OApp shared object first, find its AdminCap object ID (usually in OApp.admin_cap_id)
  sui client object <OAPP_SHARED_OBJ_ID> --json | jq '.data.content.fields'
  # 2. Then query the AdminCap object and read its owner field
  sui client object <ADMIN_CAP_OBJ_ID> --json | jq '.data.owner'
  ```
  Owner can be:
    - `{"AddressOwner": "0x..."}` — single address (EOA or multisig address)
    - `{"Shared": {...}}` — shared (rare; if the AdminCap is shared, anyone can call admin functions → 🔴 catastrophic)
    - `{"ObjectOwner": "0x..."}` — held by another object (inspect that parent object's access control)
    - `{"Immutable"}` — frozen; admin functions permanently disabled

For every admin address, also check:
- **Is it an EOA or a multisig?** (EVM: `getOwners()` / Safe; Aptos: `multisig_account::owners` / MSafe; **Sui: `sui client object <addr>` to see whether it's a multisig threshold object, or use [SuiVision](https://suivision.xyz) to inspect the address type**)
- What is the multisig threshold m-of-n?
- Whether the multisig's historical execution looks reasonable (real usage vs brand-new 0 tx).

### 5.2 Red Flags

| Situation | Severity |
|---|---|
| owner / delegate is an EOA | 🔴 High |
| Multisig threshold 1-of-N or N=1 | 🔴 High |
| owner = deployer instead of a governance multisig | 🟠 Medium |
| owner is a multisig but its members are other EOAs | 🟠 Medium |
| admin ≠ delegate (rare, sometimes intentional separation) | 🟢 Usually a good sign |
| Contract is upgradeable (EVM proxy / Aptos object code deployment / Sui UpgradeCap not burned) + admin matches any of the above red flags | 🔴 High — equivalent to full control over the escrow |
| **Sui only**: AdminCap owner is `Shared` | 🔴 Critical — anyone can call admin functions |
| **Sui only**: AdminCap is held by a wrapper object that is itself shared | 🔴 Depending on wrapper logic — effectively shared |

In the report, list each key address's multisig m-of-n, number of owners, and historical tx count.

### 5.3 Authority Transfer Order (deployment-residue risk)

LZ OApp authority transfer **must do delegate first, then ownership**, because `setDelegate` can only be called by the `owner`:

```
1. (deployer) -> setDelegate(governance_multisig)
2. (deployer) -> transferOwnership(governance_multisig)
```

If the order is reversed: after `transferOwnership`, the deployer loses the ability to call `setDelegate`, and only the new owner can change the delegate. If the new owner isn't ready in between, the delegate is stuck on the deployer EOA.

Red flags (inspect transaction history):
- `Ownership transferred` event predates `DelegateSet` → there may have been a window with the delegate stuck on the deployer EOA.
- After launch, owner is a multisig but `endpoint.delegates(oapp)` is still the deployer EOA → **endpoint-layer config (DVN / library / setConfig) controlled by an EOA**, equivalent to an R4 red flag. The report must call this out explicitly.
- Upgradeable proxy's `proxy admin` differs from the OApp `owner` → list both chains of trust (upgrade logic vs application config).

---

## 6. Cross-chain Supply Reconciliation (Supply Invariant)

This is the core invariant of an OFT. **Adapter chain escrow balance ≡ Σ(totalSupply of all mint/burn-type peer chains)**.

### 6.0 Adapter Type Selection + Decimals Consistency

The invariant only holds when there is a **single lockbox** AND **all deployments use the same shared decimals**. Confirm type + decimals alignment first, then compute reconciliation.

#### 6.0.1 Adapter Types (only one lockbox allowed)

| Token form | Native chain | Other chains |
|---|---|---|
| Brand-new token | Pure `OFT` | Pure `OFT` |
| Existing token with mint/burn | `MintAndBurnOFTAdapter` (uses the token's own mint/burn, no lockbox) | Pure `OFT` |
| Existing token without mint/burn | `OFTAdapter` (lockbox, locks inside the contract) | Pure `OFT` |
| Native gas token (ETH etc.) | `NativeOFTAdapter` | Pure `OFT` |

**🔴 Single Lockbox Rule**: **The entire deployment can only have one** `OFTAdapter` / `NativeOFTAdapter` (lockbox type). If two chains both deploy an adapter, both lock their own supply and the cross-chain mint creates an extra copy → **double-spend / supply inflation**. `MintAndBurnOFTAdapter` is not a lockbox (it uses the token's own mint/burn), so multiple are OK, but reconciliation is still required.

How to check:
- For each chain, read `token()` → if ≠ self, that chain is an adapter; count all adapters and confirm that **only one** is the lockbox type (OFTAdapter / NativeOFTAdapter).
- For the adapter chain, read `tvl()` / inspect the escrow balance. For other chains, read `totalSupply()`. Apply the formula in §6.1.

#### 6.0.2 Decimals Consistency

```solidity
oft.sharedDecimals()        // usually 6, must be consistent across all deployments
oft.decimals()              // local decimals, can vary per chain (EVM 18, Aptos 8, Sui depends on the Coin)
oft.decimalConversionRate() // = 10 ** (LD - SD)
```

Red flags:
- Any two chains have different `sharedDecimals` → cross-chain amounts are unequal after SD conversion, **each transfer loses a bit**, accumulating to escrow inflation or user loss long-term.
- Some chain has LD < SD (in theory impossible, but config bugs surface this) → `decimalConversionRate` becomes 0, packet reverts.
- LD too low so the max supply overflows on that chain: for example, 18 decimals on EVM, 1B tokens = 10^27; if a peer chain stores in u64 (Aptos / Sui), **max is 2^64-1 ≈ 1.8e19**, so the chain can carry at most ~18 billion at 6 decimals; if the token total supply is larger, overflow / packet truncation risk exists. The report must compute "max capacity on that chain vs token max supply".
- Custom codec (non-LZ standard type-safe bytes codec) → any encoding difference causes the destination to decode incorrectly, directly minting to the wrong address or wrong amount. Grep `decode`/`encode` in source and cross-check against LZ `OFTMsgCodec`.

#### 6.0.3 Minter / Burner Permissions (non-lockbox OFTs)

Pure OFT / MintAndBurnOFTAdapter calls the underlying token's `mint`/`burn` on the destination chain — **the OFT contract itself must hold that role**.

```solidity
// Check on the underlying token
token.hasRole(MINTER_ROLE, oft)        // ERC20 with AccessControl
token.minter()                         // simplified single-minter variant
```

```move
// Aptos: the fungible_asset MintRef / BurnRef must be held inside the OFT module
// Look at how the OFT module's initialization function obtains the MintRef
```

Red flags:
- OFT lacks mint role → cross-chain inbound reverts, packet jams the channel.
- mint role held by multiple addresses (OFT + EOA + other contracts) → supply not solely governed by LZ; when §6.3 reconciliation fails, root cause is unattributable.

### 6.1 Calculation

```
adapter_escrow_balance =? sum over peers of peer.totalSupply()
```

Watch out for:
- **Decimal conversion**: when SD (shared decimals, usually 6) < LD (local decimals), dust truncation aggregates small amounts < 1 SD unit.
  - Aptos LD=8 → loss up to 0.0099 / transfer
  - EVM LD=18 → loss up to 0.999999 / transfer
  - Accumulated dust over 10k packets ≤ 10k SD units ≈ 0.01 ELON-ish.
- **In-flight packets**: packets that have been `_debit`'d but not yet `_credit`'d cause adapter > Σ(peers).
- **Fees**: when fee_bps > 0, the adapter accumulates fees.

### 6.2 Red Flags

| Δ(adapter − Σpeers) | Interpretation |
|---|---|
| 0 | ✅ Perfect. |
| Small positive ≈ expected dust + in-flight | ✅ Acceptable. |
| **Large positive** (e.g. 50k tokens) | 🟠 Possibly pre-mint at deployment, big in-flight packet, or accumulated fees. **Must confirm in the BSC-end OFT source code whether any owner-only `mint()` is exposed**. |
| **Negative** (Σpeers > adapter) | 🔴 High — severe supply inflation, possibly an owner mint, a bridge bug, or partial escrow drain. |

### 6.3 Required: Does any peer expose mint?

For non-native chains (mint/burn OFTs), grep the source code:
- `function mint(` — any owner-only arbitrary mint means the OFT is not strictly 1:1 backed.
- `_mint` should only be called within `_credit` (originating from lzReceive).
- Look for controls like `mintLimit` / `mintCap`.

---

## 7. Peers

```solidity
oft.peers(eid)         // EVM, returns bytes32
```
```move
oapp_core::get_peer(oapp, eid)      // Aptos
oapp::oapp::get_peer(oapp, eid)     // Sui — read the peers Table inside the OApp shared object
```

Red flags:
- Peer is not the OFT itself on the dst chain (might be a malicious contract) — cross-check the dst chain's `oft.endpoint()`.
- Peer = 0 but the OApp claims the eid is available — config inconsistency.
- Lots of historical peers (e.g. 30 entries, only 2 actually used) — abandoned paths can still be attacked.
- Peer EVM bytes32 padding is incorrect (high bits non-zero) — config bug, packets get treated as sent to a non-existent address.
- **Sui-specific**: peer must be the **package ID** on the dst (not an object ID), because LZ uses the package address as the OAppRegistry key on Sui. Writing in an object ID = packets will never be received.

### 7.2 `allowInitializePath` and the Initialization Gate

The LayerZero v2 endpoint calls the OApp's `allowInitializePath(Origin)` on the dst chain when the first packet arrives, to confirm the path can be initialized.

```solidity
function allowInitializePath(Origin calldata _origin) public view returns (bool) {
    return peers[_origin.srcEid] == _origin.sender;       // <- LZ default logic
}
```

Red flags:
- Custom `allowInitializePath` override always returns `true` → any source eid + any sender can initialize the path; equivalent to turning off peer verification.
- Override depends on mutable state (e.g. `block.timestamp` / external oracle) → the same path may or may not be initializable at different times, hard to debug.
- Hardcoded `return false` → the path can never be initialized, packets all stuck; deployments that forgot to flip it back to `true` have caused incidents.

### 7.3 Runtime initialization / verification diagnostics

When packets **look like they should arrive but don't** (LZ Scan shows verified but dst didn't execute, or vice versa), these views are mandatory for runtime triage:

```solidity
endpoint.initializable(origin, receiver)        // can the path be initialized (allowInitializePath result)
endpoint.verifiable(origin, receiver)           // can the packet be committed (DVNs signed + lib accepts)
endpoint.inboundPayloadHash(receiver, srcEid, sender, nonce)   // the stored commit hash; = 0 means not yet committed
```

Equivalent functions exist on the Aptos / Sui endpoint module.

Interpretation:
- `initializable=false` + first-time inbound → §7.2 red flag.
- `verifiable=true` but dst didn't execute → DVNs signed but Executor never called `lzReceive`; see §3 Executor.
- `inboundPayloadHash != 0` but dst didn't mint → `lzReceive` reverted internally; see §10 DoS patterns.
- For a stuck packet, these three views + LZ Scan pinpoint exactly which layer (DVN / commit / execute) is stuck.

---

## 8. Rate Limit / Blocklist / Fee

### 8.1 Rate Limit

```move
oft_adapter_fa::rate_limit_config(eid)    -> (limit, window)
oft_adapter_fa::rate_limit_capacity(eid)  -> currently available capacity
```

Red flags:
- No rate limit (`limit=0` or `u64::MAX`): once DVN/admin is compromised, the escrow can be drained in a single shot.
- Only one direction set (only outbound or only inbound limited).
- Window too long (e.g. 30-day daily cap) → no real rate limiting.

### 8.2 Blocklist

```move
oft_impl_config::blocklist_enabled
oft_impl_config::is_blocklisted(addr)
oft_impl_config::irrevocably_disable_blocklist  // irreversible kill switch
```

Red flags:
- `blocklist_enabled=true` and `irrevocably_disable_blocklist` not called → admin can freeze any address at will.
- **`redirect_to_admin_if_blocklisted`**: when a blocklisted address receives a LZ packet, **the funds are redirected to admin** — equivalent to admin being able to seize tokens from any recipient. This is required compliance for Circle USDC, but is a high privilege for a generic OFT. The report must warn users explicitly.
- Blocklist has non-empty entries → dump and list them for the user.

### 8.3 Fee

```move
oft_adapter_fa::fee_bps
oft_adapter_fa::fee_deposit_address
```

Red flags:
- `fee_bps` too high (>100 = 1%).
- `fee_deposit_address` is an EOA (`0x1::account::Account` exists alone, no `MultisigAccount` resource).
- Fee path not logged via events → not auditable.

---

## 9. Upgradeability

| Platform | Form | How to check |
|---|---|---|
| EVM | UUPS / Transparent proxy | `eth_getStorageAt(addr, ERC1967_IMPL_SLOT)` / Etherscan's "Read as Proxy" |
| Aptos | Object Code Deployment | `0x1::code::PackageRegistry` + check whether `ExtendRef` / `UpgradeCap` is held |
| **Sui** | **UpgradeCap (Move package upgrade)** | Find the `UpgradeCap` object for the package; inspect its `policy` (`COMPATIBLE` / `ADDITIVE` / `DEP_ONLY`) and owner; if it has been `make_immutable`'d the cap is gone = ✅ immutable |
| Solana | Program upgrade authority | `solana program show <programId>` |

**Sui UpgradeCap lookup**:
```bash
# Reverse-lookup the UpgradeCap owning a package (easier via GraphQL or an indexer)
# Or: from the project's deploy tx, sui client tx <DEPLOY_DIGEST>, look at created objects — the UpgradeCap will be there
sui client object <UPGRADE_CAP_ID> --json | jq '.data.content.fields, .data.owner'
# Important fields:
#   .fields.policy: 0=COMPATIBLE (can add new functions without altering old), 128=ADDITIVE, 192=DEP_ONLY (only deps modifiable)
#   .owner: same as AdminCap — check whether it's AddressOwner / Shared / Immutable
```

Red flags:
- Upgradeable + admin is an m-of-n multisig with small m → escrow trust root = that multisig.
- Missing timelock — upgrades have no cooling-off period.
- Docs claim "immutable" but upgrade authority still exists — inconsistency.
- **Sui only**: UpgradeCap policy = `COMPATIBLE` (default, allows arbitrary new logic) + single-address owner → equivalent to an EVM admin-proxy. Prefer to see `DEP_ONLY` policy or the cap `make_immutable`'d.

---

## 10. Historical DoS Patterns

If `_lzReceive` / `lz_receive_impl` / Sui `lz_receive` aborts, **the entire channel is blocked for all subsequent packets** (LZ v2 ordering).
- OtterSec 2022 finding on Aptos Bridge.
- Common triggers: `_credit` to a non-existent / frozen account, unavailable redirect target, external call revert, destination object already destroyed on Sui.
- **Sui-specific**: hot-potato `Call` objects that aren't properly destroyed cause the entire PTB to revert → equally blocks the channel. The Sui OFT lz_receive path must verify that every branch calls `Call::complete()` / `destroy_call()`.

When reviewing, grep `_credit` / `credit` and inspect every possible abort path; confirm each has a fallback.

### 10.1 Message Bundling Safety / IFG

OFT packet design recommends "**one message, one action**" (transfer + optional compose call). If an OApp packs multiple actions in a single message (transfer A, swap B, stake C), any step reverting blocks the whole channel.

Red flags:
- `_lzReceive` payload decodes into multiple actions executed sequentially, with intermediate steps that may revert (swap slippage, insufficient stake allowance, etc.) → entire packet jams.
- Bundled compose chains (`OFT → swap → lending`) with no try/catch fallback.
- For `OAppPreCrime` or LZ Instant Finality Guarantee (IFG)-sensitive scenarios: confirm whether the receiver uses an `LzReceiveAlert` / IFG-aware base, otherwise the BFT finality assumption doesn't hold.
- Sui PTB chaining multiple hot-potato calls in a single tx → any one step aborting fails the entire PTB; same logic as EVM but the abort mode is more explicit.

Review recommendations:
- For complex compose paths, require the project to add an escape hatch (`pendingMessage` queue + admin retry / refund).
- Payload schema must include a version field so future upgrades don't break old messages.

---

## 11. Report Output Template

Mirror `defi-sec-report/stargate-aptos-bnb/stargate-aptos-bnb-review.md`. At minimum include:

1. **Basic info table**: token, metadata, adapter/OFT address (EVM contract / Aptos resource account / Sui package ID + shared OApp object), endpoint, peer EIDs, decimals, admin address (Sui: AdminCap owner), totalSupply.
2. **Role definition**: where the adapter sits, where minting happens, whether it's Stargate, peer count.
3. **Module / contract tree**: list the main modules / contracts and their responsibilities.
4. **Send and receive money flow**: textual flow diagram.
5. **Verified on-chain configuration** (raw view-function output).
6. **Governance structure table**: admin / delegate / fee_deposit / escrow, each one's form and multisig threshold.
7. **Cross-chain supply reconciliation**: adapter escrow vs Σpeers, delta interpretation.
8. **Risk list** (numbered R1..Rn, each with severity / detail).
9. **Full DVN / Executor config**: both directions, required / optional / threshold / confirmations / executor / max_message_size, marked current/deprecated.
10. **Immediate verification / action checklist**: 🔴 high items first.
11. **Conclusion**: overall standard, main residual risks, user-facing caveats.
12. **Appendix**: key addresses, reference sources (LZ docs, historic audits).

---

## 12. Tooling Quick Reference

### 12.1 Bundled script

`scripts/check-oft-dvn-config.sh` — adapted from the version Blockaid released after the KelpDAO incident.
Usage (OFT/OApp on Ethereum mainnet):
```bash
./scripts/check-oft-dvn-config.sh $OAPP_ADDR
# Defaults to a list of common mainnet src EIDs; you can also pass them explicitly:
./scripts/check-oft-dvn-config.sh $OAPP 30102 30109
```
Output: per-pathway (required, threshold, verdict); verdict = EXPOSED means k ≤ 1.
For non-Ethereum chains, set `RECV_LIB` env var (look up the ReceiveUln302 address for that chain in LZ deployments metadata) and `ETH_RPC_URL`.

### 12.2 View Function Cross-Reference

| Task | EVM (cast) | Aptos (aptos CLI) | Sui (sui CLI / devInspect) |
|---|---|---|---|
| Token / OFT identification | `cast call $OFT "token()"` | `aptos move view --function-id $OFT::oft::shared_decimals` | `sui client object $OFT_OBJ --json` look at type; `devInspect` call `$PKG::oft::shared_decimals` |
| Peer | `cast call $OFT "peers(uint32)" $EID` | `aptos move view --function-id $OFT::oapp_core::get_peer --args address:$OFT u32:$EID` | devInspect `$PKG::oapp::get_peer($OAPP_OBJ, $EID)` |
| Send lib | `cast call $EP "getSendLibrary(address,uint32)" $OFT $EID` | `aptos move view --function-id $EP::endpoint::get_effective_send_library --args address:$OFT u32:$EID` | devInspect `endpoint_v2::endpoint_v2::get_effective_send_library($EP_OBJ, $OAPP_PKG, $EID)` |
| Receive lib | `cast call $EP "getReceiveLibrary(address,uint32)" $OFT $EID` | same as above, `get_effective_receive_library` | same as above, `get_effective_receive_library` |
| ULN config (DVN) via endpoint | `cast call $EP "getConfig(address,address,uint32,uint32)" $OFT $LIB $EID 2` | `endpoint::get_config(oapp, lib, eid, 2)` | devInspect `endpoint_v2::endpoint_v2::get_config($EP_OBJ, $OAPP_PKG, $LIB_PKG, $EID, 2)` |
| ULN config (DVN) via library (shortcut) | `cast call $LIB "getUlnConfig(address,uint32)((uint64,uint8,uint8,uint8,address[],address[]))" $OFT $EID` | n/a | devInspect `uln_302::uln_302::get_uln_config($ULN_OBJ, $OAPP_PKG, $EID)` (send/receive share the package) |
| Executor config | same getConfig but type=1 | same, type=1 | same, type=1 |
| Owner / Delegate | `cast call $OFT "owner()"`, `cast call $EP "delegates(address)" $OFT` | `oapp_core::get_admin` / `get_delegate` | **inspect the AdminCap object's `.data.owner`** (see §5.1) |
| Escrow / TVL | n/a (pure OFT is burn, no escrow) | `oft_adapter_fa::tvl()` / `escrow_address()` | devInspect `$PKG::oft_adapter_coin::tvl($OFT_OBJ)`; or read the `escrow: Balance<T>` field inside the OFT shared object |
| totalSupply | `cast call $TOKEN "totalSupply()"` | `0x1::fungible_asset::supply` | `sui client object $TREASURY_CAP_ID` see `total_supply`; or `0x2::coin::total_supply<T>` |
| Upgradeable? | proxy slot read | `0x1::code` | `sui client object $UPGRADE_CAP_ID` (see §9) |
| Initialization gate | `cast call $EP "initializable((uint32,bytes32,uint64),address)" "($SRC_EID,$SENDER,$NONCE)" $OFT` | `endpoint::initializable` | devInspect `endpoint_v2::initializable` |
| Verifiable | `cast call $EP "verifiable((uint32,bytes32,uint64),address)" "($SRC_EID,$SENDER,$NONCE)" $OFT` | `endpoint::verifiable` | devInspect `endpoint_v2::verifiable` |
| Inbound payload hash | `cast call $EP "inboundPayloadHash(address,uint32,bytes32,uint64)" $OFT $SRC_EID $SENDER $NONCE` | same | same |
| `allowInitializePath` override | `cast call $OFT "allowInitializePath((uint32,bytes32,uint64))" "(...)"` | OApp-implemented view | OApp-implemented view |

Sui devInspect template:
```bash
sui client ptb --gas-budget 10000000 --move-call \
  $PKG::oapp::get_peer @$OAPP_OBJ $EID \
  --serialize-output
# Or use SDK / GraphQL to run devInspectTransactionBlock (no on-chain tx)
```

### 12.3 Common Mainnet EIDs

| Chain | EID | Chain | EID |
|---|---|---|---|
| Ethereum | 30101 | Mantle | 30181 |
| BNB Chain | 30102 | Base | 30184 |
| Avalanche | 30106 | Scroll | 30214 |
| Polygon | 30109 | Linea | 30183 |
| Arbitrum | 30110 | Aptos | 30108 |
| Optimism | 30111 | Solana | 30168 |
| **Sui** | **30378** | | |

Full list: LZ deployments metadata.

### 12.4 LayerZero Official Resources

LayerZero deployments metadata (look up whether a DVN/Executor/Lib is deprecated, operator, per-chain addresses):
- <https://metadata.layerzero-api.com/v1/metadata>
- LayerZero deployments repo

Common Ethereum mainnet addresses (drop-in for the script):
- ReceiveUln302: `0xc02Ab410f0734EFa3F14628780e6e695156024C2`
- SendUln302: `0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1`
- Endpoint v2: `0x1a44076050125825900e736c501f859c50fe728c`

**Sui mainnet (EID 30378) common package addresses**:
- Endpoint V2: `0x31beaef889b08b9c3b37d19280fc1f8b75bae5b2de2410fc3120f403e9a36dac`
- SendUln302 / ReceiveUln302 (**same package**): `0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0`
- Executor (LZ Labs canonical): `0xde7fe1a6648d587fcc991f124f3aa5b6389340610804108094d5c5fbf61d1989`
- DVN current reference: see §1.3

---

## 13. Severity Quick Reference (mapped to risk levels)

| Level | Meaning |
|---|---|
| 🔴 High | Directly threatens escrow / supply invariant; or once triggered cannot be recovered; or single point of compromise. |
| 🟠 Medium-high | Becomes High if admin is compromised; or explicit DoS risk. |
| 🟡 Medium | Poor configuration but requires further conditions to cause loss. |
| 🟢 Low | Best-practice recommendation / centralization concern, low actual impact. |

---

## 14. Anti-patterns Quick Reference (LayerZero official "Don'ts" + historical incidents)

| Anti-pattern | Severity | Section | One-line "why" |
|---|---|---|---|
| Production has only 1 DVN (`required=1, optional=0`) | 🔴 | §1 | Same as KelpDAO — single key = entire escrow lost |
| Multiple required DVNs but same operator | 🟠 | §1.2 | Nominally N-of-N, actually 1-of-1; real independence is the trust root |
| Send/Receive DVN sets asymmetric | 🟠 | §1.2 | Bidirectional trust assumptions should be equal |
| Default Executor without a liveness evaluation | 🟡 | §3 | Executor is a DoS vector; LZ Labs default isn't guaranteed-SLA |
| Multiple lockbox-type adapters (OFTAdapter / NativeOFTAdapter) in one deployment | 🔴 | §6.0 | Double-spend / supply inflation |
| Inconsistent `sharedDecimals` across chains | 🔴 | §6.0.2 | Cross-chain amounts unequal, long-term escrow inflation |
| Adapter type swapped between chains (originally lockbox end changed to pure OFT) | 🔴 | §6.0.1 | Original chain's locked tokens orphaned, new chain mints uncapped |
| Hardcoded endpoint / EID instead of admin-restricted setter | 🟠 | §4.5.3 | Cannot migrate when upgrading endpoint / adding new chains |
| **Copying** source code from the LZ examples repo instead of using npm / Move.toml | 🟠 | §4.5.3 | Falls behind LZ upgrades; history has bugs from copied libs |
| Deployment leaves mock / test / debug fns (`_mintForTest` etc.) | 🔴 | §4.5.3 | High-privilege backdoor |
| One message packs multiple actions, any of which can revert | 🟠 | §10.1 | Jams the channel; LZ v2 ordering blocks all subsequent packets |
| Solana OFT uses static enforced options for ATA creation | 🟡 | §4.1 | First and subsequent transfers have different value needs; fixed value over/underpays |
| Upgradeable + admin is EOA or 1-of-N multisig | 🔴 | §5, §9 | Escrow trust root = that address |
| `_disableInitializers()` not called in implementation constructor | 🟠 | §4.5.3 | Implementation can be init'd by anyone and then manipulated |
| `transferOwnership` executed before `setDelegate` | 🟡 | §5.3 | Delegate may be stuck on deployer EOA |
| Custom `allowInitializePath` always returns `true` | 🔴 | §7.2 | Equivalent to disabling peer verification |
| `lzCompose` missing `msg.sender == endpoint` && `_from == oApp` checks | 🔴 | §4.5.2 | Any EOA can call, compose state arbitrarily manipulated |
| Custom receiver missing `msg.sender == endpoint` | 🔴 | §4.5.1 | Bypasses the entire LZ trust root directly |
