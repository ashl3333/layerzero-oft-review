#!/usr/bin/env bash
#
# check-oft-dvn-config.sh
# ------------------------
# Audit a LayerZero OFT / OApp's DVN configuration on Ethereum mainnet.
# For each source EID, prints the required DVN count, optional threshold, and a
# PASS / FAIL verdict. A verdict of EXPOSED means the pathway would accept a
# packet if a single DVN is compromised.
#
# Released by Blockaid in the wake of the KelpDAO rsETH bridge incident
# (Apr 2026). Source: https://gist.github.com/IdoBn/7753f16fdb6810b11c5c87cdf11f8aa0
#
# Usage:
#   ./check-oft-dvn-config.sh <YOUR_OAPP_ADDRESS> [EID1 EID2 ...]
#
# Example:
#   ./check-oft-dvn-config.sh 0x85d456B2DfF1fd8245387C0BfB64Dfb700e98Ef3 \
#       30320 30110 30111 30184 30181 30214 30109 30102
#
# Requires: foundry (https://getfoundry.sh). Install with:
#   curl -L https://foundry.paradigm.xyz | bash && foundryup

set -euo pipefail

OAPP="${1:-}"
shift || true

if [ -z "$OAPP" ]; then
  echo "usage: $0 <OAPP_ADDRESS> [EID1 EID2 ...]" >&2
  exit 1
fi

# Default EIDs to check if none passed: common mainnet source EIDs
EIDS=("$@")
if [ ${#EIDS[@]} -eq 0 ]; then
  EIDS=(30101 30102 30106 30109 30110 30111 30181 30184 30214 30230 30320)
fi

RECV_LIB="${RECV_LIB:-0xc02Ab410f0734EFa3F14628780e6e695156024C2}"
RPC="${ETH_RPC_URL:-https://ethereum-rpc.publicnode.com}"

echo ""
echo "OApp / OFTAdapter DVN configuration audit"
echo "Adapter:  $OAPP"
echo "Library:  $RECV_LIB (ReceiveUln302, Ethereum)"
echo ""
printf "  %-6s  %-8s  %-9s  %s\n" "EID" "required" "threshold" "verdict"
printf "  %-6s  %-8s  %-9s  %s\n" "------" "--------" "---------" "--------"

EXPOSED_COUNT=0

for EID in "${EIDS[@]}"; do
  OUT=$(cast call --rpc-url "$RPC" "$RECV_LIB" \
    "getUlnConfig(address,uint32)((uint64,uint8,uint8,uint8,address[],address[]))" \
    "$OAPP" "$EID" 2>/dev/null || echo "error")

  if [ "$OUT" = "error" ]; then
    printf "  %-6s  %-8s  %-9s  %s\n" "$EID" "?" "?" "RPC error"
    continue
  fi

  REQ=$(echo "$OUT" | awk -F',' '{print $2}' | tr -d ' ')
  THR=$(echo "$OUT" | awk -F',' '{print $4}' | tr -d ' ')
  SUM=$((REQ + THR))

  if [ "$SUM" -le 1 ]; then
    VERDICT="EXPOSED"
    EXPOSED_COUNT=$((EXPOSED_COUNT + 1))
  else
    VERDICT="OK"
  fi

  printf "  %-6s  %-8s  %-9s  %s\n" "$EID" "$REQ" "$THR" "$VERDICT"
done

echo ""
if [ "$EXPOSED_COUNT" -gt 0 ]; then
  echo "  $EXPOSED_COUNT pathway(s) EXPOSED — requiredDVNCount + optionalDVNThreshold <= 1."
  echo "  Pause the adapter or reconfigure with >=2 independent DVNs per pathway."
else
  echo "  All checked pathways OK."
fi
echo ""
