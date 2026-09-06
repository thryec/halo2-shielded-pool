#!/usr/bin/env bash
set -euo pipefail
script_dir=${BASH_SOURCE[0]%/*}
[[ ${BASH_SOURCE[0]} == */* ]] || script_dir=.
cd -- "$script_dir"

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --check-tools-only ) ]]; then
  printf 'Usage: bash verify.sh [--check-tools-only]\n' >&2
  exit 1
fi

read -r required_forge < .foundry-version
if ! command -v forge >/dev/null 2>&1; then
  printf 'Forge %s required; forge not found. Install with: foundryup --install v%s\n' "$required_forge" "$required_forge" >&2
  exit 1
fi
if ! forge_version=$(forge --version); then
  printf 'Could not read Forge version\n' >&2
  exit 1
fi
forge_version=${forge_version%%$'\n'*}
case "$forge_version" in
  "forge Version: $required_forge"|"forge Version: $required_forge-v$required_forge") ;;
  *)
    printf 'Forge %s required; got %s. Install with: foundryup --install v%s\n' "$required_forge" "$forge_version" "$required_forge" >&2
    exit 1
    ;;
esac
printf 'Forge %s verified\n' "$required_forge"
if [[ ${1:-} == --check-tools-only ]]; then
  exit 0
fi

cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo metadata --locked --format-version 1 | jq -e \
  '[.packages[] | select(.name == "halo2-axiom" or .name == "halo2_proofs")] | length == 1'
cargo test --locked --release
cargo run --locked --release
forge test -vv
