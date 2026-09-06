#!/usr/bin/env bash
set -euo pipefail
script_dir=${BASH_SOURCE[0]%/*}
[[ ${BASH_SOURCE[0]} == */* ]] || script_dir=.
spike_dir=$(cd -- "$script_dir" && pwd)
read -r pinned_version < "$spike_dir/.foundry-version"

# Stubs ensure these checks never compile Rust or invoke the installed Forge.
cargo() {
  printf 'ERROR: Cargo ran before tool checks finished\n' >&2
  return 97
}
export -f cargo

check_case() (
  label=$1
  mock_version=$2
  expected_status=$3
  expected_message=$4
  shift 4
  export mock_version
  # The child Bash process calls this exported stub.
  # shellcheck disable=SC2329
  forge() {
    if [[ $mock_version == broken ]]; then
      return 43
    fi
    printf 'forge Version: %s\nCommit SHA: test\n' "$mock_version"
  }
  export -f forge
  if [[ $mock_version == missing ]]; then
    unset -f forge
  fi

  cd -- "$spike_dir"
  for verify_script in "$spike_dir/verify.sh" verify.sh; do
    status=0
    output=$(PATH=/nonexistent /bin/bash "$verify_script" "$@" 2>&1) || status=$?
    if [[ $status != "$expected_status" || $output != *"$expected_message"* || $output == *'Cargo ran'* ]]; then
      printf 'FAIL: %s via %s (exit %s)\n%s\n' "$label" "$verify_script" "$status" "$output" >&2
      exit 1
    fi
  done
  printf 'PASS: %s\n' "$label"
)

check_case 'pinned release' "$pinned_version-v$pinned_version" 0 "Forge $pinned_version verified" --check-tools-only
check_case 'plain release version' "$pinned_version" 0 "Forge $pinned_version verified" --check-tools-only
check_case 'wrong release' '0.0.0' 1 "Forge $pinned_version required" --check-tools-only
check_case 'nightly rejected' "$pinned_version-nightly" 1 "Forge $pinned_version required" --check-tools-only
check_case 'missing Forge' missing 1 "Forge $pinned_version required; forge not found" --check-tools-only
check_case 'broken Forge' broken 1 'Could not read Forge version' --check-tools-only
check_case 'full verify rejects wrong Forge before Cargo' '0.0.0' 1 "Forge $pinned_version required"
check_case 'full verify rejects missing Forge before Cargo' missing 1 "Forge $pinned_version required; forge not found"
