#!/usr/bin/env bash
set -euo pipefail

team="${1:-special-teams}"
phase_file="src/workflow/phases/${team}.rs"
fd_category="${team//-/_}_FD"

echo "=== Generate team MD skeleton: $team ==="

if [[ ! -f "$phase_file" ]]; then
  echo "ERROR: $phase_file not found"
  exit 1
fi

# Extract step functions: pub async fn <name>(...)
steps=$(grep -E '^pub async fn [a-z_]+\(' "$phase_file" | sed 's/pub async fn //' | sed 's/ *(.*//')

# Extract config fields from FIELD_DESCRIPTORS
fields=$(grep -A 100 "pub const $fd_category:" src/lib.rs | grep 'define_fields!.*"'"${team//_/\/}" | head -20 | sed 's/.*"'"${team//_/\/}"'\/"\([^"]*\)".*/- \1/' | sed 's/"$//')

# Generate MD
cat << EOF > "docs/team/${team}.md"
# $team

## Persona
[Specialist persona stub - football metaphor, phase role, key responsibilities]

## Steps
$(echo "$steps" | sed 's/^/- /')

## Config Fields
$fields

## Playbook
[TBD]
EOF

echo "Generated docs/team/${team}.md"
