#!/usr/bin/env bash
set -euo pipefail

echo "=== O-Line Team List ==="

if [[ ! -d .team/agents ]]; then
  echo "No .team/agents directory - run 'just team-sync' first"
  exit 1
fi

# List specialists
mapfile -t agents < <(ls .team/agents/*.md 2>/dev/null | sed 's|.*/||' | sed 's|\.md$||' | sort)
count=${#agents[@]}

if [[ $count -eq 0 ]]; then
  echo "No specialists found - run 'just team-sync'"
  exit 1
else
  echo "Active specialists ($count):"
  for agent in "${agents[@]}"; do
    echo "  • $agent"
  done
  echo ""
  echo "Sync status:"
  claude_count=$(ls .claude/skills/*/SKILL.md 2>/dev/null | wc -l 2>/dev/null || echo 0)
  opencode_count=$(ls ~/.opencode/skills/*.md 2>/dev/null | wc -l 2>/dev/null || echo 0)
  echo "  Claude CLI: $claude_count active skills"
  echo "  Opencode: $opencode_count active symlinks"
  echo "  Local files: $count specialist .md files"
  echo ""
  echo "Next: just team-tools to setup tool generation"
fi