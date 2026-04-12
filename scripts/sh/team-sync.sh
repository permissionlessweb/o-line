#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Syncing .team/agents to .claude/skills"

# .opencode/agents is a symlink to .team/agents — already in sync, skip

# Rebuild .claude/skills from scratch (fully managed by this script)
rm -rf "$REPO_ROOT/.claude/skills"
mkdir -p "$REPO_ROOT/.claude/skills"

for agent in "$REPO_ROOT/.team/agents"/*.md; do
  base_agent=$(basename "$agent")
  name="${base_agent%.md}"

  mkdir -p "$REPO_ROOT/.claude/skills/$name"
  ln -sf "$agent" "$REPO_ROOT/.claude/skills/$name/SKILL.md"
done

agent_count=$(ls "$REPO_ROOT/.team/agents"/*.md 2>/dev/null | wc -l | tr -d ' ')
echo "==> Synced $agent_count agents"
