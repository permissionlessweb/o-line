#!/usr/bin/env bash
set -euo pipefail

echo "=== O-Line Team Sync ==="

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p .team/agents .team/sync .claude/skills

# Copy existing specialists from docs
if [[ -d docs/specialists ]]; then
  echo "Copying docs/specialists to .team/agents..."
  cp docs/specialists/*.md .team/agents/ 2>/dev/null || echo "No existing specialists found"
  count=$(ls .team/agents/*.md 2>/dev/null | wc -l | tr -d ' ')
  echo "Copied ${count:-0} specialists"
else
  echo "No docs/specialists directory - specialists will be available after manual creation"
fi

# Sync to Claude (.claude/skills/)
echo "Creating Claude skills (.claude/skills/)..."
count=0
for agent in .team/agents/*.md; do
  if [[ -f "$agent" ]]; then
    name=$(basename "$agent" .md)
    mkdir -p ".claude/skills/$name"
    ln -sf "${REPO_ROOT}/${agent}" ".claude/skills/$name/SKILL.md"
    echo "  + $name"
    count=$((count + 1))
  fi
done

# Sync to opencode (~/.opencode/agents/)
echo "Creating opencode agents (~/.opencode/agents/)..."
mkdir -p ~/.opencode/agents
oc_count=0
for agent in .team/agents/*.md; do
  if [[ -f "$agent" ]]; then
    name=$(basename "$agent" .md)
    ln -sf "${REPO_ROOT}/${agent}" ~/.opencode/agents/"${name}.md"
    oc_count=$((oc_count + 1))
  fi
done
echo "  ${oc_count} agents linked"

echo ""
echo "Sync complete! ${count} specialists activated"
echo "Claude:   .claude/skills/*"
echo "Opencode: ~/.opencode/agents/*"
