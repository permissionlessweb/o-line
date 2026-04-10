# ── Team Management ──────────────────────────────────────────────────────────

team-sync:
	bash scripts/team-sync.sh

team-list:
	bash scripts/team-list.sh

team-tools:
	bash scripts/team-tools.sh

team-gen spec='oline-tools.yml':
	bash scripts/team-gen.sh $spec

team-status:
	echo "Use 'just team-list' for status"

team-clean:
	rm -rf .team/ .claude/skills/ .opencode/agents/ gen-tools/

team-update:
	bash scripts/team-update.sh

team-docs team='special-teams':
	bash scripts/gen/team-gen.sh {{team}}

# ── Documentation & Tools Generation ────────────────────────────────────────

gen-docs:
	python3 scripts/gen-docs.py

gen-tools:
	#!/usr/bin/env bash
	set -e
	echo "==> Generating o-line tools from CLI reference"
	python3 scripts/gen-tools.py --verbose
	echo "==> o-line tools generated in .team/tools/"
	echo "   - oline_tools.json (OpenAI tool schemas)"
	echo "   - oline_executor.py (Python executor)"
