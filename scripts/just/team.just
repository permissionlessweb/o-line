# ── Team Management ──────────────────────────────────────────────────────────

gen-team-sync:
	bash scripts/gen/gen-team-sync.sh

gen-team-list:
	bash scripts/gen/gen-team-list.sh

gen-team-tools:
	bash scripts/gen/gen-team-tools.sh

gen-team spec='oline-tools.yml':
	bash scripts/gen/gen-team.sh $spec

team-status:
	echo "Use 'just gen-team-list' for status"

team-clean:
	rm -rf .team/ .claude/skills/ .opencode/agents/ gen-tools/

gen-team-update:
	bash scripts/gen-team-update.sh

team-docs team='special-teams':
	bash scripts/gen/gen-team.sh {{team}}

# ── Documentation & Tools Generation ────────────────────────────────────────

# Generate docs/cli-reference.md from the installed oline help output.
# Depends on `release` so we always introspect the same optimized binary
# that `just install` ships (unified via OLINE_BIN in gen-docs.py).
gen-docs: release
	python3 scripts/gen/gen-docs.py

gen-tools:
	#!/usr/bin/env bash
	set -e
	echo "==> Generating o-line tools from CLI reference"
	python3 scripts/gen/gen-tools.py --verbose
	echo "==> o-line tools generated in .team/tools/"
	echo "   - oline_tools.json (OpenAI tool schemas)"
	echo "   - oline_executor.py (Python executor)"

# Generate Mermaid diagrams from trailmark code graph analysis.
# Requires: trailmark in .venv, trailofbits/skills plugin installed.
gen-diagrams threshold='15':
	bash scripts/gen/gen-diagrams.sh --threshold {{threshold}}

# Run trailmark structural analysis (blast radius, taint, complexity).
trailmark-analyze:
	#!/usr/bin/env bash
	set -e
	source .venv/bin/activate
	echo "==> Running trailmark structural analysis"
	uv run trailmark analyze --language rust --summary src/
	echo ""
	echo "==> Complexity hotspots (CC >= 10)"
	uv run trailmark analyze --language rust --complexity 10 src/
