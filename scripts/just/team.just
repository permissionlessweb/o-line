# ── Team Management ──────────────────────────────────────────────────────────

team-sync:
	bash scripts/team-sync.sh

team-list:
	bash scripts/gen/team-list.sh

team-tools:
	bash scripts/gen/team-tools.sh

team-gen spec='oline-tools.yml':
	bash scripts/gen/team-gen.sh $spec

team-status:
	echo "Use 'just team-list' for status"

team-clean:
	rm -rf .team/ .claude/skills/ .opencode/agents/ gen-tools/

team-update:
	bash scripts/team-update.sh

team-docs team='special-teams':
	bash scripts/gen/team-gen.sh {{team}}

# ── Documentation & Tools Generation ────────────────────────────────────────

# Generate docs/cli-reference.md from the installed oline help output.
# Depends on `release` so we always introspect the same optimized binary
# that `just install` ships (unified via OLINE_BIN in gen-docs.py).
gen-docs: release
	python3 scripts/docs/gen-docs.py

gen-tools:
	#!/usr/bin/env bash
	set -e
	echo "==> Generating o-line tools from CLI reference"
	python3 scripts/docs/gen-tools.py --verbose
	echo "==> o-line tools generated in .team/tools/"
	echo "   - oline_tools.json (OpenAI tool schemas)"
	echo "   - oline_executor.py (Python executor)"

# Generate Mermaid diagrams from trailmark code graph analysis.
# Requires: trailmark in .venv, trailofbits/skills plugin installed.
gen-diagrams threshold='15':
	bash scripts/docs/gen-diagrams.sh --threshold {{threshold}}

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
