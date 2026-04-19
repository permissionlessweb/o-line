# Documentation Generation

## CLI Reference (scripts/docs/gen-docs.sh)

Builds the oline binary and generates `docs/CLI-REFERENCE.md` from live `--help` and `--examples` output.

```bash
# Use default (debug) build
./scripts/docs/gen-docs.sh

# Use pre-built release binary
OLINE_BIN=./target/release/oline ./scripts/docs/gen-docs.sh

# Via justfile
just gen-docs
```

Output: `docs/CLI-REFERENCE.md` (auto-generated, do not edit by hand).

The script iterates over all subcommands, captures `--help` and `--examples` output, and formats them into fenced code blocks.

## Other Doc Scripts

| Script | Purpose |
|--------|---------|
| `scripts/docs/gen-apis.sh` | Generate client APIs (schema -> ts-codegen) |
| `scripts/docs/gen-docs.py` | Python-based doc generation |
| `scripts/docs/gen-tools.py` | Tool documentation generator |
| `scripts/docs/gen-tz.py` | TensorZero-style documentation |

## Team Scripts

| Script | Purpose |
|--------|---------|
| `scripts/gen/team-gen.sh` | Generate team configurations |
| `scripts/gen/team-list.sh` | List team members |
| `scripts/gen/team.sh` | Team management |
| `scripts/gen/team-sync.sh` | Sync team configs |
| `scripts/gen/team-tools-setup.sh` | Setup team tools |
| `scripts/gen/team-tools.sh` | Team tool management |

## Specialist Documentation

Located at `docs/specialists/`:
- `docs/specialists.md` -- Team roster index (9 specialists)
- Individual guides: special-teams, line-players, relayer, workflow, akash-sdl, key-management, dns-networking, snapshot-storage, testing
- Full reference: `docs/guides/devops-agent-spec.md` (complete tool spec for all recipes, scripts, network topology)
