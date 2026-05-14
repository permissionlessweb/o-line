#!/usr/bin/env python3
"""
scripts/gen/gen-tz.py
======================
Stage 3 of the docs pipeline: gen-docs → gen-tools → gen-tz

Transforms OpenAI-compatible tool schemas into TensorZero function specs:
  - functions/<name>/args_schema.json   — JSON Schema for arguments
  - functions/<name>/system.minijinja   — system prompt template
  - functions/<name>/user.minijinja     — user prompt template
  - tensorzero.toml                     — top-level config with functions + model routing
  - llms.txt                            — index of generated functions
  - episodes/                           — episode configs (oline only)

Usage:
    python3 scripts/gen/gen-tz.py                                # oline (default)
    python3 scripts/gen/gen-tz.py --target qmd                   # qmd
    python3 scripts/gen/gen-tz.py --llm-curate --llm-url URL     # with LLM enrichment
    python3 scripts/gen/gen-tz.py --force                        # ignore checksums
    python3 scripts/gen/gen-tz.py -v                             # verbose
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent


def _resolve_repo_root(heuristics_path: Path) -> Path:
    """Resolve repo root from heuristics file location.

    Falls back to REPO_ROOT (3-level-up heuristic from script dir) but
    prefers the heuristics file's grandparent if it looks like a git repo.
    This handles monorepo / nested project layouts where the script is
    shared across repos.
    """
    candidate = heuristics_path.parent.parent
    if (candidate / ".git").is_dir() or (candidate / "AGENTS.md").is_file():
        return candidate
    return REPO_ROOT

# Import parsing functions from gen-tools.py (hyphenated name, use importlib)
_spec = importlib.util.spec_from_file_location("gen_tools", SCRIPT_DIR / "gen-tools.py")
gen_tools = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(gen_tools)  # type: ignore[union-attr]

# ─── TOML parser (stdlib in 3.11+, fallback for older) ───────────────────────
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


def _load_toml(path: Path) -> dict:
    """Load a TOML file. Falls back to a minimal parser if tomllib unavailable."""
    if tomllib is not None:
        with open(path, "rb") as f:
            return tomllib.load(f)
    # Minimal fallback: only supports the structures we need
    import configparser
    cp = configparser.ConfigParser()
    cp.read(path)
    result: dict[str, Any] = {}
    for section in cp.sections():
        keys = section.split(".")
        d = result
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = dict(cp[section])
    return result


# ─── Heuristics engine ───────────────────────────────────────────────────────

class Heuristics:
    """Load tz-heuristics.toml and provide categorization + secrets detection."""

    def __init__(self, path: Path):
        self.data = _load_toml(path)
        self.data["_source_path"] = str(path.resolve())  # track origin for repo root resolution
        self.categories: dict[str, list[str]] = self.data.get("categories", {})
        secrets_cfg = self.data.get("secrets", {})
        self.secret_patterns: list[str] = secrets_cfg.get("patterns", [])
        self.templates: dict[str, Any] = self.data.get("templates", {})
        self.model_cfg: dict[str, Any] = self.data.get("model", {})
        self.targets: dict[str, dict] = self.data.get("targets", {})

    def categorize(self, tool_name: str) -> list[str]:
        """Return category tags for a tool name based on keyword matching."""
        name_lower = tool_name.lower()
        tags = []
        for category, keywords in self.categories.items():
            if any(kw in name_lower for kw in keywords):
                tags.append(category)
        return tags or ["general"]

    def is_secret(self, arg_name: str) -> bool:
        """Check if an argument name matches a secret pattern."""
        name_lower = arg_name.lower()
        return any(pat in name_lower for pat in self.secret_patterns)

    def system_prompt(self, tags: list[str]) -> str:
        """Return the most specific system prompt for given tags."""
        category_prompts = self.templates.get("category_prompts", {})
        for tag in tags:
            if tag in category_prompts:
                return category_prompts[tag]
        return self.templates.get("system_prefix",
                                  "You are an infrastructure automation assistant.")

    def user_template(self) -> str:
        return self.templates.get("user_format",
                                  "Execute: {{function_name}}({{args | tojson}})")

    def function_hints(self, tool_name: str) -> str | None:
        """Return per-function semantic hints if configured in heuristics.

        Looks up [function_hints.<tool_name>] in the heuristics data.
        Falls back to matching by category hint keys.
        Each hint entry is a dict with a 'text' key (TOML table syntax).
        """
        hints_cfg = self.data.get("function_hints", {})
        # Direct lookup by tool name (dots replaced with underscores)
        key = tool_name.replace(".", "_")
        if key in hints_cfg:
            entry = hints_cfg[key]
            return entry.get("text", str(entry)) if isinstance(entry, dict) else str(entry)
        # Category-based fallback
        tags = self.categorize(tool_name)
        for tag in tags:
            if tag in hints_cfg:
                entry = hints_cfg[tag]
                return entry.get("text", str(entry)) if isinstance(entry, dict) else str(entry)
        return None


# ─── Checksum cache ──────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _checksums_path(output_dir: Path) -> Path:
    return output_dir / ".checksums"


def _load_checksums(output_dir: Path) -> dict[str, str]:
    p = _checksums_path(output_dir)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _save_checksums(output_dir: Path, checksums: dict[str, str]) -> None:
    _checksums_path(output_dir).write_text(json.dumps(checksums, indent=2) + "\n")


def _compute_checksums(input_files: list[Path], heuristics_path: Path) -> dict[str, str]:
    checksums = {}
    for f in input_files:
        if f.exists():
            checksums[str(f)] = _sha256(f)
    checksums[str(heuristics_path)] = _sha256(heuristics_path)
    return checksums


# ─── Robust help block parser ─────────────────────────────────────────────────

def _extract_help_blocks(text: str) -> list[str]:
    """Extract all fenced code blocks from markdown.

    Handles both plain ``` and ```lang fences, matching each opener
    with its corresponding closer. Content inside is returned as-is.
    """
    blocks = []
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n\r")
        # Opening fence: ``` possibly followed by a language specifier
        if re.match(r"^```[\w]*\s*$", line):
            lang = line.strip()[3:].strip()  # e.g. "bash", ""
            block_lines = []
            i += 1
            while i < len(lines):
                close_line = lines[i].rstrip("\n\r")
                if close_line.strip() == "```":
                    blocks.append("".join(block_lines))
                    break
                block_lines.append(lines[i])
                i += 1
        i += 1
    return blocks


def parse_cli_help_blocks(text: str, bin_name: str) -> list[dict]:
    """Parse CLI help from markdown via code blocks AND ### heading sections.

    Primary: extract from ``` / ```bash code fences containing `Usage:`.
    Fallback: parse `### <bin_name> <cmd>` heading sections and grab the
    next code block's Usage line + description.
    """
    commands: dict[str, dict] = {}

    # --- Strategy A: fenced code blocks with Usage: ---
    for block in _extract_help_blocks(text):
        usage_m = re.search(rf"^Usage:\s+({bin_name}\s+.+)$", block, re.MULTILINE)
        if not usage_m:
            continue
        usage_line = usage_m.group(1).strip()
        if "<COMMAND>" in usage_line or "<command>" in usage_line:
            continue

        # Description = first non-empty line before "Usage:"
        before = block[:usage_m.start()].strip().splitlines()
        description = next((l.strip() for l in before if l.strip()), "")

        # Extract command path tokens (stop at first [ or < )
        cmd_parts: list[str] = []
        for token in usage_line.split()[1:]:  # skip bin_name
            if token.startswith(("[", "<")):
                break
            cmd_parts.append(token)
        cmd_path = bin_name + " " + " ".join(cmd_parts) if cmd_parts else bin_name

        positional_args = gen_tools._parse_arguments(block)
        flags = gen_tools._parse_options(block)

        existing = commands.get(cmd_path)
        if existing is None or len(flags) > len(existing["flags"]):
            commands[cmd_path] = {
                "cmd_path": cmd_path,
                "description": description,
                "positional_args": positional_args,
                "flags": flags,
            }

    # --- Strategy B: ### heading sections ---
    # Matches patterns like "### oline bootstrap" or "### oline test-s3"
    heading_pat = re.compile(
        rf"^###\s+{re.escape(bin_name)}\s+(\S+)\s*$", re.MULTILINE
    )
    code_blocks = _extract_help_blocks(text)
    # Map each heading's line offset to the nearest following code block
    lines = text.splitlines()
    heading_offsets: dict[str, int] = {}  # cmd_name -> line index of heading
    for m in heading_pat.finditer(text):
        cmd_name = m.group(1)
        # Find the line index of the heading
        offset = text[:m.start()].count("\n")
        heading_offsets[cmd_name] = offset

    # Build a list of (start_line, block_content) for code blocks
    block_positions: list[tuple[int, str]] = []
    for block in code_blocks:
        # Find where this block occurs in the original text
        idx = text.find(block)
        if idx >= 0:
            block_line = text[:idx].count("\n")
            block_positions.append((block_line, block))

    for cmd_name, h_line in heading_offsets.items():
        cmd_path = f"{bin_name} {cmd_name}"
        if cmd_path in commands:
            continue  # already parsed via Strategy A

        # Find the nearest code block after this heading
        best_block = None
        for b_line, b_content in block_positions:
            if b_line > h_line:
                best_block = b_content
                break

        description = ""
        flags: list[dict] = []
        positional_args: list[dict] = []

        if best_block:
            usage_m = re.search(
                rf"^Usage:\s+{re.escape(bin_name)}\s+{re.escape(cmd_name)}\S*",
                best_block, re.MULTILINE,
            )
            if usage_m:
                before = best_block[:usage_m.start()].strip().splitlines()
                description = next((l.strip() for l in before if l.strip()), "")
                flags = gen_tools._parse_options(best_block)
                positional_args = gen_tools._parse_arguments(best_block)

        if not description:
            # Grab the first prose line after the heading
            for i in range(h_line + 1, min(h_line + 10, len(lines))):
                stripped = lines[i].strip()
                if stripped and not stripped.startswith("```") and not stripped.startswith("#"):
                    description = stripped
                    break

        commands[cmd_path] = {
            "cmd_path": cmd_path,
            "description": description,
            "positional_args": positional_args,
            "flags": flags,
        }

    return list(commands.values())



# ─── npm/custom help parser (for qmd and similar CLIs) ───────────────────────

def parse_npm_help(text: str, bin_name: str = "qmd") -> list[dict]:
    """Parse npm-style or custom CLI help into command dicts.

    Handles formats like qmd:
      Primary commands:
        qmd query <query>             - Description here
        qmd search <query>            - Another description
      Global options:
        --flag <type>                 - Flag description
    """
    commands: dict[str, dict] = {}
    global_flags: list[dict] = []

    # First try clap-style parsing via code fences
    clap_cmds = parse_cli_help_blocks(text, bin_name)
    if clap_cmds:
        return clap_cmds

    lines = text.splitlines()
    in_section = None  # "commands" or "options"

    for line in lines:
        stripped = line.strip()

        # Detect section headers
        if re.match(r"^(Primary commands|Collections & context|Maintenance|Commands):", stripped, re.IGNORECASE):
            in_section = "commands"
            continue
        if re.match(r"^(Global options|Search options|Embed/query options|Multi-get options):", stripped, re.IGNORECASE):
            in_section = "options"
            continue
        if re.match(r"^(Query syntax|AI agents|Index:|Constraints:)", stripped, re.IGNORECASE):
            in_section = None
            continue

        # Empty line between sections
        if not stripped:
            continue

        # Parse command lines: "  qmd <cmd> <args>   - Description"
        if in_section == "commands":
            m = re.match(rf"^\s+{bin_name}\s+(\S+)\s+.*?-\s+(.+)", line)
            if not m:
                # Try: "  qmd <cmd>   - Description" (no args)
                m = re.match(rf"^\s+{bin_name}\s+(\S+)\s{{2,}}-\s+(.+)", line)
            if m:
                cmd_name = m.group(1).strip()
                desc = m.group(2).strip()
                cmd_path = f"{bin_name} {cmd_name}"
                # Don't overwrite if we already have this command with more detail
                if cmd_path not in commands:
                    # Infer positional args from the line
                    pos_args = []
                    pos_m = re.search(rf"{bin_name}\s+{cmd_name}\s+(<[^>]+>)", line)
                    if pos_m:
                        arg_name = pos_m.group(1).strip("<>")
                        pos_args.append({
                            "name": gen_tools._flag_to_ident(arg_name),
                            "description": arg_name,
                            "required": True,
                        })
                    commands[cmd_path] = {
                        "cmd_path": cmd_path,
                        "description": desc,
                        "positional_args": pos_args,
                        "flags": [],
                    }

        # Parse global option lines: "  --flag <type>   - Description"
        elif in_section == "options":
            m = re.match(r"^\s+(?:-(\w),\s+)?--([a-z][a-z0-9-]*)(?:\s+<([^>]+)>)?\s{2,}-?\s*(.*)", line)
            if m:
                raw_name = m.group(2)
                type_hint = m.group(3)
                desc = m.group(4).strip()
                if raw_name in {"help", "version"}:
                    continue
                param_type = "boolean" if type_hint is None else "string"
                # Check for defaults
                default = None
                dm = re.search(r"\(default[:\s]+([^)]+)\)", desc)
                if dm:
                    default = dm.group(1).strip()
                    if re.match(r"^\d+$", default):
                        param_type = "integer"
                        default = int(default)
                flag_entry: dict[str, Any] = {
                    "name": gen_tools._flag_to_ident(raw_name),
                    "cli_flag": f"--{raw_name}",
                    "description": desc,
                    "type": param_type,
                }
                if default is not None:
                    flag_entry["default"] = default
                global_flags.append(flag_entry)

    # Attach global flags to search-type commands that use them
    search_cmds = {"query", "search", "vsearch", "get", "multi-get", "multi_get", "ls"}
    for cmd_path, cmd in commands.items():
        cmd_name = cmd_path.split()[-1].replace("-", "_")
        if cmd_name in search_cmds or cmd_name in {"query", "search", "vsearch"}:
            cmd["flags"] = list(global_flags)

    return list(commands.values())


# ─── Structured user template generation ────────────────────────────────────

def _user_template_for(name: str, tags: list[str], description: str) -> str:
    """Generate a richer user.minijinja template based on function category.

    Instead of a flat "Execute: func(args)", this produces a structured
    template that gives the LLM clear instructions about what to produce
    and what context to include.
    """
    # Category-specific templates with structured output guidance
    if "deploy" in tags:
        return (
            "Execute the oline deployment command.\n\n"
            "Command: {{function_name}}\n"
            "Arguments: {{args | tojson}}\n\n"
            "IMPORTANT: Before executing, verify:\n"
            "1. SDL_DIR is set (default: templates/sdls/)\n"
            "2. Required env vars are populated\n"
            "3. deploy-config.json exists if referencing stored config\n"
            "4. Never broadcast from cmd_generate_sdl — it only renders templates"
        )
    elif "network" in tags:
        return (
            "Execute the network operation.\n\n"
            "Command: {{function_name}}\n"
            "Arguments: {{args | tojson}}\n\n"
            "Note: DNS operations require CF_API_TOKEN and CF_ZONE_ID.\n"
            "VPN operations require pfSense access.\n"
            "Relayer operations support binary hot-swap without downtime."
        )
    elif "security" in tags:
        return (
            "Execute the security operation.\n\n"
            "Command: {{function_name}}\n"
            "Arguments: {{args | tojson}}\n\n"
            "CRITICAL: Never log or echo secret values.\n"
            "Secret args are marked writeOnly in the schema.\n"
            "Encrypted data uses AES-256-GCM with Argon2 key derivation."
        )
    elif "testing" in tags:
        return (
            "Execute the infrastructure test.\n\n"
            "Command: {{function_name}}\n"
            "Arguments: {{args | tojson}}\n\n"
            "Report: pass/fail status, latency (if applicable), endpoint details.\n"
            "For S3 tests: verify bucket access + read/write round-trip.\n"
            "For gRPC tests: verify endpoint responds to health check."
        )
    elif "management" in tags:
        return (
            "Execute the management operation.\n\n"
            "Command: {{function_name}}\n"
            "Arguments: {{args | tojson}}\n\n"
            "Session state persists at ~/.config/oline/sessions/{episode_id}.json\n"
            "Refresh operations are stateless — no episode_id needed.\n"
            "FIELD_DESCRIPTORS is the source of truth for config fields."
        )
    else:
        # Default: slightly richer than the old flat template
        return (
            "Execute: {{function_name}}({{args | tojson}})\n\n"
            "Description: " + description
        )


# ─── TensorZero spec generation ──────────────────────────────────────────────

def tool_to_tz_schema(tool: dict, heuristics: Heuristics) -> dict:
    """Convert an OpenAI tool schema's parameters into a TensorZero args_schema.

    Adds writeOnly: true for secret-matching arguments.
    """
    params = tool["function"]["parameters"]
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {},
        "required": params.get("required", []),
    }
    for prop_name, prop_def in params.get("properties", {}).items():
        entry = dict(prop_def)
        if heuristics.is_secret(prop_name):
            entry["writeOnly"] = True
        schema["properties"][prop_name] = entry
    return schema


def generate_function_dir(
    output_dir: Path,
    tool: dict,
    heuristics: Heuristics,
    verbose: bool = False,
) -> dict:
    """Generate a single function's directory: args_schema.json, system.minijinja, user.minijinja.

    Returns the TOML config dict for this function.
    """
    func = tool["function"]
    name = func["name"]
    description = func.get("description", name)
    tags = heuristics.categorize(name)

    func_dir = output_dir / "functions" / name
    func_dir.mkdir(parents=True, exist_ok=True)

    # args_schema.json
    schema = tool_to_tz_schema(tool, heuristics)
    (func_dir / "args_schema.json").write_text(json.dumps(schema, indent=2) + "\n")

    # system.minijinja — enriched with architectural context from heuristics
    system_prompt = heuristics.system_prompt(tags)
    system_content = (
        f"{system_prompt}\n\n"
        f"Function: {name}\n"
        f"Description: {description}\n"
        f"Tags: {', '.join(tags)}\n"
    )
    # Append per-function semantic hints if available
    semantic_hints = heuristics.function_hints(name)
    if semantic_hints:
        system_content += f"\nSEMANTIC HINTS:\n{semantic_hints}\n"
    (func_dir / "system.minijinja").write_text(system_content)

    # user.minijinja — structured execution template
    user_content = _user_template_for(name, tags, description)
    (func_dir / "user.minijinja").write_text(user_content + "\n")

    if verbose:
        print(f"  {name} [{', '.join(tags)}]")

    return {
        "name": name,
        "description": description,
        "tags": tags,
        "type": "chat",
        "system_schema": f"functions/{name}/system.minijinja",
        "user_schema": f"functions/{name}/user.minijinja",
        "args_schema": f"functions/{name}/args_schema.json",
    }


def generate_tensorzero_toml(
    output_dir: Path,
    function_configs: list[dict],
    heuristics: Heuristics,
) -> None:
    """Generate the top-level tensorzero.toml."""
    model_name = heuristics.model_cfg.get("name", "default")

    lines = [
        "# tensorzero.toml — Auto-generated by scripts/gen/gen-tz.py",
        "# DO NOT EDIT BY HAND — regenerate with: python3 scripts/gen/gen-tz.py",
        "",
        "[gateway]",
        'bind_address = "0.0.0.0:3000"',
        "",
        f"[models.{model_name}]",
        f'routing = {json.dumps(heuristics.model_cfg.get("routing", ["default"]))}',
        "",
        f"[models.{model_name}.providers.default]",
        'type = "openai"',
        'model_name = "default"',
        "",
    ]

    for fc in sorted(function_configs, key=lambda x: x["name"]):
        name = fc["name"]
        lines.append(f"[functions.{name}]")
        lines.append(f'type = "{fc["type"]}"')
        lines.append(f'description = "{fc["description"]}"')
        lines.append(f'tags = {json.dumps(fc["tags"])}')
        lines.append(f'args_schema = "{fc["args_schema"]}"')
        lines.append("")
        lines.append(f"[functions.{name}.variants.default]")
        lines.append(f'type = "chat_completion"')
        lines.append(f'model = "{model_name}"')
        lines.append(f'system_template = "{fc["system_schema"]}"')
        lines.append(f'user_template = "{fc["user_schema"]}"')
        lines.append("")

    (output_dir / "tensorzero.toml").write_text("\n".join(lines))


def generate_llms_txt(output_dir: Path, function_configs: list[dict]) -> None:
    """Generate llms.txt index of all functions."""
    lines = [
        "# TensorZero Function Index",
        f"# Generated functions: {len(function_configs)}",
        "#",
        "# name | description | tags",
        "",
    ]
    for fc in sorted(function_configs, key=lambda x: x["name"]):
        tags_str = ", ".join(fc["tags"])
        lines.append(f"{fc['name']} | {fc['description']} | {tags_str}")

    (output_dir / "llms.txt").write_text("\n".join(lines) + "\n")


# ─── Episode parsing (oline only) ────────────────────────────────────────────

def parse_episode(path: Path) -> dict:
    """Parse an episode markdown file into structured metadata."""
    text = path.read_text()
    lines = text.splitlines()

    # Extract title from first H1
    title = path.stem
    for line in lines:
        m = re.match(r"^#\s+Episode:\s+(.+)", line)
        if m:
            title = m.group(1).strip()
            break

    # Extract metadata from bold lines
    outcome = ""
    wall_clock = ""
    groups = ""
    for line in lines:
        m = re.match(r"\*\*Outcome\*\*:\s*(.+)", line)
        if m:
            outcome = m.group(1).strip()
        m = re.match(r"\*\*Wall clock\*\*:\s*(.+)", line)
        if m:
            wall_clock = m.group(1).strip()
        m = re.match(r"\*\*Groups\*\*:\s*(.+)", line)
        if m:
            groups = m.group(1).strip()
        m = re.match(r"\*\*Trigger\*\*:\s*(.+)", line)
        if m:
            outcome = outcome or m.group(1).strip()

    # Extract step sequences (## Inference N: ...)
    steps = []
    step_re = re.compile(r"^##\s+(?:Inference\s+\d+|Pre-flight|Optional|Error handling):\s*(.+)", re.MULTILINE)
    for sm in step_re.finditer(text):
        steps.append(sm.group(1).strip())

    # Extract tool calls from code blocks
    tool_calls = []
    fence_re = re.compile(r"```(?:bash)?\n(.*?)\n```", re.DOTALL)
    for fence in fence_re.finditer(text):
        block = fence.group(1)
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("oline ") and not line.startswith("#"):
                # Extract the command (first two tokens typically)
                parts = line.split()
                cmd = parts[0] + "_" + parts[1] if len(parts) > 1 else parts[0]
                cmd = re.sub(r"[^a-z0-9_]", "_", cmd.lower())
                if cmd not in tool_calls:
                    tool_calls.append(cmd)

    return {
        "name": path.stem,
        "title": title,
        "outcome": outcome,
        "wall_clock": wall_clock,
        "groups": groups,
        "steps": steps,
        "tool_calls": tool_calls,
    }


def generate_episodes(output_dir: Path, episodes_dir: Path, verbose: bool = False) -> None:
    """Parse episode markdown files and emit TensorZero episode configs."""
    if not episodes_dir.exists():
        if verbose:
            print("  No episodes directory found, skipping")
        return

    ep_out = output_dir / "episodes"
    ep_out.mkdir(parents=True, exist_ok=True)

    episode_files = sorted(episodes_dir.glob("*.md"))
    if not episode_files:
        if verbose:
            print("  No episode files found")
        return

    for ep_file in episode_files:
        ep = parse_episode(ep_file)
        if verbose:
            print(f"  Episode: {ep['title']} ({len(ep['tool_calls'])} tool calls)")

        # Write episode TOML
        lines = [
            f"# Episode: {ep['title']}",
            f"# Source: recipes/episodes/{ep_file.name}",
            "",
            f"[episode.{ep['name']}]",
            f'title = "{ep["title"]}"',
            f'description = "{ep["outcome"]}"',
        ]
        if ep["wall_clock"]:
            lines.append(f'wall_clock = "{ep["wall_clock"]}"')
        if ep["groups"]:
            lines.append(f'groups = "{ep["groups"]}"')
        lines.append(f'functions = {json.dumps(ep["tool_calls"])}')

        if ep["steps"]:
            lines.append("")
            lines.append(f"[episode.{ep['name']}.steps]")
            for i, step in enumerate(ep["steps"]):
                lines.append(f'step_{i + 1} = "{step}"')

        lines.append("")
        (ep_out / f"{ep['name']}.toml").write_text("\n".join(lines))


# ─── LLM enrichment (optional) ───────────────────────────────────────────────

def _llm_enrich(
    function_configs: list[dict],
    llm_url: str,
    verbose: bool = False,
) -> list[dict]:
    """Optionally enrich function descriptions via an OpenAI-compatible endpoint."""
    try:
        import urllib.request
    except ImportError:
        print("WARNING: urllib not available, skipping LLM enrichment", file=sys.stderr)
        return function_configs

    endpoint = llm_url.rstrip("/") + "/v1/chat/completions"
    enriched = []

    for fc in function_configs:
        prompt = (
            f"Improve this CLI tool description for an LLM function-calling context.\n"
            f"Tool: {fc['name']}\n"
            f"Current description: {fc['description']}\n"
            f"Tags: {', '.join(fc['tags'])}\n\n"
            f"Return ONLY the improved description (one sentence, no quotes)."
        )

        payload = json.dumps({
            "model": "default",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 100,
            "temperature": 0.3,
        }).encode()

        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                new_desc = data["choices"][0]["message"]["content"].strip()
                if new_desc and len(new_desc) > 10:
                    fc = dict(fc)
                    fc["description"] = new_desc
                    if verbose:
                        print(f"  Enriched: {fc['name']}")
        except Exception as e:
            if verbose:
                print(f"  LLM enrichment failed for {fc['name']}: {e}")

        enriched.append(fc)

    return enriched


# ─── Main pipeline ───────────────────────────────────────────────────────────

def run_target(
    target_name: str,
    heuristics: Heuristics,
    force: bool = False,
    llm_url: str | None = None,
    verbose: bool = False,
) -> int:
    """Run the TensorZero generation pipeline for a single target. Returns function count."""
    target_cfg = heuristics.targets.get(target_name)
    if not target_cfg:
        print(f"ERROR: Unknown target '{target_name}'", file=sys.stderr)
        print(f"  Available: {', '.join(heuristics.targets.keys())}", file=sys.stderr)
        sys.exit(1)

    bin_name = target_cfg.get("bin_name", target_name)
    # Resolve repo root from heuristics file location (handles nested projects)
    h_path = Path(heuristics.data.get("_source_path", ""))
    resolved_root = _resolve_repo_root(h_path) if h_path.exists() else REPO_ROOT
    output_dir = resolved_root / target_cfg.get("output_dir", f"recipes/tz-{target_name}")
    heuristics_path = resolved_root / "recipes" / "tz-heuristics.toml"

    print(f"==> Target: {target_name} ({bin_name})")

    # ── Resolve input sources ─────────────────────────────────────────────
    cli_ref_path = target_cfg.get("cli_ref")
    cli_ref_cmd = target_cfg.get("cli_ref_cmd")
    tools_json_path = target_cfg.get("tools_json")
    input_files: list[Path] = []
    tools: list[dict] = []

    # Strategy 1: Pre-built tools JSON (fastest, preferred for oline)
    if tools_json_path:
        tj = resolved_root / tools_json_path
        if tj.exists():
            input_files.append(tj)
            if cli_ref_path:
                cr = resolved_root / cli_ref_path
                if cr.exists():
                    input_files.append(cr)

            # Checksum check
            if not force:
                current = _compute_checksums(input_files, heuristics_path)
                saved = _load_checksums(output_dir)
                if current == saved:
                    print(f"  Up to date (checksums match)")
                    return -1

            tools = json.loads(tj.read_text())
            if verbose:
                print(f"  Loaded {len(tools)} tools from {tj}")

            # If tools_json is sparse, also parse CLI reference and merge
            if cli_ref_path and len(tools) < 5:
                cr = resolved_root / cli_ref_path
                if cr.exists() and cr not in input_files:
                    input_files.append(cr)
                cli_text = cr.read_text()
                commands = parse_cli_help_blocks(cli_text, bin_name)
                cli_tools = [gen_tools.cmd_to_tool(cmd) for cmd in commands]
                existing = {t["function"]["name"] for t in tools}
                for ct in cli_tools:
                    if ct["function"]["name"] not in existing:
                        tools.append(ct)
                        existing.add(ct["function"]["name"])
                if verbose:
                    print(f"  Merged {len(cli_tools)} CLI commands → {len(tools)} total tools")

    # Strategy 2: Parse CLI reference markdown (local file)
    if not tools and cli_ref_path:
        full_path = resolved_root / cli_ref_path
        if not full_path.exists():
            print(f"ERROR: CLI reference not found: {full_path}", file=sys.stderr)
            print("  Run: just gen-docs   first", file=sys.stderr)
            return 0
        if full_path not in input_files:
            input_files.append(full_path)

        if not force and not tools_json_path:
            current = _compute_checksums(input_files, heuristics_path)
            saved = _load_checksums(output_dir)
            if current == saved:
                print(f"  Up to date (checksums match)")
                return -1

        cli_text = full_path.read_text()
        commands = parse_cli_help_blocks(cli_text, bin_name)
        if verbose:
            print(f"  Parsed {len(commands)} commands from {full_path}")
        tools = [gen_tools.cmd_to_tool(cmd) for cmd in commands]

    if not tools:
        print(f"  WARNING: No tools resolved for {bin_name}", file=sys.stderr)
        return 0

    # ── Tool schemas → TensorZero specs ───────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    function_configs = []

    if verbose:
        print(f"  Generating TensorZero specs:")

    for tool in tools:
        fc = generate_function_dir(output_dir, tool, heuristics, verbose)
        function_configs.append(fc)

    # ── Optional LLM enrichment ───────────────────────────────────────────
    if llm_url:
        if verbose:
            print(f"  Running LLM enrichment via {llm_url}...")
        function_configs = _llm_enrich(function_configs, llm_url, verbose)

    # ── Generate top-level files ──────────────────────────────────────────
    generate_tensorzero_toml(output_dir, function_configs, heuristics)
    generate_llms_txt(output_dir, function_configs)

    # ── Episodes (oline only) ─────────────────────────────────────────────
    if target_name == "oline":
        episodes_dir = REPO_ROOT / "recipes" / "episodes"
        if verbose:
            print(f"  Processing episodes:")
        generate_episodes(output_dir, episodes_dir, verbose)

    # ── Save checksums ────────────────────────────────────────────────────
    if input_files:
        checksums = _compute_checksums(input_files, heuristics_path)
        _save_checksums(output_dir, checksums)

    print(f"  ==> {output_dir}/  ({len(function_configs)} functions)")
    return len(function_configs)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--target", default="oline",
                    help="Target CLI: oline, ergors, qmd (default: oline)")
    ap.add_argument("--all", action="store_true",
                    help="Generate for all targets")
    ap.add_argument("--force", action="store_true",
                    help="Ignore checksums, regenerate everything")
    ap.add_argument("--llm-curate", action="store_true",
                    help="Enrich descriptions via LLM endpoint")
    ap.add_argument("--llm-url", default=None,
                    help="OpenAI-compatible endpoint URL for --llm-curate")
    ap.add_argument("--heuristics", default=None,
                    help="Path to tz-heuristics.toml (default: recipes/tz-heuristics.toml)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    # Validate LLM flags
    if args.llm_curate and not args.llm_url:
        print("ERROR: --llm-curate requires --llm-url <URL>", file=sys.stderr)
        sys.exit(1)

    # Load heuristics
    heuristics_path = Path(args.heuristics) if args.heuristics else REPO_ROOT / "recipes" / "tz-heuristics.toml"
    if not heuristics_path.exists():
        print(f"ERROR: Heuristics config not found: {heuristics_path}", file=sys.stderr)
        sys.exit(1)

    heuristics = Heuristics(heuristics_path)

    # Determine targets
    if args.all:
        targets = list(heuristics.targets.keys())
    else:
        targets = [args.target]

    # Run pipeline
    total = 0
    for target in targets:
        count = run_target(
            target,
            heuristics,
            force=args.force,
            llm_url=args.llm_url if args.llm_curate else None,
            verbose=args.verbose,
        )
        if count > 0:
            total += count

    if total > 0:
        print(f"\n==> Done. {total} functions generated across {len(targets)} target(s).")
    elif total == 0 and not any(
        run_target(t, heuristics, force=False, verbose=False) == -1 for t in []
    ):
        print("\n==> No functions generated. Check inputs.")


if __name__ == "__main__":
    main()
