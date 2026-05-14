#!/usr/bin/env python3
"""
scripts/gen-tools.py
====================
Parse docs/cli-reference.md and emit:
  .team/tools/oline_tools.json
      OpenAI-compatible tool schemas — pass directly to any LLM that supports
      tool-calling (openai, anthropic, mlx_lm, sglang, etc.)
  .team/tools/oline_executor.py
      Importable Python module for agent workflows.
      call("oline_deploy", {"parallel": True}) → subprocess result dict.
Usage:
    python3 scripts/gen-tools.py                          # defaults
    python3 scripts/gen-tools.py --cli-ref <path>         # custom input
    python3 scripts/gen-tools.py --out-dir <path>         # custom output dir
    just gen-tools                                         # via justfile
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
# ─── Config ───────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).parent.parent.parent
DEFAULT_CLI_REF = REPO_ROOT / "docs" / "cli-reference.md"
DEFAULT_OUT_DIR = REPO_ROOT / ".team" / "tools"
BIN_NAME = "oline"
# Flags that are meta/housekeeping — omit from tool schemas
SKIP_FLAGS = {"examples", "help", "h", "version", "V"}
# ─── Parser ───────────────────────────────────────────────────────────────────
def parse_cli_ref(text: str) -> list[dict]:
    """
    Return a list of command dicts:
      {cmd_path, description, positional_args, flags}
    Scans every code fence in the document for "Usage: oline ..." lines.
    Deduplicates by cmd_path, keeping the entry with the most flags (the
    subcommand detail block is more complete than the top-level summary).
    """
    commands: dict[str, dict] = {}
    fence_re = re.compile(r"```\n(.*?)\n```", re.DOTALL)
    for fence in fence_re.finditer(text):
        block = fence.group(1)
        usage_m = re.search(rf"^Usage:\s+({BIN_NAME}\s+.+)$", block, re.MULTILINE)
        if not usage_m:
            continue
        usage_line = usage_m.group(1).strip()
        # Skip the root "oline [OPTIONS] <COMMAND>" entry
        if "<COMMAND>" in usage_line:
            continue
        # Description = first non-empty line before "Usage:"
        before = block[: usage_m.start()].strip().splitlines()
        description = next((l.strip() for l in before if l.strip()), "")
        # Extract command path tokens (stop at first [ or < )
        cmd_parts: list[str] = []
        for token in usage_line.split()[1:]:  # skip "oline"
            if token.startswith(("[", "<")):
                break
            cmd_parts.append(token)
        cmd_path = BIN_NAME + " " + " ".join(cmd_parts) if cmd_parts else BIN_NAME
        positional_args = _parse_arguments(block)
        flags = _parse_options(block)
        existing = commands.get(cmd_path)
        if existing is None or len(flags) > len(existing["flags"]):
            commands[cmd_path] = {
                "cmd_path": cmd_path,
                "description": description,
                "positional_args": positional_args,
                "flags": flags,
            }
    return list(commands.values())
def _parse_arguments(block: str) -> list[dict]:
    """Parse the 'Arguments:' section → [{name, description, required}]."""
    args = []
    in_args = False
    for line in block.splitlines():
        if re.match(r"^Arguments:", line):
            in_args = True
            continue
        if in_args:
            if line and not line.startswith(" "):
                break
            m = re.match(r"^\s+<([\w][\w-]*)>(?:\.\.)?\s+(.*)", line)
            if m:
                args.append({
                    "name": _flag_to_ident(m.group(1)),
                    "description": m.group(2).strip(),
                    "required": True,
                })
    return args
def _parse_options(block: str) -> list[dict]:
    """Parse the 'Options:' section → [{name, cli_flag, type, description, ...}]."""
    flags = []
    in_options = False
    for line in block.splitlines():
        if re.match(r"^Options:", line):
            in_options = True
            continue
        if in_options:
            # Stop at a new non-indented section header
            if line and not line.startswith(" ") and not line.startswith("-"):
                break
            # --flag-name [<TYPE>]   Description [possible values: ...] [default: ...]
            m = re.match(
                r"^\s+(?:-\w,\s+)?--([a-z][a-z0-9-]*)(?:\s+<([^>]+)>)?\s{2,}(.*)",
                line,
            )
            if not m:
                continue
            raw_name, type_hint, rest = m.group(1), m.group(2), m.group(3).strip()
            if raw_name in SKIP_FLAGS:
                continue
            default = None
            dm = re.search(r"\[default:\s*([^\]]+)\]", rest)
            if dm:
                default = dm.group(1).strip()
                rest = rest[: dm.start()].strip()
            enum = None
            pm = re.search(r"\[possible values:\s*([^\]]+)\]", rest)
            if pm:
                enum = [v.strip() for v in pm.group(1).split(",")]
                rest = rest[: pm.start()].strip()
            # Infer type
            if type_hint is None:
                param_type = "boolean"
            elif default is not None and re.match(r"^\d+$", default):
                param_type = "integer"
            else:
                param_type = "string"
            flag: dict[str, Any] = {
                "name": _flag_to_ident(raw_name),
                "cli_flag": f"--{raw_name}",
                "description": rest or type_hint or raw_name,
                "type": param_type,
            }
            if default is not None:
                flag["default"] = int(default) if param_type == "integer" else default
            if enum is not None:
                flag["enum"] = enum
            flags.append(flag)
    return flags
def _flag_to_ident(s: str) -> str:
    """'model-name' → 'model_name', 'NAME' → 'name'"""
    return s.lower().replace("-", "_")
# ─── Tool schema builder ──────────────────────────────────────────────────────
def cmd_to_tool_name(cmd_path: str) -> str:
    """'oline deploy' → 'oline_deploy'"""
    return re.sub(r"[\s-]+", "_", cmd_path)
def cmd_to_tool(cmd: dict) -> dict:
    """Build one OpenAI-compatible tool definition from a parsed command."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    for arg in cmd["positional_args"]:
        properties[arg["name"]] = {
            "type": "string",
            "description": arg["description"],
        }
        if arg["required"]:
            required.append(arg["name"])
    for flag in cmd["flags"]:
        prop: dict[str, Any] = {
            "type": flag["type"],
            "description": flag["description"],
        }
        if "enum" in flag:
            prop["enum"] = flag["enum"]
        if "default" in flag:
            prop["default"] = flag["default"]
        properties[flag["name"]] = prop
    return {
        "type": "function",
        "function": {
            "name": cmd_to_tool_name(cmd["cmd_path"]),
            "description": cmd["description"] or cmd["cmd_path"],
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }
# ─── Executor generator ───────────────────────────────────────────────────────
_EXECUTOR_TEMPLATE = '''\
#!/usr/bin/env python3
"""
oline_executor.py — Auto-generated by scripts/gen-tools.py
DO NOT EDIT BY HAND — regenerate with: just gen-tools
Provides:
  TOOLS                          list of OpenAI tool schemas
  call(tool_name, kwargs)        run an oline CLI command, return result dict
  execute_tool_call(tool_call)   handle a single LLM tool_call object → str
Usage:
  from oline_executor import call, TOOLS
  result = call("oline_deploy", {"parallel": True})
  print(result["stdout"])
"""
import json
import os
import subprocess
from pathlib import Path
_here = Path(__file__).parent
# Load OpenAI tool schemas from the sibling JSON file
with open(_here / "oline_tools.json") as _f:
    TOOLS: list[dict] = json.load(_f)
# tool_name → CLI tokens (e.g. "oline_deploy" → ["oline", "deploy"])
_CMD_MAP: dict[str, list[str]] = {
__CMD_MAP__
}
# tool_name → set of positional argument names (inserted after flags)
_POSITIONAL: dict[str, set] = {
__POSITIONAL__
}
def call(tool_name: str, kwargs: dict, timeout: int = 60) -> dict:
    """
    Execute an oline CLI tool.
    Boolean flags with value True become bare flags (--flag).
    Other kwargs become --flag value pairs, except positional args which are
    appended after all flags.
    Returns {"stdout": str, "stderr": str, "returncode": int}.
    """
    cmd_parts = _CMD_MAP.get(tool_name)
    if cmd_parts is None:
        return {"stdout": "", "stderr": f"Unknown tool: {tool_name}", "returncode": 1}
    oline_bin = os.environ.get("OLINE_BIN", "oline")
    cmd = [oline_bin] + cmd_parts[1:]  # strip leading "oline"
    positional_names = _POSITIONAL.get(tool_name, set())
    flags: list[str] = []
    positional: list[str] = []
    for k, v in kwargs.items():
        cli_flag = "--" + k.replace("_", "-")
        if isinstance(v, bool):
            if v:
                flags.append(cli_flag)
        elif k in positional_names:
            positional.append(str(v))
        else:
            flags.extend([cli_flag, str(v)])
    result = subprocess.run(
        cmd + flags + positional,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "returncode": result.returncode,
    }
def execute_tool_call(tool_call: dict) -> str:
    """
    Handle a single LLM tool_call object:
      {"id": "...", "type": "function", "function": {"name": "...", "arguments": "..."}}
    Returns a string suitable for the tool message content.
    """
    name = tool_call["function"]["name"]
    args = json.loads(tool_call["function"].get("arguments", "{}"))
    result = call(name, args)
    if result["returncode"] == 0:
        return result["stdout"] or "(success, no output)"
    return f"Error (exit {result['returncode']}): {result['stderr'] or result['stdout']}"
'''
def build_executor(commands: list[dict]) -> str:
    cmd_map_lines = []
    positional_lines = []
    for cmd in sorted(commands, key=lambda c: c["cmd_path"]):
        name = cmd_to_tool_name(cmd["cmd_path"])
        parts_repr = "[" + ", ".join(f'"{p}"' for p in cmd["cmd_path"].split()) + "]"
        cmd_map_lines.append(f'    "{name}": {parts_repr},')
        if cmd["positional_args"]:
            pos_set = "{" + ", ".join(f'"{a["name"]}"' for a in cmd["positional_args"]) + "}"
            positional_lines.append(f'    "{name}": {pos_set},')
    return (
        _EXECUTOR_TEMPLATE
        .replace("__CMD_MAP__", "\n".join(cmd_map_lines))
        .replace("__POSITIONAL__", "\n".join(positional_lines))
    )
# ─── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli-ref", default=str(DEFAULT_CLI_REF), help="Path to cli-reference.md")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="Output directory")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    cli_ref = Path(args.cli_ref)
    out_dir = Path(args.out_dir)
    if not cli_ref.exists():
        print(f"ERROR: cli-reference.md not found: {cli_ref}", file=sys.stderr)
        print("  Run: just gen-docs   first", file=sys.stderr)
        sys.exit(1)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Parse
    text = cli_ref.read_text()
    commands = parse_cli_ref(text)
    if args.verbose:
        print(f"==> Parsed {len(commands)} commands from {cli_ref}")
    # Build tool schemas
    tools = [cmd_to_tool(cmd) for cmd in commands]
    # Write JSON
    json_out = out_dir / "oline_tools.json"
    json_out.write_text(json.dumps(tools, indent=2) + "\n")
    print(f"==> {json_out}  ({len(tools)} tools)")
    # Write executor
    executor_out = out_dir / "oline_executor.py"
    executor_out.write_text(build_executor(commands))
    print(f"==> {executor_out}")
    # Write __init__.py so the directory is importable
    init_out = out_dir / "__init__.py"
    if not init_out.exists():
        init_out.write_text('"""oline_tools — generated oline CLI tool schemas and executor."""\n')
    if args.verbose:
        print("==> Done. Import in agent workflows:")
        print("      from oline_executor import call, TOOLS")
if __name__ == "__main__":
    main()
