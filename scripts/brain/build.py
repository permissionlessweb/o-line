#!/usr/bin/env python3
"""
brain.terp.network static site generator.

Reads terp-brain markdown nodes, renders HTML + interactive vis.js graph.

Usage:
    python3 build.py --source ~/terp-brain/nodes --output ./dist/brain
"""

import argparse
import json
import logging
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from textwrap import dedent

try:
    import yaml
except ImportError:
    yaml = None

try:
    import markdown as md_lib
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("brain-build")

# ──────────────────────────────────────────────
# Color / type constants
# ──────────────────────────────────────────────
TYPE_COLORS = {
    "procedure": "#3b82f6",
    "concept": "#10b981",
    "lesson": "#ef4444",
    "spec": "#8b5cf6",
    "decision": "#f59e0b",
    "dependency": "#ec4899",
    "reference": "#6b7280",
    "moc": "#eab308",
}

TYPE_LABELS = {
    "procedure": "Procedure",
    "concept": "Concept",
    "lesson": "Lesson",
    "spec": "Spec",
    "decision": "Decision",
    "dependency": "Dependency",
    "reference": "Reference",
    "moc": "Domain Map",
}

DOMAIN_MAPS = [
    "devops",
    "release-automation",
    "cosmos-sdk",
    "smart-contracts",
    "client-packages",
]

# ──────────────────────────────────────────────
# Frontmatter + markdown parsing
# ──────────────────────────────────────────────

def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Parse YAML frontmatter from markdown text. Returns (metadata, body)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm_raw = text[3:end].strip()
    body = text[end + 4:].strip()
    meta = {}
    if yaml:
        try:
            meta = yaml.safe_load(fm_raw) or {}
        except yaml.YAMLError as e:
            log.warning(f"YAML parse error: {e}")
    else:
        # Fallback: simple key: value parsing
        for line in fm_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if v.startswith("[") and v.endswith("]"):
                    v = [x.strip().strip('"').strip("'") for x in v[1:-1].split(",")]
                elif v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                meta[k] = v
    return meta, body


def extract_title(body: str) -> str:
    """Extract first H1 from markdown body."""
    for line in body.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def slug_from_filename(path: Path) -> str:
    return path.stem


def extract_wiki_links(text: str) -> list[dict]:
    """Extract [[wiki-links]] with optional relationship text after ' — '."""
    links = []
    seen = set()
    for m in re.finditer(r'\[\[([^\]]+)\]\](?:\s*—\s*(.*))?', text):
        target = m.group(1).strip()
        rel = (m.group(2) or "").strip()
        if target not in seen:
            # Extract short relationship verb if present
            label = ""
            if rel:
                # Try to grab first verb phrase: "extends", "grounds", etc.
                verb_match = re.match(r'(\w+(?:\s+\w+)?)', rel)
                if verb_match:
                    label = verb_match.group(1)
                    # Clean up common patterns
                    # Clean common preamble patterns
                    lower = label.lower()
                    for prefix in ["this node ", "this ", "the "]:
                        if lower.startswith(prefix):
                            label = label[len(prefix):]
                            lower = label.lower()
                    # Extract just the verb
                    verb_m = re.match(r'(extends|grounds|drives|defines|enables|requires|implements|uses|describes|specifies|documents|tracks|mirrors|is)', lower)
                    if verb_m:
                        label = verb_m.group(1)
                    label = label.strip()
                    if len(label) > 30:
                        label = label[:27] + "..."
            links.append({"target": target, "label": label, "full_text": rel})
            seen.add(target)
    return links


def render_markdown(text: str) -> str:
    """Render markdown to HTML."""
    if HAS_MARKDOWN:
        return md_lib.markdown(
            text,
            extensions=["fenced_code", "tables", "toc", "nl2br"],
        )
    # Minimal fallback renderer
    html = text
    # Code blocks
    html = re.sub(r'```(\w*)\n(.*?)```', lambda m: f'<pre><code class="language-{m.group(1)}">{_esc(m.group(2))}</code></pre>', html, flags=re.DOTALL)
    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
    # Headers
    for i in range(6, 0, -1):
        html = re.sub(rf'^{"#" * i}\s+(.+)$', rf'<h{i}>\1</h{i}>', html, flags=re.MULTILINE)
    # Bold / italic
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)
    # Links
    html = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', html)
    # Lists
    html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    html = re.sub(r'(<li>.*?</li>(\n|$))+', lambda m: f'<ul>{m.group(0)}</ul>', html, flags=re.DOTALL)
    # Paragraphs
    html = re.sub(r'\n\n+', '</p><p>', html)
    html = f'<p>{html}</p>'
    return html


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def wiki_links_to_html(html: str, all_slugs: set, base_path: str = ".") -> str:
    """Convert [[wiki-links]] in rendered HTML to <a> tags."""
    def replace_link(m):
        slug = m.group(1).strip()
        if slug in all_slugs:
            return f'<a href="{base_path}/nodes/{slug}.html" class="wiki-link" data-slug="{slug}">{slug_to_display(slug)}</a>'
        return f'<span class="wiki-link broken">{slug_to_display(slug)}</span>'
    return re.sub(r'\[\[([^\]]+)\]\]', replace_link, html)


def slug_to_display(slug: str) -> str:
    return slug.replace("-", " ").title()


# ──────────────────────────────────────────────
# Node data model
# ──────────────────────────────────────────────

class BrainNode:
    def __init__(self, path: Path):
        self.path = path
        self.slug = slug_from_filename(path)
        raw = path.read_text(encoding="utf-8", errors="replace")
        self.meta, self.body = parse_frontmatter(raw)
        self.title = extract_title(self.body) or slug_to_display(self.slug)
        self.description = self.meta.get("description", "")
        self.type = self.meta.get("type", "reference")
        self.status = self.meta.get("status", "active")
        self.created = str(self.meta.get("created", ""))
        self.repos = self.meta.get("repos", [])
        if isinstance(self.repos, str):
            self.repos = [self.repos]
        self.topics = []
        self.wiki_links = extract_wiki_links(self.body)
        self.backlinks: list[str] = []
        # Extract topics from "Topics:" section
        self._extract_topics()

    def _extract_topics(self):
        in_topics = False
        for line in self.body.splitlines():
            if re.match(r'^#+\s*Topics', line, re.IGNORECASE) or line.strip().lower() == "topics:":
                in_topics = True
                continue
            if in_topics:
                if line.startswith("#") or (line.strip() and not line.strip().startswith("-") and not line.strip().startswith("[")):
                    break
                m = re.search(r'\[\[([^\]]+)\]\]', line)
                if m:
                    self.topics.append(m.group(1).strip())

    @property
    def color(self):
        return TYPE_COLORS.get(self.type, "#6b7280")

    @property
    def body_text(self):
        """Plain text body for search index."""
        text = re.sub(r'\[\[([^\]]+)\]\]', r'\1', self.body)
        text = re.sub(r'[#*_`\[\]()]', '', text)
        return text.strip()


# ──────────────────────────────────────────────
# Site builder
# ──────────────────────────────────────────────

class BrainSiteBuilder:
    def __init__(self, source: Path, output: Path, graphify_path: Path | None = None):
        self.source = source
        self.output = output
        self.graphify_path = graphify_path
        self.nodes: dict[str, BrainNode] = {}
        self.graph_nodes = []
        self.graph_edges = []

    def build(self):
        log.info(f"Source: {self.source}")
        log.info(f"Output: {self.output}")
        self._load_nodes()
        self._compute_backlinks()
        self._build_graph_data()
        self._prepare_output_dir()
        self._write_graph_data()
        self._write_search_index()
        self._write_assets()
        self._write_node_pages()
        self._write_index_page()
        log.info(f"✓ Built {len(self.nodes)} node pages + index → {self.output}")

    def _load_nodes(self):
        md_files = sorted(self.source.glob("*.md"))
        log.info(f"Found {len(md_files)} markdown files")
        for f in md_files:
            if f.stem == "index":
                continue
            try:
                node = BrainNode(f)
                self.nodes[node.slug] = node
                log.info(f"  ✓ {node.slug} ({node.type})")
            except Exception as e:
                log.warning(f"  ✗ Skipping {f.name}: {e}")

    def _compute_backlinks(self):
        for slug, node in self.nodes.items():
            for link in node.wiki_links:
                target = link["target"]
                if target in self.nodes and target != slug:
                    if slug not in self.nodes[target].backlinks:
                        self.nodes[target].backlinks.append(slug)

    def _build_graph_data(self):
        all_slugs = set(self.nodes.keys())
        edge_counts = {s: 0 for s in all_slugs}

        # Count edges for sizing
        for slug, node in self.nodes.items():
            for link in node.wiki_links:
                if link["target"] in all_slugs:
                    edge_counts[slug] = edge_counts.get(slug, 0) + 1
                    edge_counts[link["target"]] = edge_counts.get(link["target"], 0) + 1

        for slug, node in self.nodes.items():
            ec = edge_counts.get(slug, 0)
            size = max(15, min(50, 15 + ec * 4))
            self.graph_nodes.append({
                "id": slug,
                "label": slug_to_display(slug),
                "type": node.type,
                "group": node.type,
                "color": node.color,
                "size": size,
                "title": node.description[:120] if node.description else slug_to_display(slug),
            })

        seen_edges = set()
        for slug, node in self.nodes.items():
            for link in node.wiki_links:
                target = link["target"]
                if target in all_slugs:
                    edge_key = tuple(sorted([slug, target]))
                    if edge_key not in seen_edges:
                        self.graph_edges.append({
                            "from": slug,
                            "to": target,
                            "label": link["label"] if link["label"] else "",
                        })
                        seen_edges.add(edge_key)

        # Optionally merge graphify data
        if self.graphify_path and self.graphify_path.exists():
            try:
                gdata = json.loads(self.graphify_path.read_text())
                log.info(f"Loaded graphify data: {len(gdata.get('nodes', []))} nodes, {len(gdata.get('edges', []))} edges")
            except Exception as e:
                log.warning(f"Could not load graphify data: {e}")

    def _prepare_output_dir(self):
        if self.output.exists():
            shutil.rmtree(self.output)
        (self.output / "nodes").mkdir(parents=True)
        (self.output / "assets").mkdir(parents=True)

    def _write_graph_data(self):
        data = {"nodes": self.graph_nodes, "edges": self.graph_edges}
        (self.output / "graph-data.json").write_text(json.dumps(data, indent=2))
        log.info(f"  graph-data.json: {len(self.graph_nodes)} nodes, {len(self.graph_edges)} edges")

    def _write_search_index(self):
        index = []
        for slug, node in self.nodes.items():
            index.append({
                "slug": slug,
                "title": node.title,
                "description": node.description,
                "type": node.type,
                "topics": node.topics,
                "body_preview": node.body_text[:200],
            })
        (self.output / "search-index.json").write_text(json.dumps(index, indent=2))
        log.info(f"  search-index.json: {len(index)} entries")

    def _write_assets(self):
        (self.output / "assets" / "style.css").write_text(CSS)
        (self.output / "assets" / "graph.js").write_text(GRAPH_JS)
        log.info("  assets/ written")

    def _write_node_pages(self):
        all_slugs = set(self.nodes.keys())
        for slug, node in self.nodes.items():
            html = self._render_node_page(node, all_slugs)
            (self.output / "nodes" / f"{slug}.html").write_text(html)

    def _render_node_page(self, node: BrainNode, all_slugs: set) -> str:
        # Render body markdown → HTML, then convert wiki-links
        body_html = render_markdown(node.body)
        body_html = wiki_links_to_html(body_html, all_slugs, base_path="..")

        # Build metadata pills
        type_color = node.color
        status_color = "#10b981" if node.status == "active" else "#f59e0b" if node.status == "speculative" else "#6b7280"
        repos_html = "".join(f'<span class="pill repo-pill">{r}</span>' for r in node.repos)
        created_html = f'<span class="pill date-pill">{node.created}</span>' if node.created else ""

        # Related notes (outgoing links)
        related = ""
        outgoing = [l for l in node.wiki_links if l["target"] in all_slugs and l["target"] not in node.topics]
        if outgoing:
            items = []
            for l in outgoing:
                desc = self.nodes[l["target"]].description[:100] if l["target"] in self.nodes else ""
                rel_label = f' <span class="rel-label">— {l["label"]}</span>' if l["label"] else ""
                items.append(
                    f'<li><a href="{l["target"]}.html" class="wiki-link" data-slug="{l["target"]}">'
                    f'{slug_to_display(l["target"])}</a>{rel_label}'
                    f'<p class="link-desc">{desc}</p></li>'
                )
            related = f'<section class="related"><h2>Relevant Notes</h2><ul>{"".join(items)}</ul></section>'

        # Backlinks
        backlinks_html = ""
        if node.backlinks:
            items = []
            for bl in sorted(node.backlinks):
                desc = self.nodes[bl].description[:100] if bl in self.nodes else ""
                items.append(
                    f'<li><a href="{bl}.html" class="wiki-link" data-slug="{bl}">'
                    f'{slug_to_display(bl)}</a>'
                    f'<p class="link-desc">{desc}</p></li>'
                )
            backlinks_html = f'<section class="backlinks"><h2>Referenced By</h2><ul>{"".join(items)}</ul></section>'

        # Topics
        topics_html = ""
        if node.topics:
            items = []
            for t in node.topics:
                if t in all_slugs:
                    items.append(f'<a href="{t}.html" class="pill topic-pill">{slug_to_display(t)}</a>')
                else:
                    items.append(f'<span class="pill topic-pill">{slug_to_display(t)}</span>')
            topics_html = f'<section class="topics-section"><h2>Topics</h2><div class="topic-pills">{"".join(items)}</div></section>'

        # Prev/next within same domain
        nav_html = self._domain_nav(node)

        return NODE_PAGE_TEMPLATE.format(
            title=_esc(node.title),
            slug=node.slug,
            type_label=TYPE_LABELS.get(node.type, node.type.title()),
            type_color=type_color,
            status=node.status,
            status_color=status_color,
            created_html=created_html,
            repos_html=repos_html,
            description=_esc(node.description),
            body_html=body_html,
            related=related,
            backlinks=backlinks_html,
            topics=topics_html,
            nav_html=nav_html,
        )

    def _domain_nav(self, node: BrainNode) -> str:
        """Build prev/next navigation within the same domain."""
        if not node.topics:
            return ""
        domain = node.topics[0]
        if domain not in self.nodes:
            return ""
        # Get all nodes in this domain
        domain_node = self.nodes[domain]
        siblings = [l["target"] for l in domain_node.wiki_links if l["target"] in self.nodes and l["target"] != domain]
        if node.slug not in siblings:
            return ""
        idx = siblings.index(node.slug)
        prev_link = f'<a href="{siblings[idx-1]}.html" class="nav-prev">← {slug_to_display(siblings[idx-1])}</a>' if idx > 0 else '<span></span>'
        next_link = f'<a href="{siblings[idx+1]}.html" class="nav-next">{slug_to_display(siblings[idx+1])} →</a>' if idx < len(siblings) - 1 else '<span></span>'
        return f'<nav class="domain-nav"><div class="domain-nav-inner">{prev_link}<span class="domain-nav-label">{slug_to_display(domain)}</span>{next_link}</div></nav>'

    def _write_index_page(self):
        # Domain map sidebar items
        domain_items = []
        for dm in DOMAIN_MAPS:
            if dm in self.nodes:
                count = sum(1 for n in self.nodes.values() if dm in n.topics)
                domain_items.append(
                    f'<a href="./nodes/{dm}.html" class="domain-link">'
                    f'<span class="domain-dot" style="background:{self.nodes[dm].color}"></span>'
                    f'{slug_to_display(dm)} <span class="domain-count">{count}</span></a>'
                )
        domain_list = "\n".join(domain_items)

        # Stats
        total = len(self.nodes)
        total_edges = len(self.graph_edges)
        type_counts = {}
        for n in self.nodes.values():
            type_counts[n.type] = type_counts.get(n.type, 0) + 1
        stats_pills = "".join(
            f'<span class="stat-pill" style="border-color:{TYPE_COLORS.get(t, "#6b7280")}">'
            f'{TYPE_LABELS.get(t, t.title())}: {c}</span>'
            for t, c in sorted(type_counts.items())
        )

        html = INDEX_TEMPLATE.format(
            domain_list=domain_list,
            total_nodes=total,
            total_edges=total_edges,
            stats_pills=stats_pills,
        )
        (self.output / "index.html").write_text(html)


# ──────────────────────────────────────────────
# Templates
# ──────────────────────────────────────────────

CSS = """\
:root {
  --bg: #0d1117;
  --bg-card: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --link: #58a6ff;
  --code-bg: #1f2937;
  --code-text: #e5e7eb;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  line-height: 1.6;
  min-height: 100vh;
}

a { color: var(--link); text-decoration: none; transition: opacity 0.2s; }
a:hover { opacity: 0.8; text-decoration: underline; }

/* ── Layout ── */
.page-wrapper {
  max-width: 860px;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
}

/* ── Breadcrumb ── */
.breadcrumb {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}
.breadcrumb a { color: var(--link); }

/* ── Metadata pills ── */
.meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  align-items: center;
}
.pill {
  display: inline-block;
  padding: 0.2rem 0.7rem;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 500;
  border: 1px solid var(--border);
  background: var(--bg-card);
  color: var(--text);
  transition: background 0.2s;
}
.pill:hover { background: var(--border); }
.type-pill { border-color: currentColor; }
.status-pill { border-color: currentColor; }
.repo-pill { border-color: #58a6ff; color: #58a6ff; }
.date-pill { color: var(--text-muted); }
.topic-pill { border-color: #eab308; color: #eab308; cursor: pointer; }

/* ── Node title ── */
.node-title {
  font-size: 1.6rem;
  font-weight: 700;
  line-height: 1.3;
  margin-bottom: 0.5rem;
  color: #e6edf3;
}

.node-description {
  color: var(--text-muted);
  font-size: 0.95rem;
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
  font-style: italic;
}

/* ── Body content ── */
.node-body h1 { font-size: 1.5rem; margin: 2rem 0 1rem; color: #e6edf3; }
.node-body h2 { font-size: 1.25rem; margin: 1.8rem 0 0.8rem; color: #e6edf3; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }
.node-body h3 { font-size: 1.1rem; margin: 1.5rem 0 0.6rem; color: #e6edf3; }
.node-body p { margin-bottom: 1rem; }
.node-body ul, .node-body ol { margin: 0.5rem 0 1rem 1.5rem; }
.node-body li { margin-bottom: 0.4rem; }
.node-body code {
  background: var(--code-bg);
  color: var(--code-text);
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.88em;
}
.node-body pre {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  overflow-x: auto;
  margin: 1rem 0;
}
.node-body pre code {
  background: none;
  padding: 0;
  font-size: 0.85rem;
  line-height: 1.5;
}
.node-body blockquote {
  border-left: 3px solid var(--border);
  padding-left: 1rem;
  color: var(--text-muted);
  margin: 1rem 0;
}
.node-body table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
.node-body th, .node-body td { border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left; }
.node-body th { background: var(--bg-card); }
.node-body hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }

/* ── Wiki links ── */
.wiki-link {
  color: var(--link);
  border-bottom: 1px dotted var(--link);
  transition: all 0.2s;
}
.wiki-link:hover { border-bottom-style: solid; }
.wiki-link.broken { color: #f87171; border-color: #f87171; cursor: not-allowed; }
.rel-label { color: var(--text-muted); font-size: 0.85rem; font-style: italic; }
.link-desc { color: var(--text-muted); font-size: 0.82rem; margin-top: 0.15rem; }

/* ── Sections ── */
.related, .backlinks, .topics-section {
  margin-top: 2.5rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
}
.related h2, .backlinks h2, .topics-section h2 {
  font-size: 1.1rem;
  color: #e6edf3;
  margin-bottom: 1rem;
}
.related ul, .backlinks ul { list-style: none; padding: 0; }
.related li, .backlinks li {
  padding: 0.6rem 0.8rem;
  border-radius: 6px;
  margin-bottom: 0.4rem;
  transition: background 0.2s;
}
.related li:hover, .backlinks li:hover { background: var(--bg-card); }
.topic-pills { display: flex; flex-wrap: wrap; gap: 0.5rem; }

/* ── Domain nav ── */
.domain-nav {
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
}
.domain-nav-inner {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.domain-nav-label { color: var(--text-muted); font-size: 0.85rem; }
.nav-prev, .nav-next { font-size: 0.9rem; }

/* ── Index page ── */
.index-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 280px;
  min-width: 280px;
  background: var(--bg-card);
  border-right: 1px solid var(--border);
  padding: 1.5rem;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  z-index: 10;
}

.sidebar-title {
  font-size: 1.3rem;
  font-weight: 700;
  color: #e6edf3;
  margin-bottom: 0.3rem;
  letter-spacing: -0.02em;
}
.sidebar-subtitle {
  font-size: 0.78rem;
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}

.search-box {
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  font-size: 0.88rem;
  outline: none;
  margin-bottom: 1.5rem;
  transition: border-color 0.2s;
}
.search-box:focus { border-color: var(--link); }
.search-box::placeholder { color: var(--text-muted); }

.search-results {
  list-style: none;
  padding: 0;
  margin-bottom: 1.5rem;
  display: none;
  max-height: 300px;
  overflow-y: auto;
}
.search-results.active { display: block; }
.search-results li {
  padding: 0.4rem 0.5rem;
  border-radius: 4px;
  margin-bottom: 0.2rem;
}
.search-results li:hover { background: var(--border); }
.search-results li a { display: block; font-size: 0.85rem; }
.search-results .search-type {
  font-size: 0.7rem;
  color: var(--text-muted);
  margin-left: 0.4rem;
}

.domain-section {
  margin-bottom: 1.5rem;
}
.domain-section-title {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  margin-bottom: 0.6rem;
}

.domain-link {
  display: flex;
  align-items: center;
  padding: 0.45rem 0.5rem;
  border-radius: 6px;
  font-size: 0.88rem;
  transition: background 0.2s;
  gap: 0.5rem;
}
.domain-link:hover { background: var(--border); text-decoration: none; }
.domain-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.domain-count {
  margin-left: auto;
  font-size: 0.75rem;
  color: var(--text-muted);
  background: var(--bg);
  padding: 0.1rem 0.45rem;
  border-radius: 999px;
}

.sidebar-stats {
  margin-top: auto;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  font-size: 0.78rem;
  color: var(--text-muted);
}
.stat-pill {
  display: inline-block;
  font-size: 0.72rem;
  padding: 0.15rem 0.5rem;
  border: 1px solid;
  border-radius: 999px;
  margin: 0.2rem 0.2rem 0.2rem 0;
}

.graph-container {
  flex: 1;
  position: relative;
}
#graph-canvas {
  width: 100%;
  height: 100%;
}

/* ── Hamburger (mobile) ── */
.hamburger {
  display: none;
  position: fixed;
  top: 1rem;
  left: 1rem;
  z-index: 20;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 0.65rem;
  color: var(--text);
  font-size: 1.2rem;
  cursor: pointer;
  line-height: 1;
}

.sidebar-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  z-index: 9;
}

@media (max-width: 768px) {
  .hamburger { display: block; }
  .sidebar {
    position: fixed;
    left: -300px;
    top: 0;
    height: 100vh;
    transition: left 0.3s;
  }
  .sidebar.open { left: 0; }
  .sidebar-overlay.open { display: block; }
}

/* ── Tooltip ── */
.node-tooltip {
  position: fixed;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.6rem 0.8rem;
  max-width: 320px;
  font-size: 0.82rem;
  color: var(--text);
  pointer-events: none;
  z-index: 100;
  display: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.4);
}
"""

GRAPH_JS = """\
/* brain.terp.network — graph initialization */
(function() {
  'use strict';

  let network = null;
  let searchIndex = [];
  let graphData = null;

  async function init() {
    // Load data
    const [graphResp, searchResp] = await Promise.all([
      fetch('./graph-data.json'),
      fetch('./search-index.json'),
    ]);
    graphData = await graphResp.json();
    searchIndex = await searchResp.json();

    // Build vis.js datasets
    const nodes = new vis.DataSet(graphData.nodes.map(n => ({
      id: n.id,
      label: n.label,
      color: {
        background: n.color,
        border: n.color,
        highlight: { background: n.color, border: '#ffffff' },
        hover: { background: n.color, border: '#ffffff' },
      },
      size: n.size,
      title: n.title,
      font: {
        color: '#c9d1d9',
        size: 12,
        face: '-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif',
        strokeWidth: 3,
        strokeColor: '#0d1117',
      },
      shape: n.type === 'moc' ? 'diamond' : 'dot',
      shadow: {
        enabled: true,
        color: n.color + '40',
        size: 10,
      },
    })));

    const edges = new vis.DataSet(graphData.edges.map((e, i) => ({
      id: i,
      from: e.from,
      to: e.to,
      label: e.label || undefined,
      color: { color: '#30363d', highlight: '#58a6ff', hover: '#58a6ff' },
      font: { color: '#8b949e', size: 9, strokeWidth: 0, align: 'middle' },
      smooth: { type: 'continuous' },
      width: 1.5,
    })));

    // Create network
    const container = document.getElementById('graph-canvas');
    network = new vis.Network(container, { nodes, edges }, {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -80,
          centralGravity: 0.01,
          springLength: 120,
          springConstant: 0.06,
          damping: 0.4,
          avoidOverlap: 0.3,
        },
        stabilization: { iterations: 200 },
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        navigationButtons: false,
        keyboard: true,
      },
      layout: { improvedLayout: true },
    });

    // Click → navigate
    network.on('click', function(params) {
      if (params.nodes.length > 0) {
        const slug = params.nodes[0];
        window.location.href = './nodes/' + slug + '.html';
      }
    });

    // Hover cursor
    network.on('hoverNode', () => container.style.cursor = 'pointer');
    network.on('blurNode', () => container.style.cursor = 'default');

    // Search
    setupSearch();

    // Hamburger
    const hamburger = document.querySelector('.hamburger');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    if (hamburger) {
      hamburger.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('open');
      });
      overlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('open');
      });
    }
  }

  function setupSearch() {
    const input = document.querySelector('.search-box');
    const results = document.querySelector('.search-results');
    if (!input || !results) return;

    input.addEventListener('input', function() {
      const q = this.value.toLowerCase().trim();
      if (q.length < 2) {
        results.classList.remove('active');
        results.innerHTML = '';
        return;
      }

      const matches = searchIndex.filter(n =>
        n.title.toLowerCase().includes(q) ||
        n.description.toLowerCase().includes(q) ||
        n.slug.toLowerCase().includes(q) ||
        (n.topics || []).some(t => t.toLowerCase().includes(q))
      ).slice(0, 12);

      if (matches.length === 0) {
        results.innerHTML = '<li style="color:var(--text-muted)">No results</li>';
        results.classList.add('active');
        return;
      }

      results.innerHTML = matches.map(m =>
        '<li><a href="./nodes/' + m.slug + '.html">' +
        escHtml(m.title) +
        '<span class="search-type">' + m.type + '</span>' +
        '</a></li>'
      ).join('');
      results.classList.add('active');
    });

    // Close on outside click
    document.addEventListener('click', function(e) {
      if (!input.contains(e.target) && !results.contains(e.target)) {
        results.classList.remove('active');
      }
    });
  }

  function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // Boot
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
"""

INDEX_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>terp-brain — Knowledge Graph</title>
  <link rel="stylesheet" href="./assets/style.css">
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
</head>
<body>
  <button class="hamburger" aria-label="Menu">☰</button>
  <div class="sidebar-overlay"></div>
  <div class="index-layout">
    <aside class="sidebar">
      <div class="sidebar-title">🧠 terp-brain</div>
      <div class="sidebar-subtitle">Knowledge graph · {total_nodes} nodes · {total_edges} edges</div>

      <input type="text" class="search-box" placeholder="Search nodes..." autocomplete="off">
      <ul class="search-results"></ul>

      <div class="domain-section">
        <div class="domain-section-title">Domain Maps</div>
        {domain_list}
      </div>

      <div class="sidebar-stats">
        <div style="margin-bottom:0.4rem">Node types:</div>
        {stats_pills}
      </div>
    </aside>
    <div class="graph-container">
      <div id="graph-canvas"></div>
    </div>
  </div>
  <script src="./assets/graph.js"></script>
</body>
</html>
"""

NODE_PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — terp-brain</title>
  <link rel="stylesheet" href="../assets/style.css">
</head>
<body>
  <div class="page-wrapper">
    <div class="breadcrumb">
      <a href="../index.html">🧠 terp-brain</a> / <span>{slug}</span>
    </div>

    <div class="meta-row">
      <span class="pill type-pill" style="color:{type_color};border-color:{type_color}">{type_label}</span>
      <span class="pill status-pill" style="color:{status_color};border-color:{status_color}">{status}</span>
      {created_html}
      {repos_html}
    </div>

    <h1 class="node-title">{title}</h1>
    <div class="node-description">{description}</div>

    <div class="node-body">
      {body_html}
    </div>

    {related}
    {backlinks}
    {topics}
    {nav_html}
  </div>

  <div class="node-tooltip" id="tooltip"></div>
  <script>
    // Hover preview for wiki-links
    document.querySelectorAll('.wiki-link[data-slug]').forEach(function(el) {{
      el.addEventListener('mouseenter', function(e) {{
        var tip = document.getElementById('tooltip');
        var slug = el.dataset.slug;
        fetch('../search-index.json').then(r => r.json()).then(function(idx) {{
          var node = idx.find(function(n) {{ return n.slug === slug; }});
          if (node) {{
            tip.innerHTML = '<strong>' + node.title + '</strong><br><span style="color:var(--text-muted)">' + (node.description || '').substring(0, 150) + '</span>';
            tip.style.display = 'block';
            tip.style.left = (e.clientX + 12) + 'px';
            tip.style.top = (e.clientY + 12) + 'px';
          }}
        }});
      }});
      el.addEventListener('mouseleave', function() {{
        document.getElementById('tooltip').style.display = 'none';
      }});
      el.addEventListener('mousemove', function(e) {{
        var tip = document.getElementById('tooltip');
        tip.style.left = (e.clientX + 12) + 'px';
        tip.style.top = (e.clientY + 12) + 'px';
      }});
    }});
  </script>
</body>
</html>
"""


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Build brain.terp.network static site")
    parser.add_argument("--source", type=Path, default=Path.home() / "terp-brain" / "nodes",
                        help="Source directory with .md node files")
    parser.add_argument("--output", type=Path, default=Path.home() / "abstract" / "bme" / "o-line" / "dist" / "brain",
                        help="Output directory for static site")
    parser.add_argument("--graphify", type=Path, default=None,
                        help="Optional graphify graph.json for additional edges")
    args = parser.parse_args()

    if not args.source.exists():
        log.error(f"Source directory not found: {args.source}")
        sys.exit(1)

    builder = BrainSiteBuilder(args.source, args.output, args.graphify)
    builder.build()


if __name__ == "__main__":
    main()
