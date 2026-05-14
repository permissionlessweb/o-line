#!/usr/bin/env bash
set -euo pipefail

echo "=== O-Line Team Tool Setup ==="

# Create gen-tools directory structure
if [[ ! -d gen-tools ]]; then
  echo "Creating gen-tools Python library..."
  mkdir -p gen-tools/gen_tools .team/tools/generated
  
  # Simple pyproject.toml without complex YAML
  cat > gen-tools/setup.py << 'EOF'
from setuptools import setup, find_packages

setup(
    name="gen-tools",
    version="0.1.0",
    description="Tool generation for oline .team specialists",
    author="Oline Team",
    packages=find_packages(),
    install_requires=[
        "click>=8.0",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    entry_points={
        'console_scripts': [
            'gen-tools=gen_tools.cli:main',
        ],
    },
)
EOF

  # Create basic CLI
  mkdir -p gen-tools/gen_tools
  cat > gen-tools/gen_tools/__init__.py << 'EOF'
__version__ = "0.1.0"
EOF

  cat > gen-tools/gen_tools/cli.py << 'EOF'
#!/usr/bin/env python3
import click
import yaml
from pathlib import Path
from rich.console import Console

console = Console()

@click.group()
def main():
    "Generate tools for oline .team specialists"
    pass

@main.command()
@click.argument('spec_file')
@click.option('--output', '-o', default='.team/tools/generated')
def generate(spec_file, output):
    "Generate tools from YAML spec"
    console.print(f"Generating tools from {spec_file}")
    
    with open(spec_file, 'r') as f:
        spec = yaml.safe_load(f)
    
    output_path = Path(output)
    output_path.mkdir(exist_ok=True)
    
    tools = spec.get('tools', [])
    for tool in tools:
        name = tool['name']
        desc = tool.get('description', '')
        tool_file = output_path / f"{name}.py"
        
        with open(tool_file, 'w') as f:
            f.write(f"#!/usr/bin/env python3\n")
            f.write(f"# Generated: {name} - {desc}\n\n")
            f.write(f"def {name.replace('-', '_')}():\n")
            f.write(f'    """{desc}"""\n')
            f.write('    print(f"Executing {name} - TODO: implement")\n\n')
            f.write(f"if __name__ == '__main__':\n")
            f.write(f"    {name.replace('-', '_')}()\n")
        
        console.print(f"  ✓ {name}")
    
    console.print(f"\nGenerated {len(tools)} tools in {output}/")

if __name__ == '__main__':
    main()
EOF

  # Create simple oline spec
  cat > .team/tools/oline-tools.yml << 'EOF'
tools:
  - name: sdl-generator
    description: "Generate Akash SDL templates"
  - name: key-encryptor
    description: "Generate key encryption operations"
  - name: dns-updater
    description: "Generate DNS update scripts"
  - name: snapshot-sync
    description: "Generate snapshot sync operations"
  - name: relayer-setup
    description: "Generate relayer configuration"
EOF

  echo "✅ gen-tools library created"
  echo ""
  echo "Install: cd gen-tools && pip install -e ."
  echo "Generate: gen-tools generate .team/tools/oline-tools.yml"
else
  echo "gen-tools already exists"
  echo "Update: cd gen-tools && pip install -e ."
fi