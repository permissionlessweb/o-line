#!/usr/bin/env bash
set -euo pipefail

echo "=== O-Line Tool Generation Setup ==="

if [[ ! -d gen-tools ]]; then
  echo "Creating gen-tools Python library..."
  mkdir -p gen-tools/gen_tools .team/tools/generated
  
  # Simple setup.py
  cat > gen-tools/setup.py << 'EOF'
from setuptools import setup, find_packages

setup(
    name="gen-tools",
    version="0.1.0",
    description="Tool generation for oline .team",
    author="Oline Team",
    packages=find_packages(),
    install_requires=[
        "click",
        "pyyaml",
        "rich",
    ],
    entry_points={
        'console_scripts': [
            'gen-tools=gen_tools.cli:main',
        ],
    },
)
EOF

  # Init files
  mkdir -p gen-tools/gen_tools
  echo '__version__ = "0.1.0"' > gen-tools/gen_tools/__init__.py

  # Simple CLI
  cat > gen-tools/gen_tools/cli.py << 'EOF'
#!/usr/bin/env python3
import click
import yaml
from pathlib import Path

@click.group()
def main():
    pass

@main.command()
@click.argument('spec_file')
@click.option('--output', '-o', default='.team/tools/generated')
def generate(spec_file, output):
    print(f"Generating from {spec_file} to {output}")
    with open(spec_file) as f:
        spec = yaml.safe_load(f)
    
    output_path = Path(output)
    output_path.mkdir(exist_ok=True)
    
    for tool in spec.get('tools', []):
        name = tool['name']
        with open(output_path / f"{name}.py", 'w') as f:
            f.write(f"#!/usr/bin/env python3\n")
            f.write(f"# {name}\n")
            f.write(f"def {name.replace('-', '_')}():\n")
            f.write('    print(f"TODO: implement {name}")\n')
        print(f"Generated {name}.py")

if __name__ == '__main__':
    main()
EOF

  # Simple spec
  cat > .team/tools/oline-tools.yml << 'EOF'
tools:
  - name: sdl-generator
    description: "Akash SDL generation"
  - name: key-manager
    description: "Key encryption operations"
  - name: dns-updater
    description: "DNS configuration"
  - name: snapshot-sync
    description: "Snapshot management"
  - name: relayer-setup
    description: "IBC relayer config"
EOF

  echo "✅ gen-tools created"
  echo "Install: cd gen-tools && pip install -e ."
else
  echo "gen-tools exists - update with pip install -e gen-tools/"
fi
 