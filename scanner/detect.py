from pathlib import Path

MARKERS = {
    "Python": ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py"],
    "JavaScript/TypeScript": ["package.json", "tsconfig.json", "vite.config.ts"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "PHP": ["composer.json"],
    "C#/.NET": [".sln", ".csproj", "global.json"],
    "Go": ["go.mod"],
    "Ruby": ["Gemfile"],
    "Rust": ["Cargo.toml"],
    "Infrastructure as Code": ["terraform.tf", ".tf", "Chart.yaml"],
    "Containers": ["Dockerfile", "docker-compose.yml", "compose.yaml"],
}

def detect_technologies(root: Path) -> list[str]:
    found = set()
    # Solo inspección de nombres; no lee ni ejecuta scripts.
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in {".git", "node_modules", ".venv", "venv", "__pycache__"}
               for part in p.parts):
            continue
        name = p.name
        for tech, markers in MARKERS.items():
            if any(name == m or (m.startswith(".") and p.suffix == m) for m in markers):
                found.add(tech)
    return sorted(found)
