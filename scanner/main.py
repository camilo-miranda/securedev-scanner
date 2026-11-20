from pathlib import Path
import argparse
import json
import shutil
import subprocess
import tempfile
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .detect import detect_technologies
from .safe_extract import safe_extract_zip
from .tools import run_tool

def clone_public_github(url: str, ref: str, destination: Path) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ValueError("Solo se admiten URLs HTTPS de github.com.")
    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise ValueError("La URL del repositorio contiene componentes no permitidos.")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise ValueError("URL inválida. Formato esperado: https://github.com/OWNER/REPO")
    owner, repo = parts
    repo = repo.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
        raise ValueError("El propietario o nombre del repositorio no es válido.")
    if not re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", ref) or ref.startswith("-") or ".." in ref:
        raise ValueError("La rama o tag contiene caracteres no permitidos.")
    repo_path = f"{owner}/{repo}"
    safe_url = f"https://github.com/{repo_path}.git"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", ref, safe_url, str(destination)],
        check=True, capture_output=True, text=True, timeout=300, shell=False
    )

def main():
    ap = argparse.ArgumentParser(description="SecureDev AI static scanner")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--path", type=Path)
    src.add_argument("--zip", type=Path)
    src.add_argument("--repo")
    ap.add_argument("--ref", default="main")
    ap.add_argument("--out", type=Path, default=Path("output"))
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="securedev-") as tmp:
        work = Path(tmp) / "source"
        work.mkdir()
        if args.path:
            project = args.path.resolve()
            if not project.is_dir():
                raise SystemExit("--path debe ser un directorio.")
        elif args.zip:
            if not args.zip.is_file():
                raise SystemExit("No se encuentra el ZIP.")
            safe_extract_zip(args.zip.resolve(), work)
            children = list(work.iterdir())
            project = children[0] if len(children) == 1 and children[0].is_dir() else work
        else:
            clone_public_github(args.repo, args.ref, work)
            project = work

        technologies = detect_technologies(project)
        results_dir = args.out.resolve() / "raw"
        results_dir.mkdir(exist_ok=True)

        semgrep = run_tool(
            "semgrep",
            ["semgrep", "scan", "--config", "auto", "--json", "--metrics=off",
             "--exclude", ".git", str(project)],
            project, results_dir / "semgrep.json"
        )
        trivy = run_tool(
            "trivy",
            ["trivy", "fs", "--scanners", "vuln,misconfig,secret",
             "--format", "json", "--quiet", str(project)],
            project, results_dir / "trivy.json"
        )
        gitleaks = run_tool(
            "gitleaks",
            ["gitleaks", "dir", str(project), "--report-format", "json",
             "--report-path", str(results_dir / "gitleaks.json"), "--no-banner"],
            project, results_dir / "gitleaks.stdout.json"
        )

        report = {
            "schema_version": "1.0",
            "product": "SecureDev AI",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_type": "local_path" if args.path else ("zip" if args.zip else "github"),
            "technologies_detected": technologies,
            "scope": {
                "static_analysis": True,
                "dynamic_analysis": False,
                "project_code_executed": False
            },
            "tools": [semgrep, trivy, gitleaks],
            "limitations": [
                "La ausencia de hallazgos no demuestra que el proyecto sea seguro.",
                "El análisis dinámico y las pruebas autenticadas no están incluidos.",
                "Las herramientas no instaladas se reportan como not_installed."
            ]
        }
        report_path = args.out / "report.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        summary = [
            "SECUREDEV AI — INFORME TÉCNICO v0.1",
            f"Fecha UTC: {report['created_at']}",
            "Tecnologías: " + (", ".join(technologies) if technologies else "No identificadas"),
            "",
            "Estado de herramientas:"
        ]
        summary.extend(f"- {t['tool']}: {t['status']}" for t in report["tools"])
        summary += ["", "Alcance: análisis estático; no se ejecutó código del proyecto."]
        (args.out / "summary.txt").write_text("\n".join(summary), encoding="utf-8")
        print(f"Informe generado: {report_path}")

if __name__ == "__main__":
    main()
