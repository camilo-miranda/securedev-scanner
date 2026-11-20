from pathlib import Path
import json
import shutil
import subprocess
from datetime import datetime, timezone

def run_tool(name: str, command: list[str], cwd: Path, output_file: Path,
             timeout: int = 600) -> dict:
    if shutil.which(command[0]) is None:
        return {"tool": name, "status": "not_installed", "findings": [],
                "message": f"No se encontró el ejecutable {command[0]}."}

    started = datetime.now(timezone.utc).isoformat()
    try:
        proc = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True,
            timeout=timeout, check=False, shell=False
        )
        output_file.write_text(proc.stdout or "", encoding="utf-8")
        stderr_file = output_file.with_suffix(".stderr.txt")
        if proc.stderr:
            stderr_file.write_text(proc.stderr[-20000:], encoding="utf-8")
        parsed = None
        if proc.stdout:
            try:
                parsed = json.loads(proc.stdout)
            except json.JSONDecodeError:
                pass
        return {
            "tool": name,
            "status": "completed" if proc.returncode in (0, 1) else "error",
            "exit_code": proc.returncode,
            "started_at": started,
            "findings": parsed if parsed is not None else [],
            "raw_output_file": output_file.name,
            "message": "Ejecución finalizada."
        }
    except subprocess.TimeoutExpired:
        return {"tool": name, "status": "timeout", "findings": [],
                "message": f"Tiempo máximo excedido ({timeout}s)."}
