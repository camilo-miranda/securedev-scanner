from pathlib import Path
import zipfile

MAX_FILES = 20_000
MAX_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MiB
MAX_SINGLE_FILE = 100 * 1024 * 1024   # 100 MiB

def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("El ZIP supera el límite de archivos permitido.")
        total = sum(i.file_size for i in infos)
        if total > MAX_UNCOMPRESSED:
            raise ValueError("El ZIP supera el tamaño descomprimido permitido.")

        for info in infos:
            name = info.filename.replace("\\", "/")
            target = (root / name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"Ruta insegura detectada en ZIP: {name}")
            # Rechazar enlaces simbólicos (atributo Unix).
            mode = (info.external_attr >> 16) & 0xFFFF
            if (mode & 0o170000) == 0o120000:
                raise ValueError(f"Enlace simbólico no permitido: {name}")
            if info.file_size > MAX_SINGLE_FILE:
                raise ValueError(f"Archivo individual demasiado grande: {name}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
