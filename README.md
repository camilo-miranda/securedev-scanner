# SecureDev AI Scanner — v0.1

Motor inicial de auditoría estática. Acepta:
- Un directorio local.
- Un archivo ZIP local.
- Un repositorio público de GitHub (URL HTTPS).

Ejecuta Semgrep, Trivy y Gitleaks si están instalados. No ejecuta scripts, builds,
tests ni gestores de paquetes del proyecto auditado.

## Requisitos
- Python 3.11+
- Git (solo para repositorios GitHub)
- Semgrep, Trivy y Gitleaks (opcionales individualmente)

## Instalación

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

Instala los analizadores según sus instrucciones oficiales:
- https://semgrep.dev/docs/getting-started/
- https://trivy.dev/latest/docs/
- https://github.com/gitleaks/gitleaks

## Ejecución

```bash
python -m scanner.main --path ./mi-proyecto --out ./output
python -m scanner.main --zip ./proyecto.zip --out ./output
python -m scanner.main --repo https://github.com/ORG/REPO --ref main --out ./output
```

Los resultados se guardan en `output/report.json` y `output/summary.txt`.

## Seguridad y alcance
- Solo admite repositorios alojados en github.com mediante HTTPS.
- El ZIP se extrae con validación de rutas, límites de tamaño y rechazo de enlaces.
- No se ejecuta código del proyecto.
- Las herramientas se ejecutan con timeout y sin shell.
- El análisis estático no demuestra ausencia de vulnerabilidades.
- No subir proyectos confidenciales a un servicio externo sin autorización.

## Limitaciones de v0.1
La carga de ZIP desde Jotform/R2 y el envío automático de resultados a Cloudflare
se implementarán en la siguiente integración. En esta versión el ZIP se analiza
localmente y los repositorios públicos pueden analizarse mediante GitHub Actions.
