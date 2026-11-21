"""Apoyo de tests: arma una carpeta de corrida con crudo de ejemplo (sin red, sin herramientas).

El crudo de tests/fixtures/crudo/app_sembrada/ salió de correr gitleaks 8.30.1, semgrep 1.181.0
(p/owasp-top-ten), osv-scanner 2.7.0 y zizmor 1.32.0 sobre validacion/app-sembrada (recortado),
más checks propios sintéticos. Los secretos que contiene son CANARIOS FALSOS de la app sembrada.

Ni la app ni ese crudo se versionan: se materializan al importar este módulo desde sus plantillas
(validacion/plantilla-app-sembrada/ y tests/fixtures/crudo/plantilla-app_sembrada/) con
validacion/sembrado.py, en carpetas ignoradas por git. Ver validacion/README.md.
"""
import json
import shutil
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FIX_CRUDO = RAIZ / "tests" / "fixtures" / "crudo" / "app_sembrada"
APP = RAIZ / "validacion" / "app-sembrada"

if str(RAIZ / "validacion") not in sys.path:
    sys.path.insert(0, str(RAIZ / "validacion"))
import sembrado  # noqa: E402

if str(RAIZ / "tests") not in sys.path:
    sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE, tmp_dir  # noqa: E402,F401  (temporales FUERA del árbol del proyecto)

sembrado.asegurar()


def canario(cid):
    """Valor (str) de un canario FALSO de la app sembrada, armado en tiempo de ejecución."""
    return sembrado.canarios()[cid].decode("utf-8")

PERFIL_TECNICO = {
    "version_esquema": "1", "generador": "test", "lenguajes": ["javascript"], "frameworks": ["react", "vite"],
    "ecosistemas": {}, "baas": "supabase", "orm": [], "ssr_serverless": False, "llm": True, "pagos": True,
    "emails": True, "docker": False, "iac": False, "k8s": False, "movil": False, "pwa": False,
    "multi_idioma": False, "agente_ia": True, "ci": True, "carpetas_build": ["dist"],
}


def preparar_corrida(base, modo="estandar", proyecto=APP, crudo=FIX_CRUDO, perfil=None, nombre="corrida"):
    corrida = Path(base) / nombre
    (corrida / "crudo").mkdir(parents=True)
    if crudo is not None:
        for f in sorted(Path(crudo).iterdir()):
            shutil.copy(f, corrida / "crudo" / f.name)
    run = {"version_esquema": "1", "id": "2026-11-18_0000-abc1234", "proyecto": str(proyecto),
           "modo": modo, "commit": "abc1234def5678", "commit7": "abc1234", "inicio": "2026-11-18T00:00:00-03:00"}
    (corrida / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (corrida / "perfil_tecnico.json").write_text(json.dumps(PERFIL_TECNICO), encoding="utf-8")
    if perfil is not None:
        (corrida / "perfil.json").write_text(json.dumps(perfil), encoding="utf-8")
    return corrida


def limpiar(ruta):
    shutil.rmtree(ruta, ignore_errors=True)
