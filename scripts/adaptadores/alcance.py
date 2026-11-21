#!/usr/bin/env python3
"""alcance.py — cuántos objetos relevantes puede analizar cada herramienta (precondición de «ausencia_suficiente»).

Sin «pases vacíos»: que una herramienta corra sin hallazgos solo vale como evidencia si analizó al menos un objeto
relevante (catalogo/controles.toml → alcance_requerido). Los adaptadores guardan estos conteos en su meta
(`alcance`) y estado.py los lee.

  arbol      archivos del working tree que gitleaks recorre (sin dependencias, build, VCS ni salidas del auditor)
  fuentes    (recorrido propio, informativo) archivos de código fuente; NO es el alcance de semgrep
  lockfiles  lockfiles/manifiestos con versión resuelta que lee osv-scanner (fuera de node_modules)
  workflows  .github/workflows/*.yml|*.yaml (zizmor)

Solo se cuentan nombres (lstat); nunca se abre un archivo. Las carpetas y archivos confidenciales
(config/confidencial.toml, DECISIONES.md #3) no se recorren.

Alcance de semgrep (ronda 1 de pases vacíos): sale de `paths.scanned` del JSON de semgrep (--json-output), es decir,
de lo que semgrep REALMENTE analizó tras sus exclusiones (--exclude, --max-target-bytes, lenguajes sin reglas), y no
de un recorrido propio que las ignora (desde_semgrep):
  fuentes        archivos escaneados de lenguajes para los que los rulesets usados tienen reglas de inyección
                 (EXT_SAST: js/ts/py/go/java/php/rb/…; no .sh, .yaml, .json, .html, Dockerfile, .tf), fuera de código
                 de test. Es la precondición de SEG-SAST-INY.
  fuentes_test   lo mismo, pero código de test (carpetas test/tests/__tests__, *.test.*, *.spec.*, *_test.go,
                 test_*.py). semgrep SÍ lo escanea (sus hallazgos se reportan: una carpeta test/ puede ser código
                 desplegado, p. ej. app/api/test/route.ts), pero no cuenta como alcance de producción.
  fuentes_sin_reglas       (ronda 2) archivos de código de aplicación escaneados, fuera de test, para los que los rulesets
                           cargados NO tienen reglas de inyección (Python sin Flask/Django/Pyramid/Lambda, Kotlin,
                           Scala, Swift, Rust, C…; o cualquier lenguaje cuya familia de reglas no está en el SARIF).
                           SEG-SAST-INY no pasa si es > 0 (alcance_excluyente): la ausencia de hallazgos no cubre ese
                           código.
  consultas_sql_sin_reglas (ronda 2) lo mismo, con consultas SQL; bloquea el pass de DAT-SQL-CONCATENADO.
                           Las dos claves sin_reglas se registran siempre, también en 0 (ronda 3: una clave ausente
                           bloquea el pass en estado.py). Cuentan también los archivos que semgrep no escaneó por no
                           tener reglas cargadas para su lenguaje.
  consultas_sql  archivos de `fuentes` con al menos una consulta SQL (SELECT … FROM, INSERT INTO, UPDATE … SET,
                 DELETE FROM) o una llamada .query(/.execute(/.raw( . Precondición de DAT-SQL-CONCATENADO (para
                 detectarlas se lee el texto de esos archivos, que semgrep ya leyó; nunca rutas confidenciales).
Sin `paths.scanned` → None: el meta queda sin alcance y nada pasa por ausencia (fail-closed).

Ronda 4 de pases vacíos (PV-R3-01/04), claves siempre registradas (una ausente bloquea el pass en estado.py):
  codigo_confidencial      (calcular → gitleaks) archivos de código o .env* en rutas confidenciales (config/confidencial
                           .toml compara carpetas por SEGMENTO: datos-reales/ en cualquier nivel). No se escanean
                           (privacidad, DECISIONES.md #3), así que bloquean el pass de SEG-SECRETO-REPO. Ronda 6: en las
                           carpetas AMBIGUAS (src/patients/, pages/api/pacientes/) el código no es confidencial: se
                           escanea y no cuenta aquí; solo sus archivos de datos son confidenciales.
  lockfiles_confidenciales (calcular → osv) lockfiles en rutas confidenciales: osv descarta sus resultados; bloquean
                           SEG-DEPS-CVE-*.
  fuentes_grandes          (desde_semgrep) código de aplicación > 2 MB que semgrep omite (--max-target-bytes).
  fuentes_confidenciales   (desde_semgrep) código de aplicación en rutas confidenciales (--exclude).
  fuentes_no_escaneadas    = fuentes_grandes + fuentes_confidenciales; bloquea SEG-SAST-INY y DAT-SQL-CONCATENADO.
Para contar lo confidencial se listan NOMBRES (os.walk + lstat); su contenido nunca se abre.

Uso: alcance.py PROYECTO [--confidencial TOML]          → JSON {arbol, fuentes, lockfiles, workflows}
     alcance.py PROYECTO --semgrep-json SEMGREP.json [--sarif SEMGREP.sarif]
                                                         → JSON {fuentes, fuentes_test, consultas_sql,
                                                                 fuentes_sin_reglas, consultas_sql_sin_reglas}
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

_AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(_AQUI.parent / "checks"))

import comun  # noqa: E402
import fallback as fb  # noqa: E402

EXT_FUENTES = frozenset({
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".py", ".go", ".java",
    ".kt", ".rb", ".php", ".cs", ".rs", ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".ex", ".exs",
    ".sol", ".lua", ".dart", ".sh", ".bash", ".tf", ".hcl", ".yaml", ".yml", ".json", ".html",
})
# Lenguajes de programación (no configuración): lo que exige un SAST para tener algo que analizar.
EXT_CODIGO = EXT_FUENTES - {".yaml", ".yml", ".json", ".html", ".tf", ".hcl"}
# Lenguajes con reglas de inyección en los rulesets usados (p/owasp-top-ten + reglas vibe-coding): solo estos cuentan
# como alcance de SEG-SAST-INY / DAT-SQL-CONCATENADO. Un .sh, un YAML o un JSON escaneado por reglas genéricas no.
# Ronda 2 (fail-closed): Kotlin (.kt/.kts) y Scala ya no cuentan (en p/owasp-top-ten, Kotlin solo trae reglas de
# cripto/LDAP y ninguna de inyección), y Python cuenta SOLO si el archivo usa un framework cuyas fuentes de taint
# cubre el ruleset (Flask, Django, Pyramid o un handler de AWS Lambda): no hay reglas para FastAPI ni para DB-API
# directo (psycopg2, sqlite3), y las reglas python.lang.* de comandos solo siguen argumentos de entorno.
# Verificado contra tool.driver.rules del SARIF de semgrep 1.181 con p/owasp-top-ten (2026-11-18).
EXT_JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
EXT_SAST = EXT_JS | frozenset({".py", ".go", ".java", ".rb", ".php", ".cs"})
# Familias de reglas que deben estar cargadas (tool.driver.rules del SARIF) para que un lenguaje cuente como cubierto.
# Con solo las reglas locales vibe-coding (registro caído o desactivado), solo JS/TS queda cubierto.
FAMILIAS = {
    "js": ("vibe-coding.", "javascript.", "typescript."),
    ".go": ("go.",), ".java": ("java.",), ".rb": ("ruby.",), ".php": ("php.",), ".cs": ("csharp.",),
    "flask": ("python.flask.",), "django": ("python.django.",), "pyramid": ("python.pyramid.",),
    "lambda": ("python.aws-lambda.",),
}
RE_PY_FRAMEWORK = (
    ("flask", re.compile(r"^\s*(from|import)\s+flask\b", re.M)),
    ("django", re.compile(r"^\s*(from|import)\s+django\b", re.M)),
    ("pyramid", re.compile(r"^\s*(from|import)\s+pyramid\b", re.M)),
    ("lambda", re.compile(r"^\s*def\s+\w+\s*\(\s*event\s*,\s*context\s*\)", re.M)),
)
# Código de aplicación que, si semgrep lo escaneó sin reglas de inyección para él, deja sin cubrir parte del proyecto
# (fuentes_sin_reglas). Los scripts de shell no cuentan (no son superficie de entrada de usuarios).
EXT_APP = (EXT_CODIGO | {".kts"}) - {".sh", ".bash"}
CARPETAS_TEST = comun.CARPETAS_TEST      # criterio único en checks/comun.py
RE_ARCHIVO_TEST = comun.RE_ARCHIVO_TEST
# SQL dentro de un literal (comilla o backtick justo antes de la palabra clave: no cuenta «// select the first item
# from list») o una llamada típica de cliente de base de datos.
RE_SQL = re.compile(
    r"[\"'`]\s*(SELECT\b[^;\"'`]{0,300}?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[\w.\"\[\]]+\s+SET\b|DELETE\s+FROM\b)"
    r"|\.\s*(query|execute|executemany|raw|unsafe)\s*\(|\$(queryRaw|executeRaw)(Unsafe)?\b", re.I)
MAX_BYTES_SQL = 2_000_000
LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
    "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.txt", "Cargo.lock", "go.mod", "go.sum",
    "Gemfile.lock", "composer.lock", "mix.lock", "pubspec.lock", "gradle.lockfile", "packages.lock.json",
    "conan.lock", "renv.lock",
})


def archivos_confidenciales(proyecto, confidencial=None):
    """Rutas relativas (orden estable) de los archivos que caen en rutas confidenciales (config/confidencial.toml):
    los que ningún adaptador escanea. Solo nombres (os.walk + lstat): nunca se abre un archivo. Salta dependencias,
    carpetas de build y enlaces simbólicos, igual que el recorrido normal. Fail-closed: si la configuración no se puede
    leer, se usa la de datos_confidenciales.cargar() por defecto."""
    proyecto = Path(proyecto)
    conf = fb.cargar_confidencial(confidencial)
    if conf is None:
        return []
    salida = []
    for raiz, dirs, archivos in os.walk(proyecto):
        dirs[:] = sorted(d for d in dirs if d not in comun.DIRS_EXCLUIDOS and not os.path.islink(os.path.join(raiz, d)))
        for a in sorted(archivos):
            ruta = os.path.join(raiz, a)
            if os.path.islink(ruta):
                continue
            rel = Path(ruta).relative_to(proyecto).as_posix()
            if fb._dc.es_confidencial(rel, conf):
                salida.append(rel)
    return salida


def es_codigo_secretos(rel):
    """Archivos en los que gitleaks buscaría secretos si no fueran confidenciales: código y configuración .env*
    (no datos: CSV, DICOM, JSON…). Ronda 4 (PV-R3-01)."""
    nombre = rel.rsplit("/", 1)[-1]
    return Path(nombre).suffix.lower() in (EXT_CODIGO | {".kts"}) or nombre == ".env" or nombre.startswith(".env.")


def calcular(proyecto, confidencial=None):
    proyecto = Path(proyecto)
    arbol = fuentes = lockfiles = 0
    for p in fb.recorrer(proyecto, confidencial=confidencial):
        arbol += 1
        if p.suffix.lower() in EXT_CODIGO:
            fuentes += 1
        if p.name in LOCKFILES:
            lockfiles += 1
    # Ronda 4 (PV-R3-01): código y lockfiles en rutas confidenciales (p. ej. datos-reales/script.js): no se escanean,
    # así que su ausencia de hallazgos no es evidencia (alcance_excluyente). Ronda 6: en las carpetas AMBIGUAS
    # (pacientes, patients) el código y los lockfiles conocidos no son confidenciales (se escanean y no cuentan aquí).
    conf_rel = archivos_confidenciales(proyecto, confidencial)
    codigo_confidencial = sum(1 for r in conf_rel if es_codigo_secretos(r))
    lockfiles_confidenciales = sum(1 for r in conf_rel if r.rsplit("/", 1)[-1] in LOCKFILES)
    wf = proyecto / ".github" / "workflows"
    workflows = 0
    if wf.is_dir() and not wf.is_symlink():
        workflows = sum(1 for p in sorted(wf.iterdir())
                        if p.is_file() and not p.is_symlink() and p.suffix.lower() in (".yml", ".yaml"))
    return {"arbol": arbol, "fuentes": fuentes, "lockfiles": lockfiles, "workflows": workflows,
            "codigo_confidencial": codigo_confidencial, "lockfiles_confidenciales": lockfiles_confidenciales}


es_test = comun.es_test


def _leer(ruta):
    try:
        if ruta.is_symlink() or not ruta.is_file() or ruta.stat().st_size > MAX_BYTES_SQL:
            return None
        return ruta.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _tiene_sql(ruta):
    texto = _leer(ruta)
    return texto is not None and RE_SQL.search(texto) is not None


def _hay_familia(familia, reglas):
    if reglas is None:
        return True  # sin lista de reglas (llamada directa): se asume el ruleset completo de la cabecera
    prefijos = FAMILIAS[familia]
    # las reglas propias llevan antepuesta la ruta (…reglas.semgrep.vibe-coding.<regla>)
    return any(r.startswith(prefijos) or (familia == "js" and ".vibe-coding." in r) for r in reglas)


def cubierto(rel, ruta, reglas=None):
    """True si los rulesets cargados tienen reglas de inyección que se aplican a este archivo (ver EXT_SAST)."""
    ext = Path(rel).suffix.lower()
    if ext not in EXT_SAST:
        return False
    if ext in EXT_JS:
        return _hay_familia("js", reglas)
    if ext == ".py":
        texto = _leer(ruta) or ""
        return any(rx.search(texto) and _hay_familia(fam, reglas) for fam, rx in RE_PY_FRAMEWORK)
    return _hay_familia(ext, reglas)


def reglas_de_sarif(ruta):
    """Ids de las reglas cargadas (tool.driver.rules de todos los runs), ordenados; None si no se puede leer."""
    try:
        datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
        ids = set()
        for run in datos.get("runs") or []:
            for r in (((run.get("tool") or {}).get("driver") or {}).get("rules") or []):
                if isinstance(r, dict) and isinstance(r.get("id"), str):
                    ids.add(r["id"])
        return sorted(ids)
    except (OSError, ValueError, AttributeError):
        return None


def desde_semgrep(datos, proyecto, reglas=None):
    """Alcance real de semgrep a partir de su JSON (paths.scanned). None si no lo registró (fail-closed).
    reglas: ids de las reglas cargadas (reglas_de_sarif); deciden qué lenguajes/frameworks quedan cubiertos."""
    if not isinstance(datos, dict) or not isinstance(datos.get("paths"), dict):
        return None
    escaneados = datos["paths"].get("scanned")
    if not isinstance(escaneados, list):
        return None
    base = Path(proyecto).resolve()
    fuentes = fuentes_test = consultas = sin_reglas = consultas_sin_reglas = 0
    vistos = set()
    for r in sorted({str(x) for x in escaneados}):
        rel = r.replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            continue  # solo rutas relativas dentro del proyecto (semgrep corre desde su raíz)
        vistos.add(rel)
        ext = Path(rel).suffix.lower()
        if ext not in EXT_SAST and ext not in EXT_APP:
            continue
        if es_test(rel):
            if ext in EXT_SAST:
                fuentes_test += 1
            continue
        if cubierto(rel, base / rel, reglas):
            fuentes += 1
            if _tiene_sql(base / rel):
                consultas += 1
        elif ext in EXT_APP:
            sin_reglas += 1
            if _tiene_sql(base / rel):
                consultas_sin_reglas += 1
    # Código de aplicación que semgrep ni siquiera escaneó porque ningún ruleset cargado tiene reglas para su lenguaje
    # (p. ej. Python con solo las reglas locales, Rust, Swift): también queda sin cubrir. Se excluyen *.min.js y los
    # archivos > 2 MB (semgrep los omite a propósito) y, como siempre, dependencias, build y rutas confidenciales.
    grandes = 0
    for ruta in fb.recorrer(base, extensiones=EXT_APP):
        rel = ruta.relative_to(base).as_posix()
        if rel in vistos or es_test(rel) or rel.endswith(".min.js"):
            continue
        try:
            if ruta.stat().st_size > MAX_BYTES_SQL:
                # Ronda 4 (PV-R3-04): semgrep omite los archivos > 2 MB (--max-target-bytes). Antes se descartaban
                # también aquí y el código no analizado no impedía el pass; ahora cuenta como no escaneado.
                grandes += 1
                continue
        except OSError:
            continue
        sin_reglas += 1
        if _tiene_sql(ruta):
            consultas_sin_reglas += 1
    # Ronda 4 (PV-R3-01): código de aplicación en rutas confidenciales (excluido de semgrep con --exclude; su contenido
    # no se lee, así que tampoco se sabe si tiene SQL).
    confidenciales = sum(1 for r in archivos_confidenciales(base)
                         if Path(r).suffix.lower() in EXT_APP and not es_test(r) and not r.endswith(".min.js"))
    # Ronda 3: las claves sin_reglas se registran SIEMPRE (también en 0): estado.py trata una clave excluyente ausente
    # como no evaluable (fail-closed). Ronda 4: fuentes_no_escaneadas = fuentes_grandes + fuentes_confidenciales, también
    # siempre registrada; bloquea el pass de SEG-SAST-INY y DAT-SQL-CONCATENADO.
    return {"fuentes": fuentes, "fuentes_test": fuentes_test, "consultas_sql": consultas,
            "fuentes_sin_reglas": sin_reglas, "consultas_sql_sin_reglas": consultas_sin_reglas,
            "fuentes_grandes": grandes, "fuentes_confidenciales": confidenciales,
            "fuentes_no_escaneadas": grandes + confidenciales}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proyecto")
    ap.add_argument("--confidencial")
    ap.add_argument("--semgrep-json", help="JSON de semgrep (--json-output): alcance desde paths.scanned")
    ap.add_argument("--sarif", help="SARIF de semgrep: las reglas cargadas (tool.driver.rules) deciden la cobertura")
    a = ap.parse_args(argv)
    if not Path(a.proyecto).is_dir():
        print("alcance.py: el proyecto no es una carpeta", file=sys.stderr)
        return 2
    if a.semgrep_json:
        try:
            datos = json.loads(Path(a.semgrep_json).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"alcance.py: no se pudo leer el JSON de semgrep: {e}", file=sys.stderr)
            return 1
        reglas = None
        if a.sarif:
            reglas = reglas_de_sarif(a.sarif)
            if reglas is None:
                print("alcance.py: no se pudo leer el SARIF de semgrep (reglas cargadas)", file=sys.stderr)
                return 1
        res = desde_semgrep(datos, a.proyecto, reglas)
        if res is None:
            print("alcance.py: el JSON de semgrep no trae paths.scanned (alcance no registrado)", file=sys.stderr)
            return 1
        print(json.dumps(res, sort_keys=True))
        return 0
    print(json.dumps(calcular(a.proyecto, a.confidencial), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
