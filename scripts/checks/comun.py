"""Utilidades comunes de los chequeos propios (scripts/checks/*.py).

Contrato de salida de cada chequeo (crudo/check_<nombre>.json):
  {
    "check": "<nombre>", "version": "1", "estado": "ok" | "no_evaluado" | "error",
    "motivo": str | null,
    "hallazgos":   [{regla, archivo, linea, mensaje, evidencia, severidad_sugerida}],
    "checks_pass": [{regla, archivo, mensaje}]     # subreglas verificadas y cumplidas
  }
  regla = "check:<nombre>.<subregla>" (se mapea a controles con catalogo.control_por_regla).
  checks_pass permite que el control quede en `pass` (y no en `no_evaluado`) cuando corresponde.

Además se escribe crudo/check_<nombre>.meta.json con la misma forma que los adaptadores:
  {herramienta, version, estado, exit_code, duracion_s, comando, error}.

La evidencia nunca contiene valores de secretos (ver enmascarar()).
"""
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

VERSION_CHECKS = "1"
SEVERIDADES = ("critica", "alta", "media", "baja", "info")

# Carpetas que nunca se recorren: dependencias, artefactos de build, VCS y salidas del auditor.
# Ronda 6 (secretos): también entornos de nox/tox, la caché de ruff y cualquier site-packages (código de terceros
# instalado en un entorno virtual con nombre libre, p. ej. .venv312/lib/python3.12/site-packages).
DIRS_EXCLUIDOS = frozenset({
    "node_modules", ".git", ".auditoria", "dist", "build", ".next", "out", ".nuxt", ".svelte-kit",
    ".output", ".vercel", ".turbo", "coverage", "vendor", ".venv", "venv", "env", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".cache", "bower_components",
    ".nox", ".tox", ".ruff_cache", "site-packages",
})
TAMANO_MAX = 1_000_000  # bytes por archivo de código leído

# Código de test (criterio único: lo usan adaptadores/alcance.py, archivos_clave y detectar_stack).
CARPETAS_TEST = frozenset({"test", "tests", "__tests__", "__test__", "spec", "specs", "e2e", "cypress"})
RE_ARCHIVO_TEST = re.compile(r"(\.(test|spec)\.[a-z0-9]+$|_test\.(go|py)$|^test_[^/]+\.py$|^conftest\.py$)", re.I)
# Datos de prueba: su contenido no describe al proyecto (no es evidencia de una superficie real).
CARPETAS_FIXTURE = frozenset({"fixtures", "__fixtures__", "__mocks__"})


def es_test(rel):
    """True si la ruta relativa (separador /) es código de test: carpeta de test o nombre de archivo de test."""
    partes = str(rel).split("/")
    return any(p.lower() in CARPETAS_TEST for p in partes[:-1]) or bool(RE_ARCHIVO_TEST.search(partes[-1]))


def es_test_o_fixture(rel):
    """es_test(rel) o dentro de una carpeta de fixtures/mocks. Sirve para NO usar esos archivos como evidencia
    positiva (un pase) ni para encender obligaciones del perfil; los escaneos de hallazgos no lo usan."""
    partes = str(rel).split("/")
    return es_test(rel) or any(p.lower() in CARPETAS_FIXTURE for p in partes[:-1])


def hallazgo(nombre, subregla, archivo, linea, mensaje, evidencia, severidad):
    if severidad not in SEVERIDADES:
        raise ValueError(f"severidad inválida: {severidad}")
    evidencia = (evidencia or "").strip()
    if len(evidencia) > 300:
        evidencia = evidencia[:297] + "..."
    return {
        "regla": f"check:{nombre}.{subregla}",
        "archivo": archivo,
        "linea": linea,
        "mensaje": mensaje,
        "evidencia": evidencia,
        "severidad_sugerida": severidad,
    }


def pase(nombre, subregla, mensaje, archivo=None):
    return {"regla": f"check:{nombre}.{subregla}", "archivo": archivo, "mensaje": mensaje}


def resultado(hallazgos=None, checks_pass=None, estado="ok", motivo=None):
    return {"estado": estado, "motivo": motivo, "hallazgos": hallazgos or [], "checks_pass": checks_pass or []}


def enmascarar(valor):
    """Prefijo de 4 + **** + últimos 4 (solo si es largo); nunca el valor completo."""
    valor = str(valor)
    if len(valor) >= 16:
        return f"{valor[:4]}****{valor[-4:]}"
    return "****"


def rel(proyecto, ruta):
    return Path(ruta).relative_to(proyecto).as_posix()


def recorrer(proyecto, extensiones=None, nombres=None):
    """Archivos del proyecto (orden estable), saltando DIRS_EXCLUIDOS y enlaces simbólicos."""
    proyecto = Path(proyecto)
    for raiz, dirs, archivos in os.walk(proyecto):
        dirs[:] = sorted(d for d in dirs if d not in DIRS_EXCLUIDOS and not os.path.islink(os.path.join(raiz, d)))
        for a in sorted(archivos):
            p = Path(raiz) / a
            if p.is_symlink():
                continue
            if extensiones is not None and p.suffix.lower() not in extensiones:
                continue
            if nombres is not None and a not in nombres:
                continue
            yield p


def leer(ruta, limite=TAMANO_MAX):
    try:
        if ruta.stat().st_size > limite:
            return None
        return ruta.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def linea_de(texto, patron, desde=0):
    """Número de línea (1-based) de la primera coincidencia de `patron` (cadena o regex compilada)."""
    if isinstance(patron, str):
        i = texto.find(patron, desde)
        if i < 0:
            return None
    else:
        m = patron.search(texto, desde)
        if not m:
            return None
        i = m.start()
    return texto.count("\n", 0, i) + 1


def linea_texto(texto, n):
    lineas = texto.splitlines()
    return lineas[n - 1] if n and 0 < n <= len(lineas) else ""


def escribir_json(ruta, datos):
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_suffix(ruta.suffix + ".tmp")
    tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(ruta)


def main_check(nombre, analizar, argv=None, **kwargs_extra):
    """CLI común: <script> PROYECTO DIR_CRUDO. Escribe check_<nombre>.json y su .meta.json.

    `kwargs_extra` puede ser un callable(proyecto, crudo) → dict de argumentos para analizar().
    Código de salida 0 salvo error de uso (2) o excepción (1, con meta estado=error).
    """
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] in ("-h", "--help"):
        print(f"uso: {nombre}.py PROYECTO DIR_CRUDO", file=sys.stderr)
        return 2
    proyecto, crudo = Path(argv[0]).resolve(), Path(argv[1])
    if not proyecto.is_dir():
        print(f"{nombre}.py: no es una carpeta: {proyecto}", file=sys.stderr)
        return 2
    crudo.mkdir(parents=True, exist_ok=True)
    inicio = time.monotonic()
    comando = " ".join(shlex.quote(x) for x in [Path(sys.argv[0]).name, *argv])
    error = None
    codigo = 0
    try:
        extra = kwargs_extra.get("argumentos")
        kw = extra(proyecto, crudo) if extra else {}
        res = analizar(proyecto, **kw)
    except Exception as e:  # el chequeo nunca debe tumbar la fase completa
        res = resultado(estado="error", motivo=f"{type(e).__name__}: {e}")
        error = res["motivo"]
        codigo = 1
    datos = {"check": nombre, "version": VERSION_CHECKS, **res}
    escribir_json(crudo / f"check_{nombre}.json", datos)
    escribir_json(crudo / f"check_{nombre}.meta.json", {
        "herramienta": f"check:{nombre}",
        "version": VERSION_CHECKS,
        "estado": res["estado"],
        "exit_code": codigo,
        "duracion_s": round(time.monotonic() - inicio, 3),
        "comando": comando,
        "error": error if error else (res["motivo"] if res["estado"] != "ok" else None),
        "salidas": [f"check_{nombre}.json"],
        "conteo": len(res["hallazgos"]),
    })
    return codigo


# Patrones de valores con forma de secreto (compartidos por env_publicas y config_agentes).
PATRONES_SECRETO = [
    ("stripe_secreta", re.compile(r"^(sk|rk)_(live|test)_[A-Za-z0-9]{10,}")),
    ("openai_anthropic", re.compile(r"^sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}")),
    ("github", re.compile(r"^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|^github_pat_[A-Za-z0-9_]{30,}")),
    ("aws", re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$")),
    ("slack", re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("sendgrid", re.compile(r"^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    ("supabase_secreta", re.compile(r"^sb_secret_[A-Za-z0-9_-]{10,}")),
    ("clave_privada", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("url_con_credenciales", re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]+:[^@\s]+@")),
]


def rol_jwt(valor):
    """Rol declarado en el payload de un JWT (sin verificar firma), o None."""
    import base64
    partes = str(valor).split(".")
    if len(partes) != 3 or not partes[0].startswith("eyJ"):
        return None
    try:
        relleno = "=" * (-len(partes[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(partes[1] + relleno))
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict):
        return payload.get("role") or payload.get("rol")
    return None


def tipo_secreto(valor):
    """Nombre del tipo de secreto si el valor tiene forma de credencial privada; None si no."""
    v = str(valor).strip().strip("'\"")
    if not v:
        return None
    for nombre, patron in PATRONES_SECRETO:
        if patron.search(v):
            return nombre
    rol = rol_jwt(v)
    if rol == "service_role":
        return "jwt_service_role"
    return None


def es_referencia_variable(valor):
    """${VAR}, $VAR o %VAR%: el valor real vive fuera del archivo."""
    v = str(valor).strip()
    return bool(re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*(:-[^}]*)?\}?|%[A-Za-z_][A-Za-z0-9_]*%", v))
