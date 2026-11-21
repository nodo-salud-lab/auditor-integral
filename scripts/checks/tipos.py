#!/usr/bin/env python3
"""tipos — runner opcional del typecheck (Anexo C del brazo C, M-01) → COD-TIPOS.

Corre `<tsc> --noEmit --incremental --tsBuildInfoFile <tmp> -p <tsconfig> --pretty false --listFiles` sobre un
proyecto con `tsconfig.json`. Nunca instala nada y nunca escribe en el proyecto (--noEmit; el .tsbuildinfo va a una
carpeta temporal fuera de él). Corre con GIT_OPTIONAL_LOCKS=0. tsc no ejecuta vite.config (solo lo tipa).

Qué tsc se ejecuta (ronda 4, PV-R3-02: el auditor no ejecuta código del repo auditado sin confianza explícita):
  1. un tsc CONFIABLE ajeno al proyecto: AUDITOR_BIN_TSC o `tsc` del PATH, siempre que su ruta real NO esté dentro del
     proyecto auditado (un PATH con ./node_modules/.bin no lo vuelve confiable);
  2. si no hay, el `node_modules/.bin/tsc` del proyecto SOLO si (a) es un enlace simbólico cuya ruta real queda dentro
     de node_modules/typescript/ del proyecto, (b) node_modules/typescript/package.json declara name = "typescript", y
     (c) el investigador declaró el proyecto confiable con AUDITOR_CONFIAR_TSC_PROYECTO=1. Ejecutarlo es ejecutar
     código del repositorio auditado (node_modules puede estar manipulado): sin esas tres condiciones no se ejecuta
     nada y el control queda no_evaluado con el motivo.
Antes (rondas 1-3) se llamaba `npx --no-install tsc`, que resuelve y ejecuta cualquier node_modules/.bin/tsc del repo
(un `#!/bin/sh exit 0` daba el pase).

Subregla      sev    → control
  error_tsc    media  → COD-TIPOS: un error `archivo(línea,col): error TSxxxx` por hallazgo.
Pase sin_errores: tsc terminó con código 0, sin errores y (ronda 4) tipó ≥ 1 archivo fuente del proyecto según
--listFiles (sin node_modules ni .d.ts); el mensaje registra cuántos. Con 0 archivos tipados → no_evaluado.
Estados: no_evaluado sin tsc confiable, sin tsconfig, sin archivos tipados o si tsc solo dio errores de configuración
(sin ubicación); timeout si superó el límite; error si el binario no existe.
Uso: tipos.py PROYECTO DIR_CRUDO
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402

NOMBRE = "tipos"
TIMEOUT_S = 240
MAX_HALLAZGOS = 200
RE_ERROR = re.compile(r"^(?P<archivo>[^\s(][^(]*?)\((?P<linea>\d+),(?P<col>\d+)\): error (?P<cod>TS\d+): (?P<msg>.*)$")
RE_ERROR_GLOBAL = re.compile(r"\berror (TS\d+):")
EXT_TIPADOS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".vue")
ENV_CONFIAR = "AUDITOR_CONFIAR_TSC_PROYECTO"


MAX_TSCONFIG_SUBPAQUETES = 20
PROFUNDIDAD_TSCONFIG = 4


def tsconfigs_subpaquetes(proyecto):
    """Ronda 6 (stack): monorepo sin tsconfig.json en la raíz → los tsconfig.json de los subpaquetes (apps/web,
    packages/*, netlify/functions…), sin node_modules ni carpetas de build/test, hasta PROFUNDIDAD_TSCONFIG niveles."""
    proyecto = Path(proyecto)
    salida = []
    for p in comun.recorrer(proyecto, nombres={"tsconfig.json"}):
        rel = p.relative_to(proyecto).as_posix()
        if rel == "tsconfig.json" or len(Path(rel).parts) > PROFUNDIDAD_TSCONFIG or comun.es_test_o_fixture(rel):
            continue
        salida.append(rel)
    return sorted(salida)[:MAX_TSCONFIG_SUBPAQUETES]


def _configs(proyecto):
    """tsconfig a verificar: los referenciados si tsconfig.json es solo un contenedor de referencias; sin tsconfig.json
    en la raíz, los de los subpaquetes (ronda 6)."""
    base = proyecto / "tsconfig.json"
    if not base.is_file():
        return tsconfigs_subpaquetes(proyecto)
    try:
        datos = json.loads(re.sub(r"^\s*//.*$", "", base.read_text(encoding="utf-8"), flags=re.M))
    except (OSError, ValueError):
        return ["tsconfig.json"]
    refs = datos.get("references") if isinstance(datos, dict) else None
    if isinstance(refs, list) and refs and datos.get("files") == []:
        salida = []
        for r in refs:
            ruta = (r or {}).get("path") if isinstance(r, dict) else None
            if not isinstance(ruta, str):
                continue
            p = (proyecto / ruta)
            p = p / "tsconfig.json" if p.is_dir() else p
            try:
                p.resolve().relative_to(proyecto.resolve())
            except ValueError:
                continue
            if p.is_file():
                salida.append(p.relative_to(proyecto).as_posix())
        return salida or ["tsconfig.json"]
    return ["tsconfig.json"]


def _ejecutar(cmd, cwd, env, timeout):
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        salida, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.communicate()
        return None, ""
    return proc.returncode, salida.decode("utf-8", errors="replace")


def _rel(proyecto, archivo):
    p = Path(archivo)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(proyecto.resolve()).as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix()


def _dentro(ruta, base):
    try:
        Path(ruta).resolve().relative_to(Path(base).resolve())
        return True
    except (ValueError, OSError):
        return False


def tsc_externo(proyecto, explicito=None):
    """Ruta de un tsc confiable AJENO al proyecto (AUDITOR_BIN_TSC o el PATH), o None. explicito="" desactiva."""
    if explicito == "":
        return None
    candidato = explicito or os.environ.get("AUDITOR_BIN_TSC") or shutil.which("tsc")
    if not candidato or not Path(candidato).is_file() or _dentro(candidato, proyecto):
        return None
    return str(Path(candidato).resolve())


def tsc_del_proyecto(proyecto, confiar):
    """(ruta, None) si el tsc del proyecto se puede ejecutar; (None, motivo) si no (ronda 4, PV-R3-02)."""
    proyecto = Path(proyecto)
    enlace = proyecto / "node_modules" / ".bin" / "tsc"
    if not enlace.exists() and not enlace.is_symlink():
        return None, ("sin un tsc confiable (AUDITOR_BIN_TSC o tsc en el PATH, fuera del proyecto) ni "
                      "node_modules/.bin/tsc local: el auditor no instala TypeScript")
    paquete = proyecto / "node_modules" / "typescript"
    if not enlace.is_symlink():
        return None, ("node_modules/.bin/tsc no es el enlace estándar a node_modules/typescript (es un archivo propio "
                      "del repo): no se ejecuta un binario del proyecto auditado (fail-closed)")
    real = enlace.resolve()
    if not _dentro(real, paquete):
        return None, ("node_modules/.bin/tsc apunta fuera de node_modules/typescript del proyecto: no se ejecuta un "
                      "binario fuera del paquete TypeScript (fail-closed)")
    try:
        nombre = json.loads((paquete / "package.json").read_text(encoding="utf-8")).get("name")
    except (OSError, ValueError, AttributeError):
        nombre = None
    if nombre != "typescript":
        return None, "node_modules/typescript/package.json no declara el paquete typescript: no se ejecuta (fail-closed)"
    if not confiar:
        return None, (f"ejecutar node_modules/.bin/tsc es ejecutar código del repositorio auditado: sin un tsc confiable "
                      f"externo (AUDITOR_BIN_TSC) ni la declaración {ENV_CONFIAR}=1 del investigador, no se ejecuta")
    return str(real), None


def _tipados(proyecto, salida):
    """Archivos fuente del proyecto que tsc listó (--listFiles): dentro del proyecto, fuera de node_modules, sin .d.ts."""
    n = set()
    for linea in salida.splitlines():
        l = linea.strip()
        if not l.lower().endswith(EXT_TIPADOS) or l.lower().endswith(".d.ts") or RE_ERROR.match(l):
            continue
        p = Path(l) if Path(l).is_absolute() else Path(proyecto) / l
        if _dentro(p, proyecto) and "node_modules" not in Path(_rel(proyecto, str(p))).parts:
            n.add(_rel(proyecto, str(p)))
    return n


def analizar(proyecto, tsc=None, timeout=TIMEOUT_S, confiar_proyecto=None):
    """tsc: ruta de un tsc confiable externo (None = AUDITOR_BIN_TSC o PATH; "" = ninguno).
    confiar_proyecto: None = variable AUDITOR_CONFIAR_TSC_PROYECTO == "1"."""
    proyecto = Path(proyecto)
    if not (proyecto / "tsconfig.json").is_file() and not tsconfigs_subpaquetes(proyecto):
        return comun.resultado(estado="no_evaluado", motivo="sin tsconfig.json (ni en la raíz ni en subpaquetes): no hay "
                               "typecheck de TypeScript que correr")
    if confiar_proyecto is None:
        confiar_proyecto = os.environ.get(ENV_CONFIAR) == "1"
    binario, origen = tsc_externo(proyecto, tsc), "tsc confiable externo"
    if binario is None:
        binario, motivo = tsc_del_proyecto(proyecto, confiar_proyecto)
        if binario is None:
            return comun.resultado(estado="no_evaluado", motivo=motivo)
        origen = f"node_modules/.bin/tsc del proyecto ({ENV_CONFIAR}=1)"
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", CI="1", NO_UPDATE_NOTIFIER="1", npm_config_update_notifier="false")
    hallazgos, globales, codigos, tipados = [], [], [], set()
    with tempfile.TemporaryDirectory(prefix="auditor-tsc-") as tmp:
        for i, cfg in enumerate(_configs(proyecto)):
            cmd = [binario, "--noEmit", "--incremental", "--tsBuildInfoFile", str(Path(tmp) / f"tsc{i}.tsbuildinfo"),
                   "-p", cfg, "--pretty", "false", "--listFiles"]
            try:
                codigo, salida = _ejecutar(cmd, str(proyecto), env, timeout)
            except (FileNotFoundError, PermissionError):
                return comun.resultado(estado="error", motivo=f"no se pudo ejecutar {binario}")
            if codigo is None:
                return comun.resultado(estado="timeout", motivo=f"tsc superó el límite de {timeout} s")
            codigos.append(codigo)
            tipados |= _tipados(proyecto, salida)
            for linea in salida.splitlines():
                m = RE_ERROR.match(linea.strip())
                if m:
                    if len(hallazgos) < MAX_HALLAZGOS:
                        hallazgos.append(comun.hallazgo(
                            NOMBRE, "error_tsc", _rel(proyecto, m["archivo"]), int(m["linea"]),
                            f"tsc ({cfg}): {m['cod']}: {m['msg'][:200]}", f"{m['cod']}: {m['msg']}", "media"))
                elif RE_ERROR_GLOBAL.search(linea):
                    globales.append(linea.strip()[:200])
    if hallazgos:
        return comun.resultado(hallazgos)
    if globales or any(c != 0 for c in codigos):
        detalle = globales[0] if globales else f"código de salida {max(codigos)} sin errores con ubicación"
        return comun.resultado(estado="no_evaluado", motivo=f"tsc no pudo verificar los tipos (configuración): {detalle}")
    if not tipados:
        return comun.resultado(estado="no_evaluado", motivo=(
            f"tsc ({origen}) terminó sin errores, pero no tipó ningún archivo fuente del proyecto (--listFiles): "
            "no hay evidencia de typecheck (fail-closed)"))
    return comun.resultado(checks_pass=[comun.pase(NOMBRE, "sin_errores", (
        f"tsc --noEmit sin errores ({', '.join(_configs(proyecto))}; {len(tipados)} archivo(s) fuente tipado(s); "
        f"{origen})"))])


if __name__ == "__main__":
    sys.exit(comun.main_check(NOMBRE, analizar))
