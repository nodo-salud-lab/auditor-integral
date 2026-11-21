#!/usr/bin/env python3
"""Gestión de la carpeta de corrida del auditor (PLAN_MAESTRO §3.2, "Salida en el proyecto auditado").

<proyecto>/.auditoria/<AAAA-MM-DD_HHMM>-<commit7 | sin-commits | sin-git>/run.json

Del proyecto auditado solo se escribe:
  - la carpeta .auditoria/ (o la indicada con --salida), y
  - la línea '.auditoria/' en .git/info/exclude, si es un repositorio git.
Las consultas a git son de solo lectura (--no-optional-locks: ni siquiera refresca el índice) y pasan
por git_seguro: el .git/config del repo auditado no es confiable (core.fsmonitor, filtros, textconv).
Por eso no se usa `git status` y run.json.git_sucio queda en null.

Seguridad de la carpeta (correcciones post-verificación):
  - cada `crear` hace una carpeta nueva (si el nombre ya existe se agrega -2, -3...): dos corridas en
    el mismo minuto no se pisan;
  - `.auditoria` no puede ser un enlace simbólico, y la carpeta resuelta debe quedar dentro del proyecto;
  - `ultima` solo acepta carpetas con nombre del formato propio, sin enlaces, cuyo run.json declare
    este mismo proyecto y esta misma carpeta y cuya fecha no esté en el futuro (una corrida plantada
    en el repo con fecha 9999-12-31 no gana);
  - run.json se reescribe con un temporal único y bajo fcntl.flock (invocaciones concurrentes).

Uso:
  corrida.py crear --proyecto RUTA --modo MODO [--salida DIR] [--subcomando S]   → imprime la carpeta
  corrida.py ultima --proyecto RUTA                                              → imprime la más reciente
  corrida.py fase --corrida DIR --fase F --estado E --codigo N --duracion S [--detalle TXT]
"""
import argparse
import datetime as dt
import fcntl
import json
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import git_seguro  # noqa: E402

VERSION_AUDITOR = "0.2.0"
MODOS = ("rapido", "estandar", "profundo")
ESTADOS_FASE = ("ok", "error", "pendiente", "omitida", "en_curso")
LINEA_EXCLUDE = ".auditoria/"
# sin-git: fuera de todo repositorio; sin-commits: dentro de un repo que aún no tiene ningún commit.
RE_ID = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{4})-([0-9a-f]{7}|sin-git|sin-commits)(?:-(\d{1,4}))?$")


def _git(proyecto, *args):
    """Ejecuta git en modo solo lectura y seguro (git_seguro); devuelve stdout o None si falla."""
    codigo, salida = git_seguro.ejecutar(proyecto, *args)
    return salida.strip() if codigo == 0 else None


def info_git(proyecto):
    if _git(proyecto, "rev-parse", "--is-inside-work-tree") != "true":
        return {"es_repo": False, "commit": None, "commit7": None, "rama": None, "git_sucio": None}
    commit = _git(proyecto, "rev-parse", "HEAD")  # None si el repo no tiene commits
    return {
        "es_repo": True,
        "commit": commit,
        "commit7": commit[:7] if commit else None,
        "rama": _git(proyecto, "rev-parse", "--abbrev-ref", "HEAD") if commit else None,
        # `git status` ejecutaría core.fsmonitor y filtros del repo auditado: no se consulta.
        "git_sucio": None,
    }


def agregar_exclude(proyecto):
    """Agrega '.auditoria/' a .git/info/exclude (idempotente). Devuelve True si el archivo quedó con la línea."""
    comun = _git(proyecto, "rev-parse", "--git-common-dir")
    if not comun:
        return False
    git_dir = Path(comun)
    if not git_dir.is_absolute():
        git_dir = Path(proyecto) / git_dir
    exclude = git_dir / "info" / "exclude"
    try:
        # Un .git plantado puede traer info/ o info/exclude como enlace a cualquier archivo: no se siguen.
        if git_dir.is_symlink() or (git_dir / "info").is_symlink() or exclude.is_symlink():
            return False
        actual = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
        lineas = [l.strip() for l in actual.splitlines()]
        if LINEA_EXCLUDE in lineas or "/.auditoria/" in lineas or ".auditoria" in lineas:
            return True
        exclude.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(exclude, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            if actual and not actual.endswith("\n"):
                f.write("\n")
            f.write("# auditor-integral: salidas de auditoría (no versionar)\n" + LINEA_EXCLUDE + "\n")
        return True
    except OSError:
        return False


def _ahora():
    return dt.datetime.now().astimezone()


def _escribir_run(carpeta, run):
    """Escritura atómica con un temporal único por llamada (no se pisan procesos concurrentes)."""
    fd, tmp = tempfile.mkstemp(prefix=".run.", suffix=".json.tmp", dir=carpeta)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(run, ensure_ascii=False, indent=2) + "\n")
        os.replace(tmp, carpeta / "run.json")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class _Cerrojo:
    """fcntl.flock exclusivo sobre <carpeta>/.run.lock mientras se lee y reescribe run.json."""

    def __init__(self, carpeta):
        self.ruta = Path(carpeta) / ".run.lock"

    def __enter__(self):
        self.fd = os.open(self.ruta, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o644)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def _base_auditoria(proyecto):
    """<proyecto>/.auditoria, rechazando enlaces simbólicos (escribirían fuera del proyecto)."""
    base = proyecto / ".auditoria"
    if base.is_symlink():
        raise OSError(f"{base} es un enlace simbólico: se rechaza para no escribir fuera del proyecto")
    if base.exists() and not base.is_dir():
        raise OSError(f"{base} existe y no es una carpeta")
    return base


def _carpeta_nueva(base, ident):
    """Crea base/ident (o ident-2, ident-3...) de forma exclusiva y la devuelve."""
    base.mkdir(exist_ok=True)
    if base.is_symlink() or base.resolve() != base.parent.resolve() / ".auditoria":
        raise OSError(f"{base} no resuelve dentro del proyecto")
    for n in range(1, 10000):
        nombre = ident if n == 1 else f"{ident}-{n}"
        carpeta = base / nombre
        try:
            carpeta.mkdir()
        except FileExistsError:
            continue
        return carpeta
    raise OSError(f"no se pudo crear una carpeta de corrida nueva en {base}")


def crear(proyecto, modo, salida=None, subcomando=None, ahora=None):
    """Crea una carpeta de corrida nueva y su run.json (con --salida usa esa carpeta, aunque exista)."""
    if modo not in MODOS:
        raise ValueError(f"modo inválido: {modo!r} (use {', '.join(MODOS)})")
    proyecto = Path(proyecto).resolve()
    if not proyecto.is_dir():
        raise FileNotFoundError(f"no es una carpeta: {proyecto}")
    ahora = ahora or _ahora()
    g = info_git(proyecto)
    sufijo = g["commit7"] or ("sin-commits" if g["es_repo"] else "sin-git")
    ident = f"{ahora:%Y-%m-%d_%H%M}-{sufijo}"

    if salida:
        carpeta = Path(salida).resolve()
        carpeta.mkdir(parents=True, exist_ok=True)
    else:
        base = _base_auditoria(proyecto)
        if g["es_repo"]:
            agregar_exclude(proyecto)
        carpeta = _carpeta_nueva(base, ident)

    previo = {}
    if salida and (carpeta / "run.json").is_file():
        try:
            previo = json.loads((carpeta / "run.json").read_text(encoding="utf-8"))
        except ValueError:
            previo = {}
    run = {
        "version_esquema": "1",
        "auditor_version": VERSION_AUDITOR,
        "id": previo.get("id", carpeta.name if not salida else ident),
        "proyecto": str(proyecto),
        "carpeta": str(carpeta),
        "modo": modo,
        "subcomando": subcomando or previo.get("subcomando"),
        "inicio": previo.get("inicio", ahora.isoformat(timespec="seconds")),
        "actualizado": ahora.isoformat(timespec="seconds"),
        "es_repo_git": g["es_repo"],
        "commit": g["commit"],
        "commit7": g["commit7"],
        "rama": g["rama"],
        "git_sucio": g["git_sucio"],
        "fases": previo.get("fases", {}),
    }
    _escribir_run(carpeta, run)
    return carpeta


def _corrida_propia(d, proyecto, limite):
    """Clave de orden si d es una corrida creada por el auditor para este proyecto; si no, None."""
    m = RE_ID.match(d.name)
    if not m or d.is_symlink() or not d.is_dir() or (d / "run.json").is_symlink():
        return None
    try:
        fecha = dt.datetime.strptime(m.group(1), "%Y-%m-%d_%H%M")
        run = json.loads((d / "run.json").read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if fecha > limite or not isinstance(run, dict):
        return None
    if run.get("proyecto") != str(proyecto) or run.get("carpeta") != str(d.resolve()) or run.get("id") != d.name:
        return None
    return (m.group(1), int(m.group(3) or 1), d.name)


def ultima(proyecto, ahora=None):
    """Corrida más reciente creada por el auditor para este proyecto, o None (ver _corrida_propia)."""
    proyecto = Path(proyecto).resolve()
    base = proyecto / ".auditoria"
    if base.is_symlink() or not base.is_dir():
        return None
    limite = (ahora or _ahora()).replace(tzinfo=None) + dt.timedelta(minutes=1)
    candidatas = []
    for d in base.iterdir():
        clave = _corrida_propia(d, proyecto, limite)
        if clave:
            candidatas.append((clave, d))
    return max(candidatas)[1] if candidatas else None


def registrar_fase(carpeta, fase, estado, codigo, duracion_s, detalle=None):
    if estado not in ESTADOS_FASE:
        raise ValueError(f"estado de fase inválido: {estado}")
    carpeta = Path(carpeta)
    with _Cerrojo(carpeta):
        run = json.loads((carpeta / "run.json").read_text(encoding="utf-8"))
        run.setdefault("fases", {})[fase] = {
            "estado": estado,
            "codigo": codigo,
            "duracion_s": round(float(duracion_s), 3),
            "fin": _ahora().isoformat(timespec="seconds"),
            "detalle": detalle,
        }
        run["actualizado"] = _ahora().isoformat(timespec="seconds")
        _escribir_run(carpeta, run)


def main(argv=None):
    p = argparse.ArgumentParser(description="Carpeta de corrida del auditor-integral")
    sub = p.add_subparsers(dest="accion", required=True)
    c = sub.add_parser("crear")
    c.add_argument("--proyecto", required=True)
    c.add_argument("--modo", required=True, choices=MODOS)
    c.add_argument("--salida")
    c.add_argument("--subcomando")
    u = sub.add_parser("ultima")
    u.add_argument("--proyecto", required=True)
    f = sub.add_parser("fase")
    f.add_argument("--corrida", required=True)
    f.add_argument("--fase", required=True)
    f.add_argument("--estado", required=True, choices=ESTADOS_FASE)
    f.add_argument("--codigo", type=int, default=0)
    f.add_argument("--duracion", type=float, default=0.0)
    f.add_argument("--detalle")
    a = p.parse_args(argv)

    try:
        if a.accion == "crear":
            print(crear(a.proyecto, a.modo, a.salida, a.subcomando))
        elif a.accion == "ultima":
            d = ultima(a.proyecto)
            if d is None:
                return 1
            print(d)
        else:
            registrar_fase(a.corrida, a.fase, a.estado, a.codigo, a.duracion, a.detalle)
    except (ValueError, OSError) as exc:
        print(f"corrida.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
