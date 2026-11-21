#!/usr/bin/env python3
"""registro_deps — dependencias que no existen en el registro (slopsquatting) o que se publicaron
hace muy poco (PLAN_MAESTRO §3.2; control SEG-DEPS-EXISTEN, N1).

Lee package.json (dependencies, devDependencies, optionalDependencies, peerDependencies),
requirements*.txt y pyproject.toml ([project].dependencies, [project.optional-dependencies],
[tool.poetry.dependencies]) y consulta:
  npm:  https://registry.npmjs.org/<paquete>   (documento abreviado; el completo solo si hay pocas
        versiones, que es cuando el paquete es nuevo y el documento es chico)
  PyPI: https://pypi.org/pypi/<paquete>/json
Subreglas:
  inexistente  el registro responde 404 → crítica (la IA inventó el nombre o alguien lo registrará)
  reciente     primera publicación hace < 30 días → alta (paquete recién registrado: revisar a mano)
Ronda 3 (PV-R2-07, fail-closed): también se lee Pipfile ([packages], [dev-packages]; PyPI). Los manifiestos de
ecosistemas sin verificador (go.mod, Cargo.toml, Gemfile, composer.json, pubspec.yaml, pom.xml, build.gradle(.kts),
*.csproj, mix.exs, Package.swift) con ≥ 1 dependencia quedan registrados en `no_cubiertos` e impiden los pases: «todas
las dependencias existen» no se puede afirmar si hay dependencias que no se revisaron. Los hallazgos de los
manifiestos cubiertos se reportan igual.
Sin red: estado 'no_evaluado' (no se asume nada). Caché por corrida en DIR_CORRIDA/cache/registro_deps.json.
Variables: AUDITOR_SIN_RED=1 (interruptor global: el usuario no autorizó la red; cualquier valor distinto de vacío o
«0») fuerza el modo sin red y el motivo dice «sin red (AUDITOR_SIN_RED)»; AUDITOR_REGISTRO_SIN_RED=1 es su alias
histórico (solo para este check; su motivo no cita AUDITOR_SIN_RED porque el resto de la corrida sí pudo usar red); AUDITOR_REGISTRO_TIMEOUT (s, por defecto 5). En modo sin red no se abre ninguna
conexión (lo comprueban consultar_registro y _get_json); la caché de la corrida sí se usa.

Uso: registro_deps.py PROYECTO DIR_CRUDO
Ronda 4 (investigacion/16): se siguen los `-r` de requirements (dentro del proyecto; uno que no se puede seguir impide
el pase), se leen [dependency-groups] (PEP 735), [tool.poetry.group.*.dependencies] y [tool.poetry.dev-dependencies],
y setup.py, setup.cfg y environment.yml/conda.yml con dependencias impiden el pase (NO_CUBIERTOS; setup.py no se
ejecuta).
"""
import datetime as dt
import json
import os
import re
import ssl
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402

NOMBRE = "registro_deps"
DIAS_RECIENTE = 30
VERSIONES_PARA_DETALLE = 5
SECCIONES_NPM = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
PREFIJOS_NO_REGISTRO = ("file:", "link:", "workspace:", "portal:", "git+", "git:", "github:", "gitlab:",
                        "bitbucket:", "http:", "https:", "npm:")
USER_AGENT = "auditor-integral/0.1 (+chequeo de existencia de paquetes)"


class ErrorRed(Exception):
    """No hay conexión o el registro no respondió: el paquete queda sin verificar."""


# --------------------------------------------------------------------------- consulta real

# El Python de python.org en macOS no trae certificados raíz propios: si el almacén por defecto está
# vacío se usa el primer paquete de CA del sistema que exista. Nunca se desactiva la verificación TLS.
CA_SISTEMA = ("/etc/ssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem", "/usr/local/etc/openssl@3/cert.pem",
              "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")
_CONTEXTO_TLS = None


def _contexto_tls():
    global _CONTEXTO_TLS
    if _CONTEXTO_TLS is None:
        ctx = ssl.create_default_context()
        if not ctx.get_ca_certs() and not os.environ.get("SSL_CERT_FILE"):
            ca = next((c for c in CA_SISTEMA if os.path.isfile(c)), None)
            if ca:
                ctx = ssl.create_default_context(cafile=ca)
        _CONTEXTO_TLS = ctx
    return _CONTEXTO_TLS


def motivo_sin_red():
    """Texto del motivo si el usuario negó la red (AUDITOR_SIN_RED; alias AUDITOR_REGISTRO_SIN_RED), o None."""
    if os.environ.get("AUDITOR_SIN_RED", "") not in ("", "0"):
        return "sin red (AUDITOR_SIN_RED): el usuario no autorizó consultas de red"
    if os.environ.get("AUDITOR_REGISTRO_SIN_RED", "") not in ("", "0"):
        # El alias solo apaga ESTE check: no se cita AUDITOR_SIN_RED para que nadie lea «corrida sin red».
        return ("registro no consultado (AUDITOR_REGISTRO_SIN_RED=1, solo este check): "
                "el resto de la corrida pudo usar la red")
    return None


def _get_json(url, timeout, aceptar=None):
    sin_red = motivo_sin_red()
    if sin_red:  # defensa en profundidad: ningún camino abre una conexión con la red apagada
        raise ErrorRed(sin_red)
    cab = {"User-Agent": USER_AGENT}
    if aceptar:
        cab["Accept"] = aceptar
    req = urllib.request.Request(url, headers=cab)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_contexto_tls()) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise ErrorRed(f"HTTP {e.code} en {url}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ErrorRed(f"{type(e).__name__}: {e}") from e


def consultar_registro(ecosistema, nombre, timeout):
    """{existe: bool, creado: ISO8601 | None, versiones: int | None}. Lanza ErrorRed."""
    sin_red = motivo_sin_red()
    if sin_red:
        raise ErrorRed(sin_red)
    if ecosistema == "npm":
        base = "https://registry.npmjs.org/" + urllib.parse.quote(nombre, safe="@")
        doc = _get_json(base, timeout, aceptar="application/vnd.npm.install-v1+json")
        if doc is None:
            return {"existe": False}
        n = len(doc.get("versions") or {})
        creado = None
        if n <= VERSIONES_PARA_DETALLE:
            completo = _get_json(base, timeout)
            creado = ((completo or {}).get("time") or {}).get("created")
        return {"existe": True, "creado": creado, "versiones": n}
    if ecosistema == "pypi":
        doc = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(nombre)}/json", timeout)
        if doc is None:
            return {"existe": False}
        fechas = [a.get("upload_time_iso_8601") for archivos in (doc.get("releases") or {}).values()
                  for a in archivos if a.get("upload_time_iso_8601")]
        return {"existe": True, "creado": min(fechas) if fechas else None, "versiones": len(doc.get("releases") or {})}
    raise ValueError(f"ecosistema desconocido: {ecosistema}")


# --------------------------------------------------------------------------- manifiestos

def _normalizar_pypi(nombre):
    return re.sub(r"[-_.]+", "-", nombre).lower()


def _deps_npm(proyecto, archivo):
    texto = comun.leer(archivo)
    try:
        datos = json.loads(texto or "")
    except json.JSONDecodeError:
        return []
    deps = []
    for seccion in SECCIONES_NPM:
        bloque = datos.get(seccion)
        if not isinstance(bloque, dict):
            continue
        ini = texto.find(f'"{seccion}"')
        for nombre, version in bloque.items():
            v = str(version)
            if v.startswith(PREFIJOS_NO_REGISTRO) or "/" in v and not v.startswith("@") and ":" not in v:
                continue  # local, git o alias: no está en el registro público con ese nombre
            n = comun.linea_de(texto, f'"{nombre}"', max(ini, 0))
            deps.append(("npm", nombre, comun.rel(proyecto, archivo), n, f'"{nombre}": "{v}"'))
    return deps


RE_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;@ ].*)?$")


RE_INCLUDE_REQ = re.compile(r"^(?:-r|--requirement)(?:\s*=?\s*)(\S+)$")


def includes_requirements(proyecto, archivo):
    """Ronda 4 (SEG-DEPS-EXISTEN): ([archivos incluidos con -r, resueltos dentro del proyecto], [incluidos que no se
    pueden leer: fuera del proyecto, inexistentes, enlaces o URLs]). Los -c (restricciones) no agregan dependencias."""
    proyecto = Path(proyecto).resolve()
    ok, malos = [], []
    for linea in (comun.leer(archivo) or "").splitlines():
        m = RE_INCLUDE_REQ.match(linea.split(" #", 1)[0].strip())
        if not m:
            continue
        destino = m.group(1)
        ruta = (Path(archivo).parent / destino)
        try:
            dentro = ruta.resolve().relative_to(proyecto) is not None
        except ValueError:
            dentro = False
        if "://" in destino or not dentro or ruta.is_symlink() or not ruta.is_file():
            malos.append(f"{comun.rel(proyecto, Path(archivo).resolve())} → -r {destino}")
        else:
            ok.append(ruta.resolve())
    return ok, malos


def _deps_requirements(proyecto, archivo):
    texto = comun.leer(archivo) or ""
    deps = []
    for n, linea in enumerate(texto.splitlines(), 1):
        l = linea.split("#", 1)[0].strip()
        if not l or l.startswith(("-", "git+", "http:", "https:", "file:", ".", "/")):
            continue
        m = RE_REQ.match(l)
        if m and "@" not in (m.group(3) or "")[:2]:
            deps.append(("pypi", _normalizar_pypi(m.group(1)), comun.rel(proyecto, archivo), n, l))
    return deps


def _deps_pyproject(proyecto, archivo):
    texto = comun.leer(archivo) or ""
    try:
        datos = tomllib.loads(texto)
    except tomllib.TOMLDecodeError:
        return []
    especs = list((datos.get("project") or {}).get("dependencies") or [])
    for grupo in ((datos.get("project") or {}).get("optional-dependencies") or {}).values():
        especs.extend(grupo)
    # Ronda 4: [dependency-groups] (PEP 735; las entradas {include-group = …} remiten a otro grupo ya leído).
    for grupo in (datos.get("dependency-groups") or {}).values():
        especs.extend(x for x in (grupo if isinstance(grupo, list) else []) if isinstance(x, str))
    tool_poetry = (datos.get("tool") or {}).get("poetry") or {}
    poetry = dict(tool_poetry.get("dependencies") or {})
    # Ronda 4: grupos de Poetry ([tool.poetry.group.<g>.dependencies]) y [tool.poetry.dev-dependencies] (Poetry < 1.2).
    for grupo in (tool_poetry.get("group") or {}).values():
        if isinstance(grupo, dict):
            poetry.update(grupo.get("dependencies") or {})
    poetry.update(tool_poetry.get("dev-dependencies") or {})
    deps = []
    for espec in especs:
        m = RE_REQ.match(str(espec))
        if m:
            nombre = m.group(1)
            deps.append(("pypi", _normalizar_pypi(nombre), comun.rel(proyecto, archivo),
                         comun.linea_de(texto, nombre), str(espec)))
    for nombre, v in poetry.items():
        if nombre.lower() == "python" or isinstance(v, dict) and ("path" in v or "git" in v or "url" in v):
            continue
        deps.append(("pypi", _normalizar_pypi(nombre), comun.rel(proyecto, archivo),
                     comun.linea_de(texto, re.compile(rf"^\s*{re.escape(nombre)}\s*=", re.M)), f"{nombre} = {v}"))
    return deps


def _deps_pipfile(proyecto, archivo):
    texto = comun.leer(archivo) or ""
    try:
        datos = tomllib.loads(texto)
    except tomllib.TOMLDecodeError:
        return []
    deps = []
    for seccion in ("packages", "dev-packages"):
        for nombre, v in (datos.get(seccion) or {}).items():
            if isinstance(v, dict) and ("path" in v or "git" in v or "file" in v or "editable" in v):
                continue
            deps.append(("pypi", _normalizar_pypi(nombre), comun.rel(proyecto, archivo),
                         comun.linea_de(texto, re.compile(rf"^\s*['\"]?{re.escape(nombre)}['\"]?\s*=", re.M)),
                         f"{nombre} = {v}"))
    return deps


def dependencias(proyecto):
    proyecto = Path(proyecto)
    deps = []
    leidos = set()

    def requirements(p):
        p = Path(p).resolve()
        if p in leidos:
            return []
        leidos.add(p)
        salida = _deps_requirements(proyecto, p)
        for incluido in includes_requirements(proyecto, p)[0]:
            salida += requirements(incluido)  # ronda 4: se siguen los -r (deps/base.txt no se llama requirements*)
        return salida

    for p in comun.recorrer(proyecto):
        if p.name == "package.json":
            deps += _deps_npm(proyecto, p)
        elif re.fullmatch(r"requirements[\w.-]*\.(txt|in)", p.name):
            deps += requirements(p)
        elif p.name == "pyproject.toml":
            deps += _deps_pyproject(proyecto, p)
        elif p.name == "Pipfile":
            deps += _deps_pipfile(proyecto, p)
    return deps


def _contar_toml(texto, secciones):
    try:
        datos = tomllib.loads(texto)
    except tomllib.TOMLDecodeError:
        return 1 if texto.strip() else 0  # no se puede leer: no se asume que esté vacío
    n = 0
    for s in secciones:
        nodo = datos
        for parte in s.split("."):
            nodo = nodo.get(parte) if isinstance(nodo, dict) else None
        if isinstance(nodo, dict):
            n += len(nodo)
    for clave in ("target",):  # [target.'cfg(...)'.dependencies]
        for objetivo in ((datos.get(clave) or {}).values() if isinstance(datos.get(clave), dict) else []):
            if isinstance(objetivo, dict):
                n += sum(len(objetivo.get(s) or {}) for s in ("dependencies", "dev-dependencies"))
    return n


def _contar_composer(texto):
    try:
        datos = json.loads(texto)
    except json.JSONDecodeError:
        return 1 if texto.strip() else 0
    return sum(1 for s in ("require", "require-dev") for k in ((datos.get(s) or {}) if isinstance(datos, dict) else {})
               if k != "php" and not k.startswith(("ext-", "lib-")))


def _contar_go_mod(texto):
    n, en_bloque = 0, False
    for linea in texto.splitlines():
        l = linea.split("//", 1)[0].strip()
        if en_bloque:
            if l == ")":
                en_bloque = False
            elif l:
                n += 1
        elif re.match(r"^require\s*\($", l):
            en_bloque = True
        elif re.match(r"^require\s+\S+", l):
            n += 1
    return n


def _contar_pubspec(texto):
    n, dentro = 0, False
    for linea in texto.splitlines():
        if re.match(r"^(dependencies|dev_dependencies)\s*:", linea):
            dentro = True
        elif linea and not linea[0].isspace():
            dentro = False
        elif dentro and re.match(r"^[ \t]{2}[\w-]+\s*:", linea):
            n += 1
    return n


def _contar_setup_py(texto):
    n = 0
    for m in re.finditer(r"\b(install_requires|tests_require|setup_requires|extras_require)\s*=\s*", texto):
        resto = texto[m.end():]
        lista = re.match(r"[\[\{]([^\]\}]*)[\]\}]", resto)
        if lista is None:
            n += 1  # variable o expresión: no se puede saber qué declara (fail-closed)
        else:
            n += len(re.findall(r"['\"][^'\"]+['\"]", lista.group(1)))
    return n


def _contar_setup_cfg(texto):
    """Entradas de install_requires/tests_require/setup_requires (en línea o multilínea) y de [options.extras_require]."""
    n, lista, extras = 0, False, False
    for linea in texto.splitlines():
        l = linea.strip()
        if not l or l.startswith(("#", ";")):
            continue
        if linea.startswith("["):
            extras, lista = linea.startswith("[options.extras_require]"), False
            continue
        if extras:
            n += 1
            continue
        m = re.match(r"^(install_requires|tests_require|setup_requires)\s*=\s*(.*)$", l) if not linea[:1].isspace() else None
        if m:
            n += len([x for x in re.split(r"[;,]", m.group(2)) if x.strip()])
            lista = True
        elif linea[:1].isspace() and lista:
            n += 1
        else:
            lista = False
    return n


def _contar_conda(texto):
    return sum(1 for m in re.finditer(r"^\s*-\s*([A-Za-z0-9][\w.-]*)", texto, re.M)
               if m.group(1).lower() not in ("python", "pip"))


# Manifiestos de ecosistemas sin verificador de registro: (nombre o regex del archivo, función que cuenta sus deps).
NO_CUBIERTOS = (
    ("go.mod", _contar_go_mod),
    ("Cargo.toml", lambda t: _contar_toml(t, ("dependencies", "dev-dependencies", "build-dependencies",
                                              "workspace.dependencies"))),
    ("Gemfile", lambda t: len(re.findall(r"^\s*gem\s+['\"]", t, re.M))),
    ("composer.json", _contar_composer),
    ("pubspec.yaml", lambda t: _contar_pubspec(t)),
    ("pom.xml", lambda t: len(re.findall(r"<dependency>", t))),
    (re.compile(r"build\.gradle(\.kts)?"), lambda t: len(re.findall(
        r"^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|kapt|ksp)\b", t, re.M))),
    (re.compile(r".+\.(csproj|fsproj|vbproj)"), lambda t: len(re.findall(r"<PackageReference\b", t))),
    ("mix.exs", lambda t: len(re.findall(r"\{\s*:\w+\s*,", t))),
    ("Package.swift", lambda t: len(re.findall(r"\.package\s*\(", t))),
    # Ronda 4 (SEG-DEPS-EXISTEN): manifiestos Python que no se leen (setup.py se EJECUTA para resolverlo: no se hace).
    ("setup.py", lambda t: _contar_setup_py(t)),
    ("setup.cfg", lambda t: _contar_setup_cfg(t)),
    (re.compile(r"environment\.ya?ml|conda\.ya?ml"), lambda t: _contar_conda(t)),
)


def manifiestos_no_cubiertos(proyecto):
    """[(archivo relativo, nº de dependencias)] de manifiestos de ecosistemas sin verificador, con ≥ 1 dependencia."""
    proyecto = Path(proyecto)
    salida = []
    for p in comun.recorrer(proyecto):
        if re.fullmatch(r"requirements[\w.-]*\.(txt|in)", p.name):
            # Ronda 4: un -r que no se puede seguir (fuera del proyecto, inexistente, URL) deja dependencias sin revisar.
            salida.extend((malo, 1) for malo in includes_requirements(proyecto, p)[1])
        for patron, contar in NO_CUBIERTOS:
            if (p.name == patron) if isinstance(patron, str) else bool(patron.fullmatch(p.name)):
                n = contar(comun.leer(p) or "")
                if n:
                    salida.append((comun.rel(proyecto, p), int(n)))
                break
    return salida


# --------------------------------------------------------------------------- análisis

def _cargar_cache(ruta):
    if not ruta:
        return {}
    try:
        return json.loads(Path(ruta).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _fecha(iso):
    try:
        return dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).date()
    except ValueError:
        return None


def analizar(proyecto, consulta=consultar_registro, cache=None, hoy=None, timeout=None):
    proyecto = Path(proyecto)
    timeout = timeout or float(os.environ.get("AUDITOR_REGISTRO_TIMEOUT", "5"))
    hoy = dt.date.fromisoformat(hoy) if isinstance(hoy, str) else (hoy or dt.date.today())
    deps = dependencias(proyecto)
    no_cubiertos = manifiestos_no_cubiertos(proyecto)
    txt_no_cubiertos = ", ".join(f"{a} ({n})" for a, n in no_cubiertos[:8]) + (" …" if len(no_cubiertos) > 8 else "")
    if not deps:
        if no_cubiertos:
            res = comun.resultado(motivo=(
                "solo hay manifiestos de ecosistemas sin verificador de registro: "
                f"{txt_no_cubiertos}; sus dependencias no se revisaron (fail-closed: sin pase)"))
            res["no_cubiertos"] = [{"archivo": a, "dependencias": n} for a, n in no_cubiertos]
            return res
        return comun.resultado(motivo="sin manifiestos de dependencias (package.json, requirements, pyproject, "
                                      "Pipfile)")

    memo = _cargar_cache(cache)
    hallazgos, sin_verificar, error_red = [], 0, None
    for eco, nombre, archivo, linea, evid in deps:
        clave = f"{eco}:{nombre}"
        info = memo.get(clave)
        if info is None:
            if error_red:
                sin_verificar += 1
                continue
            try:
                info = consulta(eco, nombre, timeout)
            except ErrorRed as e:
                error_red = str(e)
                sin_verificar += 1
                continue
            memo[clave] = info
        registro = "npm" if eco == "npm" else "PyPI"
        if not info.get("existe"):
            hallazgos.append(comun.hallazgo(
                NOMBRE, "inexistente", archivo, linea,
                f"'{nombre}' no existe en {registro}. Puede ser un nombre inventado por la IA: cualquiera "
                f"podría registrarlo con código malicioso. Quitarlo o reemplazarlo por el paquete real.",
                evid, "critica"))
            continue
        creado = _fecha(info.get("creado")) if info.get("creado") else None
        if creado and (hoy - creado).days < DIAS_RECIENTE:
            hallazgos.append(comun.hallazgo(
                NOMBRE, "reciente", archivo, linea,
                f"'{nombre}' se publicó en {registro} hace {(hoy - creado).days} días ({creado.isoformat()}). "
                f"Revisar a mano el autor y el código antes de usarlo.",
                evid, "alta"))

    if cache:
        comun.escribir_json(cache, memo)

    if sin_verificar:
        return comun.resultado(hallazgos, [], estado="no_evaluado",
                               motivo=(error_red if error_red.startswith(("sin red (AUDITOR_SIN_RED",
                                                                    "registro no consultado (AUDITOR_REGISTRO_SIN_RED"))
                                       else f"sin red o registro inaccesible ({error_red})")
                               + f"; {sin_verificar} de {len(deps)} dependencias sin verificar")
    if no_cubiertos:
        res = comun.resultado(hallazgos, [], motivo=(
            f"{len(deps)} dependencias verificadas, pero hay manifiestos de ecosistemas sin verificador de registro: "
            f"{txt_no_cubiertos}; sin revisar esas dependencias no se puede afirmar que todas existan (sin pase)"))
        res["no_cubiertos"] = [{"archivo": a, "dependencias": n} for a, n in no_cubiertos]
        return res
    pases = []
    reglas = {h["regla"] for h in hallazgos}
    for sub, txt in (("inexistente", f"Todas las dependencias existen en su registro ({len(deps)} verificadas)."),
                     ("reciente", f"Ninguna dependencia publicada hace menos de {DIAS_RECIENTE} días.")):
        if f"check:{NOMBRE}.{sub}" not in reglas:
            pases.append(comun.pase(NOMBRE, sub, txt))
    return comun.resultado(hallazgos, pases)


def _argumentos(proyecto, crudo):
    cache = os.environ.get("AUDITOR_CACHE_REGISTRO") or str(Path(crudo).parent / "cache" / "registro_deps.json")
    return {"cache": cache}


if __name__ == "__main__":
    sys.exit(comun.main_check(NOMBRE, analizar, argumentos=_argumentos))
