#!/usr/bin/env python3
"""datos_confidenciales — carpetas y archivos confidenciales del proyecto (DECISIONES.md #3, generalizada).

Patrones: config/confidencial.toml (o el archivo de AUDITOR_CONFIDENCIAL). Este módulo es la única
fuente de la regla de coincidencia; la usan los adaptadores (exclusiones de semgrep, configuración de
gitleaks) y el normalizador (descarte de hallazgos en esas rutas).

El chequeo trabaja SOLO con metadatos y NUNCA abre ni lee esos archivos:
  - recorrido con os.walk + lstat (existencia, n.º de archivos, tamaño); no sigue enlaces;
  - git ls-files -z (rutas versionadas; lee el índice, no el contenido) y
    git check-ignore --no-index --stdin -z (rutas ignoradas), ambos vía scripts/git_seguro.py.
La evidencia lleva solo ruta y conteo.

Subregla                      → control (mapea_reglas del catálogo)
  trackeado (crítica)         → DAT-PII-REPO     algún archivo confidencial está versionado en git
  sin_gitignore (alta)        → DAT-PII-INVENTARIO  existe, no está versionado, pero tampoco ignorado:
                                                    un `git add .` lo subiría
  no_trackeado (pase)         → DAT-PII-REPO     (ronda 1 de pases vacíos) solo en un repositorio git y si se
                                                  evaluó ≥ 1 objeto: candidatos confidenciales (locales o
                                                  versionados) o, sin candidatos, ≥ 1 archivo versionado
                                                  contrastado con los patrones. Sin repositorio git → estado
                                                  no_aplica (nada está versionado; el control trata del
                                                  repositorio: si se crea el repo, re-auditar). Repo sin archivos
                                                  versionados ni candidatos → no_aplica. El inventario se entrega
                                                  igual en ambos casos.
  sintetico_declarado (info)   → sin mapear al catálogo: archivos versionados en rutas que el creador
                                 declaró sintéticas ([sinteticos] de config/confidencial.toml). Nota:
                                 «declarado sintético por el creador, verificar». No genera el crítico
                                 `trackeado` ni bloqueo, salvo que el inspector DICOM lea una cabecera que
                                 NO parezca ficticia (entonces vuelve a `trackeado`, crítico).
  pii_tabular (crítica|alta)  → DAT-PII-REPO  (ronda 3, PV-R2-01) archivo de DATOS versionado y no confidencial por
                                 nombre (CSV/TSV/PSV, JSON/JSONL con registros) cuyo encabezado o contenido muestra
                                 datos personales (RUT, DNI, email, teléfono, fecha de nacimiento, dirección; o nombre
                                 + diagnóstico) o de salud. Crítica con datos de salud o identificador nacional.
                                 La evidencia lleva SOLO nombres de columna y conteos, nunca valores.
                                 Un archivo de datos binario (xlsx, sav, sqlite, parquet…) no se puede inspeccionar en
                                 estático: no hay hallazgo, pero tampoco pase no_trackeado (motivo explícito).
  pii_tabular (ronda 4, PV-R3-10/11) también en volcados .sql (filas INSERT/COPY), en .yaml/.yml/.xml/.txt y
                                 comprimidos (.zip, .gz, .bak, .dump…) con nombre o carpeta sospechosos (seed, dump,
                                 export, backup, datos, pacientes…) y en JSON truncados con raíz objeto. Lo que no se
                                 puede descartar queda «no inspeccionable» e impide el pase.
  trackeado_historial (crítica) → DAT-PII-REPO (ronda 4, PV-R3-12) rutas confidenciales que solo quedan en el historial
                                 de git; los archivos de datos de commits anteriores se inspeccionan igual (blob acotado
                                 a 256 KiB, máx. 300 versiones; si hay más o falla git rev-list, no hay pase).
                                 Ronda 6: solo BLOBS (archivos; git cat-file --batch-check) cuya ruta ya NO está en el
                                 árbol actual. rev-list --objects lista también las carpetas (árboles): una carpeta
                                 vigente como pages/api/patients no es un archivo borrado.
  pii_en_test (media)          → sin mapear al catálogo hasta que se asigne control (ronda 6): pii_tabular en un archivo de
                                 test o fixture (checks/comun.es_test_o_fixture). Nota «en carpeta de test, verificar que
                                 sea ficticio». No es crítico ni bloquea, pero impide el pase no_trackeado (motivo).
  Ronda 8 (crítica adversarial, DECISIONES.md #12 adenda 3): en listas de registros JSON/JSONL se recorren TODOS los
                                 escalares (anidados en dict/list y claves) y todas las filas leídas; teléfonos +56
                                 por valor en CSV y listas JSON/YAML; «contacto» y sinónimos son columnas de contacto;
                                 claves de un JSON de raíz objeto (correo o RUT como clave) cuentan; .json5/.jsonc/
                                 .geojson se leen (conversión relajada); .vcf/.ldif/.hl7/.eml/.mbox/.ics siempre como
                                 texto; .duckdb… binarios. Truncado (> 256 KiB), recorrido acotado o anidamiento
                                 excesivo sin PII → no inspeccionable (sin pase). Un archivo de datos cuya única PII
                                 es relleno evidente (RUT de dígito repetido, móviles de ≤ 2 dígitos distintos) sin
                                 columnas personales ni correos reales → pii_no_tabular (media), no pii_tabular.
  pii_no_tabular (media)       → DAT-PII-TEST (ronda 7): archivo versionado o del historial que NO es una lista de
                                 registros (JSON/YAML de configuración, estado o memoria de una herramienta) con
                                 valores con forma de email real (no reservado ni buzón de sistema) o teléfono +56.
                                 Evidencia: conteos por tipo, nunca valores. Un RUT válido en un JSON de raíz lista,
                                 un YAML o un texto sigue siendo pii_tabular (crítico, ronda 6); en un JSON de raíz
                                 objeto (antes omitido entero) es pii_no_tabular, con conteo aparte de RUT de relleno
                                 (dígitos repetidos). Sin bloqueo global, pero impide el pase no_trackeado. Los
                                 no inspeccionables llevan nota: truncado y correos descartados (reservados/sistema).
  Ronda 6 — carpetas AMBIGUAS (carpetas_ambiguas de config/confidencial.toml: pacientes, patients): dentro de ellas
  solo los archivos que no son código ni configuración son confidenciales (es_codigo_en_ambigua); el código
  (pages/api/patients/search.js) se escanea y no genera DAT-PII-REPO. Las carpetas inequívocas (datos-reales,
  datos_abiertos, data/raw…) siguen siendo confidenciales enteras.
  Ronda 6 — falsos positivos de pii_tabular: (a) un YAML/JSON solo es tabular si es una lista de registros (≥ 2
  mapeos con claves comunes) y sus «columnas» son las claves de esos registros (no las de una configuración); en esos
  registros «condicion»/«tratamiento» solo cuentan como salud si los nombres parecen de personas. (b) Los correos de
  dominios reservados (RFC 2606/6761: example.com/.net/.org, *.example, *.test, *.invalid, *.localhost) y los buzones
  de sistema (noreply@…) no son datos personales; una columna de correo con solo esos valores se da por ficticia.
  Que ningún NOMBRE coincida con los patrones no prueba que no haya datos personales versionados: el pase
  no_trackeado exige además que todos los archivos de datos versionados se hayan inspeccionado sin hallazgos.
Además el JSON incluye "inventario": [{ruta, tipo, archivos, bytes, en_gitignore, trackeados,
sintetico_declarado}].

AUD-SINT — inspector de cabecera DICOM (inspeccionar_cabecera_dicom): es la ÚNICA lectura de contenido de
archivos CONFIDENCIALES de este módulo y solo ocurre en archivos dentro de rutas declaradas sintéticas. (Ronda 3:
los archivos de datos versionados que NO son confidenciales por nombre se leen de forma acotada —256 KiB, 200
filas— para buscar columnas o valores personales; de ellos solo salen nombres de columna y conteos.) Lee como máximo los primeros
256 KiB, recorre los elementos hasta el grupo 0010 y considera solo PatientName (0010,0010), PatientID
(0010,0020) y PatientBirthDate (0010,0030). Devuelve un veredicto (ficticio / no_ficticio /
no_determinado / no_dicom) y los NOMBRES de los tags leídos; los valores nunca salen de la función.

Uso:
  datos_confidenciales.py PROYECTO DIR_CRUDO            chequeo (check_datos_confidenciales.json + meta)
  datos_confidenciales.py --exclusiones semgrep         un patrón --exclude de semgrep por línea
  datos_confidenciales.py --config-gitleaks BASE SALIDA configuración de gitleaks que extiende BASE y
                                                        agrega la allowlist de rutas confidenciales
  datos_confidenciales.py --patrones                    carpetas y patrones de archivo, uno por línea
  datos_confidenciales.py --filtrar-osv OSV.json PROY   quita de osv.json los resultados en rutas
                                                        confidenciales; imprime cuántos quitó

Cobertura de la exclusión (DECISIONES.md #3): semgrep (--exclude), gitleaks (allowlist de rutas en una
configuración generada por corrida, los tres modos), osv (filtro de source.path), normalizar/run.py
(descarta cualquier registro en esas rutas) y este check (solo metadatos). zizmor solo lee
.github/workflows. PENDIENTE fuera del alcance de esta tarea: checks/comun.recorrer() (usado por
env_publicas, archivos_clave, config_agentes y registro_deps) aún no salta estas rutas: debería
agregar `and not datos_confidenciales.es_confidencial(rel)`; mientras tanto el normalizador descarta sus
hallazgos en esas rutas, pero el crudo de esos checks podría traer evidencia enmascarada.
"""
import collections
import fnmatch
import os
import re
import struct
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parent.parent))
import comun  # noqa: E402
import git_seguro  # noqa: E402

NOMBRE = "datos_confidenciales"
RAIZ = Path(__file__).resolve().parent.parent.parent
RUTA_CONFIG = RAIZ / "config" / "confidencial.toml"
# Carpetas que el recorrido no visita (no son del proyecto). No incluye dist/build: si alguien deja datos
# reales ahí, también cuentan.
NO_RECORRER = frozenset({"node_modules", ".git", ".auditoria", ".venv", "venv", "__pycache__"})


# --------------------------------------------------------------------------- configuración

# Ronda 6 (verificación ciega node-next): carpetas de nombre AMBIGUO (pacientes, patients). Dentro de ellas solo los
# archivos que NO son código ni configuración son confidenciales. Listas por defecto (config/confidencial.toml
# [ambiguas] las puede reemplazar). .json/.yaml/.html/.md/.txt quedan fuera a propósito (fail-closed): dentro de una
# carpeta «pacientes» pueden ser registros o documentos; los manifiestos y lockfiles conocidos van por nombre.
EXT_CODIGO_AMBIGUA = frozenset({
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro", ".py", ".go", ".java",
    ".kt", ".kts", ".rb", ".php", ".cs", ".rs", ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".ex", ".exs",
    ".sol", ".lua", ".dart", ".sh", ".bash", ".zsh", ".ps1", ".tf", ".hcl", ".css", ".scss", ".sass", ".less",
    ".graphql", ".gql", ".prisma", ".proto", ".ejs", ".hbs", ".pug", ".njk", ".toml", ".ini", ".cfg", ".conf", ".lock",
})
NOMBRES_CODIGO_AMBIGUA = (
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", "bun.lock",
    "bun.lockb", "composer.json", "deno.json", "deno.jsonc", "tsconfig*.json", "jsconfig*.json", "project.json",
    "nx.json", "turbo.json", "angular.json", "vercel.json", ".eslintrc*", ".prettierrc*", ".babelrc*", ".npmrc",
    ".nvmrc", ".editorconfig", ".gitignore", ".gitkeep", ".gitattributes", ".dockerignore", ".env", ".env.*",
    "requirements*.txt", "Pipfile", "go.mod", "go.sum", "Gemfile", "Dockerfile*", "Makefile", "Procfile",
)
# Extensiones que los escáneres externos (semgrep --exclude, allowlist de gitleaks) excluyen dentro de una carpeta
# ambigua: datos, documentos, imágenes y comprimidos. Los globs/regex de esos escáneres no pueden expresar «todo menos
# el código», así que se enumeran; un archivo de extensión desconocida fuera de esta lista sigue siendo confidencial
# para el auditor (es_confidencial: el normalizador descarta cualquier hallazgo en él), pero el escáner lo recorre.
EXT_DATOS_AMBIGUA = (
    ".csv", ".tsv", ".psv", ".tab", ".json", ".jsonl", ".ndjson", ".geojson", ".xlsx", ".xlsm", ".xls", ".ods",
    ".numbers", ".sav", ".zsav", ".dta", ".sas7bdat", ".xpt", ".rds", ".rdata", ".rda", ".parquet", ".feather",
    ".arrow", ".avro", ".orc", ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb", ".dbf", ".h5", ".hdf5", ".mat",
    ".sql", ".yaml", ".yml", ".xml", ".txt", ".md", ".markdown", ".rst", ".html", ".htm", ".pdf", ".doc", ".docx",
    ".odt", ".rtf", ".ppt", ".pptx", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".webp",
    ".svg", ".wav", ".mp3", ".mp4", ".m4a", ".avi", ".mov", ".mkv", ".log", ".dat", ".out", ".bin", ".vcf", ".ics",
    ".eml", ".msg", ".hl7", ".dcm", ".dicom", ".nii", ".gz", ".edf", ".bdf", ".zip", ".tgz", ".bz2", ".xz", ".7z",
    ".rar", ".tar", ".zst", ".bak", ".dump", ".dmp",
)


def _lista(valor):
    return [str(x).strip() for x in (valor or []) if str(x).strip()]


def cargar(ruta=None):
    """{"carpetas", "carpetas_ambiguas", "codigo_ambiguas": {"extensiones", "nombres"}, "archivos", "sinteticos"} desde
    config/confidencial.toml (o AUDITOR_CONFIDENCIAL). Retrocompatible: sin `carpetas_ambiguas` la lista queda vacía y
    todas las `carpetas` son inequívocas (todo su contenido confidencial, como antes de la ronda 6)."""
    ruta = Path(ruta or os.environ.get("AUDITOR_CONFIDENCIAL") or RUTA_CONFIG)
    with open(ruta, "rb") as f:
        datos = tomllib.load(f)
    carpetas = [str(c).strip().strip("/") for c in datos.get("carpetas", []) if str(c).strip().strip("/")]
    inequivocas = {"/".join(_segmentos(c)).casefold() for c in carpetas}
    # Fail-closed: si un nombre está en las dos listas, gana la inequívoca (todo confidencial).
    ambiguas = [str(c).strip().strip("/") for c in datos.get("carpetas_ambiguas", []) if str(c).strip().strip("/")
                and "/".join(_segmentos(c)).casefold() not in inequivocas]
    amb = datos.get("ambiguas") or {}
    ext = {e.lower() if e.startswith(".") else "." + e.lower() for e in _lista(amb.get("extensiones_codigo"))} \
        if "extensiones_codigo" in amb else set(EXT_CODIGO_AMBIGUA)
    nombres = _lista(amb.get("nombres_codigo")) if "nombres_codigo" in amb else list(NOMBRES_CODIGO_AMBIGUA)
    archivos = [str(a).strip() for a in datos.get("archivos", []) if str(a).strip()]
    sint = datos.get("sinteticos") or {}
    sinteticos = [str(r).strip().strip("/") for r in (sint.get("rutas") or []) if str(r).strip().strip("/")]
    return {"carpetas": carpetas, "carpetas_ambiguas": ambiguas,
            "codigo_ambiguas": {"extensiones": sorted(ext), "nombres": nombres},
            "archivos": archivos, "sinteticos": sinteticos}


def es_sintetico_declarado(ruta, conf=None):
    """AUD-SINT: la ruta (relativa a la raíz del proyecto) es o está dentro de una ruta de [sinteticos].
    Las rutas se anclan a la raíz del proyecto (no se buscan en cualquier profundidad)."""
    conf = conf or cargar()
    segs = [s.casefold() for s in _segmentos(ruta)]
    for r in conf.get("sinteticos") or []:
        obj = [s.casefold() for s in _segmentos(r)]
        if obj and segs[:len(obj)] == obj:
            return True
    return False


# --------------------------------------------------------------------------- inspector DICOM (AUD-SINT)

TAGS_PACIENTE = {(0x0010, 0x0010): "PatientName", (0x0010, 0x0020): "PatientID",
                 (0x0010, 0x0030): "PatientBirthDate"}
_MAX_CABECERA = 256 * 1024
_VR_LARGOS = {b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"SQ", b"SV", b"UC", b"UN", b"UR", b"UT", b"UV"}
_IMPLICITA_LE = "1.2.840.10008.1.2"
_TOKEN_FICTICIO = re.compile(r"^(FICTICI\w*|ANON\w*|TEST\d*|SINTETIC\w*|SYNTHETIC\w*|PHANTOM\w*|FANTOMA\w*"
                             r"|DUMMY\w*|PRUEBA\d*)$")
_RUT_FICTICIO = re.compile(r"^1{1,2}\.?1{3}\.?1{3}-?1$")


def _valor_ficticio(crudo):
    texto = crudo.decode("latin-1", "replace").strip(" \0").upper()
    if not texto:
        return True
    if _RUT_FICTICIO.match(texto):
        return True
    tokens = [t for t in re.split(r"[^0-9A-Z]+", texto) if t]
    return bool(tokens) and any(_TOKEN_FICTICIO.match(t) for t in tokens) and all(
        _TOKEN_FICTICIO.match(t) or t.isdigit() or t in ("PACIENTE", "PATIENT", "NOMBRE", "APELLIDO")
        for t in tokens)


def _elementos(buf, pos, implicita, hasta_grupo):
    """Generador (grupo, elemento, valor_bytes) en little endian; se detiene al pasar `hasta_grupo` o ante
    una longitud indefinida (secuencias): la inspección es solo de cabecera."""
    n = len(buf)
    while pos + 8 <= n:
        grupo, elem = struct.unpack_from("<HH", buf, pos)
        if grupo > hasta_grupo:
            return
        if implicita and grupo != 0x0002:
            largo = struct.unpack_from("<I", buf, pos + 4)[0]
            pos += 8
        else:
            vr = buf[pos + 4:pos + 6]
            if vr in _VR_LARGOS:
                if pos + 12 > n:
                    return
                largo = struct.unpack_from("<I", buf, pos + 8)[0]
                pos += 12
            else:
                largo = struct.unpack_from("<H", buf, pos + 6)[0]
                pos += 8
        if largo == 0xFFFFFFFF:
            raise ValueError("longitud indefinida antes de los datos del paciente")
        if pos + largo > n:
            raise ValueError("cabecera truncada")
        yield grupo, elem, buf[pos:pos + largo]
        pos += largo


def inspeccionar_cabecera_dicom(ruta):
    """AUD-SINT. {"veredicto", "tags_leidos"}: ficticio si los tags de paciente presentes están vacíos o
    tienen patrones ficticios (FICTICIO, ANON, TEST, SINTETICO, 11.111.111-1…). Nunca devuelve valores."""
    try:
        with open(ruta, "rb") as f:
            buf = f.read(_MAX_CABECERA)
    except OSError:
        return {"veredicto": "no_determinado", "tags_leidos": []}
    if len(buf) < 132 or buf[128:132] != b"DICM":
        return {"veredicto": "no_dicom", "tags_leidos": []}
    leidos, ficticios = [], []
    try:
        sintaxis, pos = None, 132
        for grupo, elem, valor in _elementos(buf, 132, False, 0x0002):
            pos += (12 if buf[pos + 4:pos + 6] in _VR_LARGOS else 8) + len(valor)
            if (grupo, elem) == (0x0002, 0x0010):
                sintaxis = valor.decode("ascii", "replace").strip(" \0")
        if sintaxis is None or sintaxis.endswith(".1.2.2") or sintaxis.endswith(".1.2.1.99"):
            return {"veredicto": "no_determinado", "tags_leidos": []}  # big endian o deflate: no se inspecciona
        for grupo, elem, valor in _elementos(buf, pos, sintaxis == _IMPLICITA_LE, 0x0010):
            nombre = TAGS_PACIENTE.get((grupo, elem))
            if nombre:
                leidos.append(nombre)
                ficticios.append(_valor_ficticio(valor))
                valor = None
    except (ValueError, struct.error):
        return {"veredicto": "no_determinado", "tags_leidos": sorted(set(leidos))}
    return {"veredicto": "ficticio" if all(ficticios) else "no_ficticio", "tags_leidos": sorted(set(leidos))}


def _segmentos(ruta):
    return [s for s in str(ruta).replace("\\", "/").split("/") if s not in ("", ".")]


def _carpeta_en(segs, carpeta):
    """Índice final (exclusivo) de la primera aparición de `carpeta` (1 o más segmentos) en segs, o None."""
    objetivo = [s.casefold() for s in _segmentos(carpeta)]
    bajos = [s.casefold() for s in segs]
    k = len(objetivo)
    for i in range(len(bajos) - k + 1):
        if bajos[i:i + k] == objetivo:
            return i + k
    return None


def _archivo_coincide(nombre, conf):
    bajo = nombre.casefold()
    for patron in conf["archivos"]:
        if fnmatch.fnmatchcase(bajo, patron.casefold()):
            return patron
    return None


def es_codigo_en_ambigua(nombre, conf=None):
    """True si un archivo con este NOMBRE, dentro de una carpeta ambigua (pacientes, patients), es código o
    configuración (se analiza normalmente). Sin extensión no se distingue de una subcarpeta: True (no confidencial)."""
    conf = conf or cargar()
    cod = conf.get("codigo_ambiguas") or {"extensiones": sorted(EXT_CODIGO_AMBIGUA), "nombres": NOMBRES_CODIGO_AMBIGUA}
    bajo = nombre.casefold()
    if any(fnmatch.fnmatchcase(bajo, n.casefold()) for n in cod["nombres"]):
        return True
    ext = Path(bajo).suffix
    if not ext:
        return True
    return ext in set(cod["extensiones"])


def _fin_carpetas(segs, carpetas, dentro=False):
    mejor = None
    for carpeta in carpetas:
        fin = _carpeta_en(segs, carpeta)
        if fin is not None and (not dentro or fin < len(segs)) and (mejor is None or fin < mejor):
            mejor = fin
    return mejor


def raiz_confidencial(ruta, conf=None):
    """Ruta de la carpeta confidencial que contiene a `ruta` (o la ruta del archivo si coincide por
    nombre); None si no es confidencial.
    Ronda 6: en una carpeta AMBIGUA (carpetas_ambiguas: pacientes, patients) solo cuentan los archivos que no son
    código ni configuración (es_codigo_en_ambigua); la carpeta misma no es confidencial (los recorridos la visitan y
    deciden archivo por archivo). Las carpetas inequívocas (datos-reales…) ganan siempre."""
    conf = conf or cargar()
    segs = _segmentos(ruta)
    if not segs:
        return None
    mejor = _fin_carpetas(segs, conf["carpetas"])
    if mejor is not None:
        return "/".join(segs[:mejor])
    amb = _fin_carpetas(segs, conf.get("carpetas_ambiguas") or [], dentro=True)
    if amb is not None and not es_codigo_en_ambigua(segs[-1], conf):
        return "/".join(segs[:amb])
    if _archivo_coincide(segs[-1], conf):
        return "/".join(segs)
    return None


def es_confidencial(ruta, conf=None):
    return raiz_confidencial(ruta, conf) is not None


def exclusiones_semgrep(conf=None):
    """Patrones para `semgrep --exclude`. Un nombre suelto excluye esa carpeta en cualquier nivel; una
    ruta con "/" solo se ancla a la raíz, por eso se agrega también "**/<ruta>"."""
    conf = conf or cargar()
    salida = []
    for c in conf["carpetas"]:
        variantes = [c, c.lower(), c.upper()]
        for v in variantes:
            salida += [v] if "/" not in v else [v, f"**/{v}"]
    # Ronda 6: en las carpetas ambiguas solo se excluyen los archivos de datos (EXT_DATOS_AMBIGUA); el código se escanea.
    for c in conf.get("carpetas_ambiguas") or []:
        for v in dict.fromkeys([c, c.lower(), c.upper()]):
            for ext in EXT_DATOS_AMBIGUA:
                for e in dict.fromkeys([ext, ext.upper()]):
                    salida.append(f"**/{v}/**/*{e}")
    for a in conf["archivos"]:
        salida += [a, a.lower(), a.upper()]
    vistos = []
    for s in salida:
        if s not in vistos:
            vistos.append(s)
    return vistos


def _glob_a_regex(patron):
    cuerpo = ""
    for ch in patron:
        cuerpo += "[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch)
    return cuerpo


def regex_gitleaks(conf=None):
    """Expresiones (sintaxis Go RE2) para [[allowlists]].paths de gitleaks, sin distinguir mayúsculas."""
    conf = conf or cargar()
    rx = [f"(?i)(^|/){'/'.join(re.escape(s) for s in _segmentos(c))}(/|$)" for c in conf["carpetas"]]
    # Ronda 6: carpetas ambiguas → solo archivos de datos (RE2 no permite «todo menos el código»: se enumeran).
    exts = "|".join(re.escape(e.lstrip(".")) for e in EXT_DATOS_AMBIGUA)
    rx += [f"(?i)(^|/){'/'.join(re.escape(s) for s in _segmentos(c))}/(.*/)?[^/]*\\.({exts})$"
           for c in conf.get("carpetas_ambiguas") or []]
    rx += [f"(?i)(^|/){_glob_a_regex(a)}$" for a in conf["archivos"]]
    return rx


def _toml_literal(texto):
    if "'''" in texto:
        raise ValueError(f"patrón no representable en TOML literal: {texto!r}")
    return f"'''{texto}'''"


def config_gitleaks(base, conf=None):
    """Texto TOML de una configuración de gitleaks que extiende `base` (que a su vez extiende la de
    fábrica) y agrega una allowlist con las rutas confidenciales. gitleaks fusiona las allowlists de la
    configuración extendida: las de `base` siguen vigentes."""
    base = str(Path(base).resolve())
    if '"' in base or "\\" in base:
        raise ValueError("ruta de configuración base no representable")
    paths = ",\n  ".join(_toml_literal(r) for r in regex_gitleaks(conf))
    return ("# Generado por scripts/checks/datos_confidenciales.py (config/confidencial.toml). No editar.\n"
            "title = \"auditor-integral (con exclusión de rutas confidenciales)\"\n\n"
            f"[extend]\npath = \"{base}\"\n\n"
            "[[allowlists]]\n"
            "description = \"Rutas confidenciales (DECISIONES.md #3): su contenido no se analiza\"\n"
            f"paths = [\n  {paths},\n]\n")


# --------------------------------------------------------------------------- metadatos

def _inventario(proyecto, conf):
    """{raiz: {"tipo", "archivos": [rel...], "bytes"}} solo con os.walk + lstat (sin abrir archivos)."""
    raices = {}
    for raiz, dirs, archivos in os.walk(proyecto):
        rel_raiz = Path(raiz).relative_to(proyecto).as_posix()
        rel_raiz = "" if rel_raiz == "." else rel_raiz
        quedan = []
        for d in sorted(dirs):
            ruta_d = os.path.join(raiz, d)
            if d in NO_RECORRER or os.path.islink(ruta_d):
                continue
            rel_d = f"{rel_raiz}/{d}" if rel_raiz else d
            r = raiz_confidencial(rel_d, conf)
            if r is not None and r == rel_d:  # la carpeta misma es confidencial: se cuenta entera
                raices[rel_d] = _contar(proyecto, rel_d)
            else:
                quedan.append(d)
        dirs[:] = quedan
        for a in sorted(archivos):
            rel_a = f"{rel_raiz}/{a}" if rel_raiz else a
            p = os.path.join(raiz, a)
            if os.path.islink(p):
                continue
            r = raiz_confidencial(rel_a, conf)
            if r is None:
                continue
            try:
                tam = os.lstat(p).st_size
            except OSError:
                tam = 0
            if r == rel_a:
                raices[rel_a] = {"tipo": "archivo", "archivos": [rel_a], "bytes": tam}
            else:
                # Ronda 6: archivo de datos dentro de una carpeta ambigua (pacientes/, patients/): se agrupa en esa
                # carpeta, que cuenta solo sus archivos de datos (el código de la carpeta no es confidencial).
                info = raices.setdefault(r, {"tipo": "carpeta", "archivos": [], "bytes": 0})
                info["archivos"].append(rel_a)
                info["bytes"] += tam
    return raices


def _contar(proyecto, rel):
    lista, total = [], 0
    for raiz, dirs, archivos in os.walk(Path(proyecto) / rel):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(raiz, d)))
        for a in sorted(archivos):
            p = os.path.join(raiz, a)
            if os.path.islink(p):
                continue
            lista.append(Path(p).relative_to(proyecto).as_posix())
            try:
                total += os.lstat(p).st_size
            except OSError:
                pass
    return {"tipo": "carpeta", "archivos": lista, "bytes": total}


def _git_lista(proyecto, *args, entrada=None):
    """Lista de rutas separadas por NUL; None si git no corrió; [] si no es repo o no hay resultados."""
    import subprocess
    try:
        r = subprocess.run(["git", "--no-optional-locks", *git_seguro.argumentos(), "-C", str(proyecto), *args],
                           input=entrada, capture_output=True, timeout=60, env=git_seguro.entorno())
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    salida = [x.decode("utf-8", "replace") for x in r.stdout.split(b"\0") if x]
    return r.returncode, salida


# --------------------------------------------------------------------------- datos personales en archivos de datos

EXT_TABULAR = {".csv": None, ".tsv": "\t", ".psv": "|", ".tab": "\t"}
# Ronda 8 (crítica adversarial): .json5/.jsonc (JSON con comentarios, claves sin comillas, comas finales) y .geojson
# también son JSON de datos; antes _clase() los ignoraba y se emitía el pase no_trackeado sin leerlos.
EXT_JSON_DATOS = {".json", ".jsonl", ".ndjson", ".json5", ".jsonc", ".geojson"}
EXT_JSON_RELAJADO = {".json5", ".jsonc"}
EXT_DATOS_BINARIOS = {".xlsx", ".xlsm", ".xls", ".ods", ".numbers", ".sav", ".zsav", ".dta", ".sas7bdat", ".xpt",
                      ".rds", ".rdata", ".rda", ".parquet", ".feather", ".arrow", ".avro", ".orc", ".sqlite",
                      ".sqlite3", ".db", ".mdb", ".accdb", ".dbf", ".h5", ".hdf5", ".mat",
                      # ronda 8: más bases de datos de archivo (no se abren: no inspeccionables, sin pase)
                      ".duckdb", ".db3", ".s3db", ".sl3"}
# Ronda 8: formatos de texto que son, por definición, registros de contacto o clínicos (vCard/VCF, LDIF, HL7, correos,
# calendarios). Se inspeccionan siempre (como texto, sin importar el nombre); sin PII detectable quedan no
# inspeccionables: los nombres o teléfonos no chilenos que suelen traer no se detectan por valor.
EXT_TEXTO_REGISTROS = {".vcf", ".vcard", ".ldif", ".hl7", ".eml", ".mbox", ".ics"}
_MAX_DATOS = 256 * 1024
_MAX_FILAS = 200
# Ronda 8: tope de valores y de profundidad al recorrer estructuras JSON (claves y valores anidados). Un archivo leído
# tiene ≤ 256 KiB, así que el tope de valores casi nunca se alcanza; si se alcanza (o se pasa la profundidad), el
# archivo sin PII detectada queda no inspeccionable (nunca limpio ni pase).
_MAX_ESCALARES = 200_000
_MAX_PROFUNDIDAD = 200
# Tokens de nombre de columna (normalizados: minúsculas, sin tildes, separados por «_»).
COL_ID_NACIONAL = {"rut", "dni", "cedula", "ssn", "pasaporte", "passport", "nif", "nie", "curp", "rfc", "cpf", "nss",
                   "mrn", "ficha"}
COL_CONTACTO = {"email", "correo", "mail", "telefono", "phone", "celular", "movil", "mobile", "fono", "whatsapp",
                "nacimiento", "birth", "birthdate", "birthday", "dob", "direccion", "address", "domicilio",
                # ronda 8: nombres de columna de contacto genéricos o en plural
                "contacto", "contactos", "contact", "contacts", "telefonos", "phones", "celulares", "moviles",
                "fonos", "tel", "cel"}
# Ronda 8: columnas de contacto genéricas («contacto»): como una columna de correo, si TODOS sus valores con forma de
# correo son de dominios reservados y no hay teléfonos ni RUT, se da por ficticia.
COL_CONTACTO_GENERICO = frozenset({"contacto", "contactos", "contact", "contacts"})
COL_NOMBRE = {"nombre", "nombres", "apellido", "apellidos", "name", "firstname", "lastname", "fullname", "surname",
              "paciente", "patient"}
COL_SALUD = {"diagnostico", "diagnosticos", "diagnosis", "dx", "cie10", "cie", "icd", "icd10", "patologia",
             "enfermedad", "enfermedades", "condicion", "comorbilidad", "comorbilidades", "medicamento",
             "medicamentos", "farmaco", "farmacos", "tratamiento", "alergia", "alergias", "vih", "hiv", "sida",
             "embarazo", "discapacidad", "epicrisis", "anamnesis"}
RE_RUT = re.compile(r"(?<![\d.])(\d{1,2})\.?(\d{3})\.?(\d{3})-([\dkK])(?![\w])")
# Integración ronda 8: partes acotadas (local ≤ 64, etiqueta ≤ 63; RFC 5321/1035). Sin tope, un valor largo sin «@»
# (p. ej. un campo de 140 KiB, ahora que se revisan todos los valores) costaba tiempo cuadrático (minutos por archivo).
# Un correo con parte local más larga se sigue detectando (coincide con sus últimos 64 caracteres).
RE_EMAIL = re.compile(r"([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63})")
# Ronda 6: dominios reservados para documentación y pruebas (RFC 2606 y RFC 6761): example.com/.net/.org (y sus
# subdominios) y los TLD .example, .test, .invalid y .localhost. Un correo en ellos no es un dato personal.
DOMINIOS_RESERVADOS = ("example.com", "example.net", "example.org")
TLD_RESERVADOS = frozenset({"example", "test", "invalid", "localhost"})
# Buzones de sistema (no identifican a una persona): p. ej. el «Co-Authored-By: … <noreply@…>» de los commits.
RE_BUZON_SISTEMA = re.compile(r"^(no-?reply|do-?not-?reply|mailer-daemon|postmaster)([+._-].*)?$", re.I)
COL_EMAIL = frozenset({"email", "correo", "mail", "emails", "correos", "mails"})
# Ronda 6: tokens de salud que en un YAML/JSON de configuración suelen ser otra cosa («condicion» de una regla,
# «tratamiento» de un error). En registros YAML/JSON solo cuentan si la columna de nombre parece de personas.
COL_SALUD_AMBIGUA = frozenset({"condicion", "tratamiento"})
RE_NOMBRE_PERSONA = re.compile(r"^[A-ZÁÉÍÓÚÑÜ][a-záéíóúñü'-]+(?:\s+(?:de|del|la|las|los|y|[A-ZÁÉÍÓÚÑÜ][a-záéíóúñü'-]+)){1,4}$")


def nombres_de_personas(registros):
    """True si ≥ la mitad de los valores de las columnas de nombre de unos registros parecen nombres de personas
    («Juana Pérez Soto»); para decidir si un token de salud ambiguo cuenta en registros YAML/JSON."""
    vals = [str(v).strip() for r in registros for k, v in r.items()
            if _tokens_columna(k) & COL_NOMBRE and isinstance(v, str) and str(v).strip()]
    return bool(vals) and sum(1 for v in vals if RE_NOMBRE_PERSONA.match(v.strip("\"'"))) * 2 >= len(vals)


def email_reservado(dominio):
    """True si el dominio de un correo está reservado para pruebas o documentación (RFC 2606/6761)."""
    d = str(dominio).strip().rstrip(".").lower()
    if d.rsplit(".", 1)[-1] in TLD_RESERVADOS:
        return True
    return any(d == r or d.endswith("." + r) for r in DOMINIOS_RESERVADOS)


def email_no_personal(local, dominio):
    """True si el correo no es un dato personal: dominio reservado (RFC 2606/6761) o buzón de sistema (noreply…)."""
    return email_reservado(dominio) or bool(RE_BUZON_SISTEMA.match(str(local)))


def _contar_emails(valores):
    """(valores con ≥ 1 correo real, valores con correos SOLO de dominios reservados o buzones de sistema)."""
    reales = reservados = 0
    for v in valores:
        correos = [(m.group(1), m.group(2)) for m in RE_EMAIL.finditer(v)]
        if not correos:
            continue
        if all(email_no_personal(lo, d) for lo, d in correos):
            reservados += 1
        else:
            reales += 1
    return reales, reservados


# Ronda 7 (grupo «datos»): teléfonos chilenos con prefijo internacional explícito (+56 y 9 dígitos nacionales: móvil
# 9 XXXX XXXX o fijo de 9 dígitos). Sin «+56» no se cuenta: una cadena de dígitos suelta (ID, marca de tiempo) no es
# un teléfono. Limitación declarada: otros países no se detectan por valor (sí por nombre de columna).
RE_TELEFONO = re.compile(r"(?<![\w+])\+56[\s.-]?\(?(?:9|[2-8]\d?)\)?[\s.-]?\d{3,4}[\s.-]?\d{4}(?!\d)")
# Manifiestos públicos de paquetes: el correo del autor/mantenedor es un dato publicado a propósito, no un registro.
JSON_MANIFIESTO_PUBLICO = frozenset({"package.json", "composer.json", "bower.json", "manifest.json", "app.json",
                                     "deno.json", "jsr.json", "lerna.json"})


def pii_en_valores(valores):
    """Ronda 7: conteos de valores con forma de PII en un archivo NO tabular (configuración, estado, memoria de un
    agente…), sin copiar ninguno: {rut (DV válido), rut_relleno (de ellos, con un solo dígito repetido), email (no
    reservado ni buzón de sistema), telefono (+56), email_descartado (dominio reservado RFC 2606/6761 o buzón de
    sistema)}. Cada aparición cuenta una vez."""
    c = {"rut": 0, "rut_relleno": 0, "email": 0, "telefono": 0, "email_descartado": 0}
    for v in valores:
        v = str(v)
        for m in RE_RUT.finditer(v):
            if _rut_valido(m):
                c["rut"] += 1
                # relleno evidente (11.111.111-1, 22.222.222-2…): se cuenta aparte, pero sigue visible (no se descarta)
                c["rut_relleno"] += len(set(m.group(1) + m.group(2) + m.group(3))) == 1
        for m in RE_EMAIL.finditer(v):
            c["email_descartado" if email_no_personal(m.group(1), m.group(2)) else "email"] += 1
        c["telefono"] += len(RE_TELEFONO.findall(v))
    return c


def _tokens_columna(nombre):
    import unicodedata
    base = unicodedata.normalize("NFKD", str(nombre))
    base = "".join(ch for ch in base if not unicodedata.combining(ch)).lower()
    base = re.sub(r"[^a-z0-9]+", "_", base).strip("_")
    return set(base.split("_")) | {base.replace("_", "")}


def _rut_valido(m):
    cuerpo = m.group(1) + m.group(2) + m.group(3)
    suma, factor = 0, 2
    for d in reversed(cuerpo):
        suma += int(d) * factor
        factor = 2 if factor == 7 else factor + 1
    dv = 11 - suma % 11
    esperado = "0" if dv == 11 else "K" if dv == 10 else str(dv)
    return m.group(4).upper() == esperado


def _leer_acotado(ruta):
    """(texto, truncado) de los primeros _MAX_DATOS bytes; None si no se puede leer."""
    try:
        with open(ruta, "rb") as f:
            crudo = f.read(_MAX_DATOS + 1)
    except OSError:
        return None
    truncado = len(crudo) > _MAX_DATOS
    crudo = crudo[:_MAX_DATOS]
    if b"\0" in crudo[:4096]:
        return None
    return crudo.decode("utf-8-sig", errors="replace"), truncado


def _registros_tabulares(texto, truncado, sep):
    """(columnas, [valores]) del encabezado y de todas las filas leídas (ronda 8: antes solo las primeras _MAX_FILAS;
    un valor personal en la fila 300 de un CSV de 50 KiB se perdía). La lectura ya está acotada a _MAX_DATOS."""
    import csv
    import io
    lineas = texto.splitlines()
    if truncado and lineas:
        lineas = lineas[:-1]
    if not lineas:
        return [], [], False
    if sep is None:
        cab = lineas[0]
        sep = max((",", ";", "\t", "|"), key=cab.count)
    try:
        filas = list(csv.reader(io.StringIO("\n".join(lineas)), delimiter=sep))
    except csv.Error:
        # Integración ronda 8: campo > field_size_limit (128 KiB) u otro error de csv. Se conservan las columnas del
        # encabezado (separadas a mano) y TODO el texto como valor; el llamador no puede dar el archivo por limpio
        # (sin PII → no inspeccionable): antes «nombre,diagnostico» + un campo enorme quedaba limpio y con pase.
        return [c.strip().strip('"') for c in lineas[0].split(sep)], ["\n".join(lineas)], True
    if not filas:
        return [], [], False
    return filas[0], [v for fila in filas[1:] for v in fila], False


def _columnas_comunes(registros):
    """Ronda 6: claves presentes en ≥ 2 registros (mapeos). Una lista de registros exige ≥ 2 mapeos con claves comunes;
    si no las hay, el archivo no es tabular (configuración, manifiesto, esquema)."""
    cuenta = {}
    for r in registros:
        for k in {str(k) for k in r}:
            cuenta[k] = cuenta.get(k, 0) + 1
    return sorted(k for k, n in cuenta.items() if n >= 2)


def _escalares(valor, salida, tope=_MAX_ESCALARES, prof=0, estado=None):
    """Valores escalares (texto) de una estructura JSON, acotados. Ronda 8: también las CLAVES de los objetos (un
    correo o un RUT usado como clave, p. ej. {"<correo>": {...}}, se perdía) y con tope de profundidad. Si se corta
    por tope de valores o de profundidad, estado["truncado"] = True (el llamador no puede dar el archivo por limpio)."""
    if len(salida) >= tope or prof > _MAX_PROFUNDIDAD:
        if estado is not None:
            estado["truncado"] = True
        return salida
    if isinstance(valor, dict):
        for k, v in valor.items():
            salida.append(str(k))
            _escalares(v, salida, tope, prof + 1, estado)
    elif isinstance(valor, list):
        for v in valor:
            _escalares(v, salida, tope, prof + 1, estado)
    elif isinstance(valor, (str, int)) and not isinstance(valor, bool):
        salida.append(str(valor))
    return salida


def _json_relajado(texto):
    """Ronda 8: convierte JSON5/JSONC a JSON estricto sin librerías: quita comentarios (// y /* */) fuera de cadenas,
    comas finales antes de } o ], pone comillas a las claves sin comillas y pasa las cadenas con comilla simple a
    comilla doble. No interpreta nada más (hexadecimales, +1…): si el resultado no es JSON, json.loads fallará y el
    archivo se trata como ilegible."""
    sal, i, n = [], 0, len(texto)
    coma = None  # índice en `sal` de la última coma emitida, si después solo hubo espacios o comentarios
    while i < n:
        ch = texto[i]
        if ch in "\"'":
            j, partes = i + 1, []
            while j < n and texto[j] != ch:
                if texto[j] == "\\" and j + 1 < n:
                    sig = texto[j + 1]
                    if sig == "'" and ch == "'":
                        partes.append("'")
                    elif sig == "\n":
                        pass  # continuación de línea de JSON5
                    else:
                        partes.append("\\" + sig)
                    j += 2
                    continue
                partes.append('\\"' if texto[j] == '"' and ch == "'" else texto[j])
                j += 1
            sal.append('"' + "".join(partes) + '"')
            coma, i = None, j + 1
            continue
        if texto.startswith("//", i):
            fin = texto.find("\n", i)
            i = n if fin < 0 else fin
            continue
        if texto.startswith("/*", i):
            fin = texto.find("*/", i + 2)
            i = n if fin < 0 else fin + 2
            continue
        if ch in "}]" and coma is not None:
            sal[coma] = ""
        if ch.isspace():
            sal.append(ch)
            i += 1
            continue
        if ch.isalpha() or ch in "_$":
            j = i
            while j < n and (texto[j].isalnum() or texto[j] in "_$"):
                j += 1
            k = j
            while k < n and texto[k] in " \t":
                k += 1
            palabra = texto[i:j]
            sal.append(f'"{palabra}"' if k < n and texto[k] == ":" else palabra)
            coma, i = None, j
            continue
        if ch == ",":
            coma = len(sal)
        else:
            coma = None
        sal.append(ch)
        i += 1
    return "".join(sal)


def _cargar_json(texto, relajado=False):
    """(ok, valor). json.loads tolerante a anidamiento extremo: RecursionError → (False, "profundo"), que el llamador
    no puede dar por limpio. Con relajado, si el JSON estricto falla, prueba la conversión de JSON5/JSONC (ronda 8).
    (False, None) si no se puede leer."""
    import json
    try:
        return True, json.loads(texto)
    except RecursionError:
        return False, "profundo"
    except ValueError:
        pass
    if relajado:
        try:
            return True, json.loads(_json_relajado(texto))
        except RecursionError:
            return False, "profundo"
        except ValueError:
            pass
    return False, None


def _registros_json(texto, truncado, ext):
    """(columnas, [valores], nombres_de_personas, recorte) de un JSON con lista de objetos o de un JSONL; ("config",
    [valores escalares], raíz_lista, recorte) si se pudo leer pero no es una lista de registros (configuración,
    manifiesto: ronda 6, ≥ 2 mapeos con claves comunes); None si no se pudo leer; "truncado" si está truncado y empieza
    con «[». Ronda 8: los valores son TODOS los escalares de los registros (anidados en dict/list y claves incluidos;
    antes solo los str/int de primer nivel de las columnas comunes y solo las primeras _MAX_FILAS filas); las columnas
    siguen saliendo de las claves comunes de primer nivel de los primeros _MAX_FILAS registros. `recorte` = True si el
    recorrido se cortó por tope de valores o profundidad, o si hubo líneas JSONL ilegibles (sin PII → no limpio)."""
    estado = {"truncado": False}
    registros, todos = [], []
    if ext in (".jsonl", ".ndjson"):
        lineas = [x for x in texto.splitlines() if x.strip()]
        if truncado and lineas:
            lineas = lineas[:-1]  # la última línea leída puede estar cortada
        for linea in lineas:
            ok, d = _cargar_json(linea)
            if not ok:
                estado["truncado"] = True  # línea ilegible: lo que trae no se revisó como JSON
                todos.append(linea)
                continue
            if isinstance(d, dict):
                registros.append(d)
            else:
                _escalares(d, todos, estado=estado)
        raiz = registros
    else:
        ok, d = _cargar_json(texto, relajado=not truncado)
        if not ok:
            if d == "profundo":
                return "profundo"
            return "truncado" if truncado and texto.lstrip().startswith("[") else None
        raiz = d
        if isinstance(d, dict):
            d = next((v for v in d.values() if isinstance(v, list) and len(v) >= 2
                      and all(isinstance(x, dict) for x in v[:5])), None)
        if isinstance(d, list) and d and all(isinstance(x, dict) for x in d[:5]):
            registros = [x for x in d if isinstance(x, dict)]
    columnas = _columnas_comunes(registros[:_MAX_FILAS]) if len(registros) >= 2 else []
    if not columnas:
        # Sin lista de registros: configuración, manifiesto o estado. Ronda 7: sus valores escalares se revisan siempre
        # (raíz lista u objeto): RUT válido → crítico; email/teléfono → pii_no_tabular (media). Antes de la ronda 7 una
        # raíz objeto se omitía entera y un correo real en un JSON de estado versionado se perdía.
        valores = _escalares(raiz, todos, estado=estado)
        return "config", valores, isinstance(raiz, list), estado["truncado"]
    # Ronda 8: TODO el contenido de los registros (incluidas claves y estructuras anidadas: meta.correo, contactos: [..],
    # usuario.{correo, rut}) y de la raíz que los contiene; se cuenta por valor en _clasificar_pii.
    valores = _escalares(raiz, todos, estado=estado)
    return columnas, valores, nombres_de_personas(registros[:_MAX_FILAS]), estado["truncado"]


RE_YAML_ITEM = re.compile(r"^(\s*)-\s+([A-Za-z_\u00C0-\u017F\"'][^:#]*?)\s*:(?:\s+(.*))?$")
RE_YAML_CLAVE = re.compile(r"^(\s*)([A-Za-z_\u00C0-\u017F\"'][^:#]*?)\s*:(?:\s+(.*))?$")


def _registros_yaml(texto):
    """Ronda 6: listas de mapeos de un YAML en bloque («- clave: valor» y claves hermanas con la misma sangría), sin
    librerías. Devuelve [(columnas comunes, [valores], nombres_de_personas)] de las listas con ≥ 2 mapeos y ≥ 1 clave común; el resto del
    documento (configuración, esquemas, mapeos sueltos) no es tabular. Las listas anidadas se siguen con una pila."""
    pila, listas = [], []
    for linea in texto.splitlines():
        if not linea.strip() or linea.lstrip().startswith("#"):
            continue
        sangria = len(linea) - len(linea.lstrip(" "))
        m = RE_YAML_ITEM.match(linea)
        if m:
            guion = len(m.group(1))
            while pila and pila[-1]["guion"] > guion:
                listas.append(pila.pop())
            if not pila or pila[-1]["guion"] != guion:
                pila.append({"guion": guion, "items": []})
            col = linea.index(m.group(2), guion + 1)
            pila[-1]["items"].append({"col": col, "claves": {m.group(2).strip("\"'"): (m.group(3) or "")}})
            continue
        while pila and pila[-1]["guion"] >= sangria:
            listas.append(pila.pop())
        m = RE_YAML_CLAVE.match(linea)
        if m and pila and pila[-1]["items"] and sangria == pila[-1]["items"][-1]["col"]:
            pila[-1]["items"][-1]["claves"][m.group(2).strip("\"'")] = m.group(3) or ""
    listas.extend(pila)
    salida = []
    for lista in listas:
        regs = [i["claves"] for i in lista["items"]][:_MAX_FILAS]
        if len(regs) < 2:
            continue
        cols = _columnas_comunes(regs)
        if cols:
            salida.append((cols, [str(v) for r in regs for k, v in r.items() if k in cols and v],
                           nombres_de_personas(regs)))
    return salida


def _clasificar_pii(columnas, valores, solo_valores_fuertes=False, salud_ambigua=True, telefonos=False):
    """(columnas personales detectadas, conteos de contenido {rut, email}, crítica) — nunca valores.
    Ronda 6: los correos de dominios reservados (RFC 2606/6761) no cuentan; y una columna de correo cuyos valores con
    forma de correo son TODOS de dominios reservados (≥ 1) se da por ficticia. solo_valores_fuertes: archivo que no
    es una lista de registros (YAML/JSON de configuración): sus claves no son columnas y solo un RUT válido cuenta.
    salud_ambigua=False (registros YAML/JSON cuyos nombres no parecen de personas): «condicion»/«tratamiento» no son
    columnas de salud.
    Ronda 8: telefonos=True (ramas tabulares: CSV y listas de registros JSON/YAML) cuenta también los teléfonos +56 por
    valor, como pii_en_valores (antes un «contacto: +56…» en una columna de nombre neutro no contaba); y los RUT de
    relleno (un solo dígito repetido) se cuentan aparte en conteos["rut_relleno"] (siguen contando como RUT)."""
    ruts = rellenos = 0
    for v in valores:
        for m in RE_RUT.finditer(v):
            if _rut_valido(m):
                ruts += 1
                rellenos += len(set(m.group(1) + m.group(2) + m.group(3))) == 1
    if solo_valores_fuertes:
        return ([], {"rut": ruts, "rut_relleno": rellenos, "email": 0, "telefono": 0}, True) if ruts else None
    emails, reservados = _contar_emails(valores)
    fonos = fonos_relleno = 0
    if telefonos:
        for v in valores:
            for m in RE_TELEFONO.finditer(v):
                fonos += 1
                fonos_relleno += _telefono_relleno(m.group(0))
    email_ficticio = reservados > 0 and emails == 0
    detectadas, salud, id_nac, nombre, contacto = [], False, False, False, False
    for c in columnas:
        toks = _tokens_columna(c)
        if toks & COL_ID_NACIONAL:
            detectadas.append(c)
            id_nac = True
        elif toks & COL_CONTACTO:
            if email_ficticio and toks & COL_CONTACTO <= COL_EMAIL:
                continue  # columna de correo con valores de prueba (@example.test…): no es un dato personal
            if email_ficticio and not fonos and not ruts and toks & COL_CONTACTO <= COL_EMAIL | COL_CONTACTO_GENERICO:
                continue  # ronda 8: «contacto» con solo correos de prueba, sin teléfonos ni RUT
            detectadas.append(c)
            contacto = True
        elif toks & COL_SALUD and (salud_ambigua or toks & COL_SALUD - COL_SALUD_AMBIGUA):
            detectadas.append(c)
            salud = True
        elif toks & COL_NOMBRE:
            detectadas.append(c)
            nombre = True
    personal = bool(id_nac or contacto or (nombre and salud) or ruts or emails or fonos)
    if not personal:
        return None
    # Ronda 8: «solo relleno» = la única PII es por valor y TODA es relleno evidente (RUT de un solo dígito repetido,
    # teléfonos con ≤ 2 dígitos distintos), sin columnas personales ni correos reales: ver _hallazgo_pii.
    solo_relleno = bool((ruts or fonos) and not detectadas and not emails and ruts == rellenos
                        and fonos == fonos_relleno)
    return (detectadas, {"rut": ruts, "rut_relleno": rellenos, "email": emails, "telefono": fonos,
                         "telefono_relleno": fonos_relleno, "solo_relleno": solo_relleno},
            bool(salud or id_nac or ruts))


def _telefono_relleno(texto):
    """Ronda 8: teléfono +56 de relleno evidente: sus 9 dígitos nacionales tienen ≤ 2 dígitos distintos (9 1111 1111)."""
    nacional = re.sub(r"\D", "", texto)[2:]
    return len(set(nacional)) <= 2


# Ronda 4 (PV-R3-10): volcados de texto y archivos opacos. Los .sql se inspeccionan siempre (filas de INSERT/COPY); los
# .yaml/.yml/.xml/.txt y los comprimidos solo si su nombre o su ubicación son sospechosos de ser datos (seed, dump,
# export, backup, datos, pacientes…). Si no se puede descartar que tengan datos personales, impiden el pase (fail-closed).
EXT_SQL = {".sql"}
EXT_TEXTO_SOSPECHOSO = {".yaml", ".yml", ".xml", ".txt"}
EXT_OPACOS = {".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".zst", ".bak", ".dump", ".dmp"}
EXT_OPACOS_SIEMPRE = {".bak", ".dump", ".dmp"}
TOKENS_SOSPECHOSOS = {"seed", "seeds", "dump", "dumps", "export", "exports", "exportacion", "backup", "backups",
                      "respaldo", "respaldos", "bkp", "datos", "data", "dataset", "datasets", "pacientes", "paciente",
                      "patients", "patient", "registros", "records", "fichas", "clientes", "usuarios", "users",
                      "personas", "people", "padron", "nomina", "censo", "encuesta", "encuestas"}
# JSON grandes que son manifiestos o lockfiles, no datos: si están truncados no impiden el pase.
JSON_NO_DATOS = {"package-lock.json", "npm-shrinkwrap.json", "composer.lock", "bun.lock", "deno.lock",
                 "tsconfig.json", "jsconfig.json", "angular.json", "project.json", "nx.json", "turbo.json"}
RE_INSERT = re.compile(r"\bINSERT\s+INTO\s+[\w.\"`\[\]]+\s*(\(([^)]*)\))?\s*VALUES\b|"
                       r"\bCOPY\s+[\w.\"]+\s*(\(([^)]*)\))?\s*FROM\s+stdin\b", re.I)
RE_CLAVE_YAML = re.compile(r"^\s*(?:-\s+)?([A-Za-z_\u00C0-\u017F][\w\u00C0-\u017F-]*)\s*:", re.M)
RE_ETIQUETA_XML = re.compile(r"<([A-Za-z_][\w.-]*)(?:\s[^>]*)?>[^<]+</\1>")
RE_CLAVE_JSON = re.compile(r'"([^"\\]{1,60})"\s*:')
MAX_BLOBS_HISTORIAL = 300


def sospechoso(rel):
    """True si el nombre o alguna carpeta de la ruta sugiere datos (seed, dump, export, backup, datos, pacientes…)."""
    toks = set()
    for parte in rel.lower().split("/"):
        toks |= set(re.split(r"[^a-z0-9\u00e0-\u017f]+", parte))
    return bool(toks & TOKENS_SOSPECHOSOS)


def _clase(rel):
    """Tipo de archivo de datos a inspeccionar (tabular, json, binario, sql, texto, opaco) o None si no es de datos."""
    bajo = rel.lower()
    ext = Path(bajo).suffix
    if bajo.endswith(".nii.gz"):
        return None
    if ext in EXT_TABULAR:
        return "tabular"
    if ext in EXT_JSON_DATOS:
        return "json"
    if ext in EXT_DATOS_BINARIOS:
        return "binario"
    if ext in EXT_SQL:
        return "sql"
    if ext in EXT_TEXTO_REGISTROS or (ext in EXT_TEXTO_SOSPECHOSO and sospechoso(rel)):
        return "texto"
    if ext in EXT_OPACOS and (ext in EXT_OPACOS_SIEMPRE or sospechoso(rel)):
        return "opaco"
    return None


def _registros_sql(texto):
    """(columnas, [valores], hay_filas) de los INSERT … VALUES / COPY … FROM stdin. Un CREATE TABLE no es un dato."""
    columnas, hay = [], False
    for m in RE_INSERT.finditer(texto):
        hay = True
        lista = m.group(2) or m.group(4)
        if lista:
            columnas.extend(c.strip().strip('"`[]') for c in lista.split(",") if c.strip())
    if not hay:
        return [], [], False
    inicio = min(m.end() for m in RE_INSERT.finditer(texto))
    return sorted(set(columnas)), [texto[inicio:]], True


def _clasificar_texto(clase, rel, texto, truncado):
    """('pii', detalle) | ('limpio',) | ('no_insp',) | ('omitir',) para un archivo de clase sql/texto o un JSON truncado."""
    if clase == "sql":
        columnas, valores, filas = _registros_sql(texto)
        if not filas:
            if sospechoso(rel):
                pii = _clasificar_pii([], [texto])
                return ("pii", pii) if pii else ("limpio",)
            return ("omitir",)  # esquema o migración sin datos
        pii = _clasificar_pii(columnas, valores)
        if pii:
            return ("pii", pii)
        return ("limpio",) if columnas else ("no_insp",)
    ext = Path(rel).suffix.lower()
    if ext in (".yaml", ".yml"):
        # Ronda 6: un YAML solo es tabular si tiene listas de registros (≥ 2 mapeos con claves comunes); sus columnas
        # son las claves de esos registros (no las claves de configuración: p. ej. «nombre», «condicion» de una
        # política). Sin registros, solo un RUT válido en los valores cuenta; si hay estructura clave: valor y no está
        # truncado, queda inspeccionado (limpio).
        tablas = _registros_yaml(texto)
        if tablas:
            for cols, vals, personas in tablas:
                pii = _clasificar_pii(cols, vals, salud_ambigua=personas, telefonos=True)
                if pii:
                    return ("pii", pii)
        pii = _clasificar_pii([], [texto], solo_valores_fuertes=True)
        if pii:
            return ("pii", pii)
        nt = _no_tabular(rel, [texto])  # ronda 7: email/teléfono reales en un YAML no tabular → media
        if nt:
            return nt
        estructura = bool(tablas) or bool(RE_CLAVE_YAML.search(texto))
        return ("limpio",) if estructura and not truncado else ("no_insp", _nota_descartados([texto], truncado))
    if ext == ".xml":
        claves = RE_ETIQUETA_XML.findall(texto)
        estructura = len(claves) >= 2
    elif ext in EXT_JSON_DATOS:
        # JSON truncado: las «columnas» son las claves que se repiten (≥ 2 veces), como en una lista de registros.
        claves = [k for k, n in collections.Counter(RE_CLAVE_JSON.findall(texto)).items() if n >= 2]
        estructura = False
    else:
        claves, estructura = [], False
    pii = _clasificar_pii(sorted(set(claves)), [texto])
    if pii:
        return ("pii", pii)
    nt = _no_tabular(rel, [texto])  # ronda 7: p. ej. teléfonos +56 en un JSON truncado sin columnas personales
    if nt:
        return nt
    return ("limpio",) if estructura and not truncado else ("no_insp", _nota_descartados([texto], truncado))


def _no_tabular(rel, valores, con_rut=False):
    """Ronda 7: ('pii_nt', conteos) si los valores de un archivo NO tabular tienen emails reales o teléfonos +56 (y,
    con con_rut, RUT con DV válido: JSON de raíz objeto, que antes se omitía); None si no. Los manifiestos públicos de
    paquetes (package.json…) no cuentan por correo (autor publicado a propósito)."""
    c = pii_en_valores(valores)
    if not con_rut:
        c["rut"] = c["rut_relleno"] = 0
    if Path(rel).name.lower() in JSON_MANIFIESTO_PUBLICO:
        c["email_descartado"] += c["email"]
        c["email"] = 0
    return ("pii_nt", c) if c["email"] or c["telefono"] or c["rut"] else None


def _nota_descartados(valores, truncado):
    """Ronda 7: nota visible para un archivo no inspeccionable: por qué no se cerró (truncado) y cuántos correos se
    descartaron por ser de dominio reservado o buzón de sistema (sin copiar ninguno)."""
    partes = [f"truncado: solo se leyeron {_MAX_DATOS // 1024} KiB"] if truncado else []
    n = pii_en_valores(valores)["email_descartado"]
    if n:
        partes.append(f"{n} valor(es) con forma de email descartado(s) por dominio reservado o buzón de sistema")
    return "; ".join(partes)


def inspeccionar_archivo(rel, leer, conf):
    """Inspección acotada de un archivo de datos (del árbol o de un blob del historial). leer() → (texto, truncado) o
    None. Devuelve ('pii', (detectadas, conteos, critica)) | ('pii_nt', conteos) (ronda 7: archivo no tabular con
    emails reales o teléfonos) | ('limpio',) | ('no_insp'[, nota]) | ('omitir',) | ('sintetico',)."""
    clase = _clase(rel)
    if clase is None:
        return ("omitir",)
    if es_sintetico_declarado(rel, conf):
        return ("sintetico",)
    if clase in ("binario", "opaco"):
        return ("no_insp",)
    leido = leer()
    if leido is None:
        return ("no_insp",) if clase in ("tabular", "texto", "sql") else ("omitir",)
    texto, truncado = leido
    if clase in ("sql", "texto"):
        return _clasificar_texto(clase, rel, texto, truncado)
    if clase == "tabular":
        columnas, valores, error_csv = _registros_tabulares(texto, truncado, EXT_TABULAR[Path(rel).suffix.lower()])
        # Ronda 8: teléfonos +56 por valor también en CSV (p. ej. columna «contacto»).
        pii = _clasificar_pii(columnas, valores, telefonos=True)
        if pii:
            return ("pii", pii)
        # Ronda 8: un CSV de más de _MAX_DATOS solo se leyó en parte: sin PII en lo leído no queda limpio (sin pase).
        if error_csv:
            return ("no_insp", "; ".join(x for x in ("CSV no legible por el módulo csv (p. ej. campo > 128 KiB)",
                                                    _nota_descartados(valores, truncado)) if x))
        return ("no_insp", _nota_descartados(valores, True)) if truncado else ("limpio",)
    else:
        r = _registros_json(texto, truncado, Path(rel).suffix.lower())
        if r == "truncado" or (r is None and truncado):
            # Ronda 4 (PV-R3-11): un JSON truncado que no se puede leer entero no se da por «configuración» por empezar
            # con «{»: se buscan claves y valores personales en lo leído y, si no hay, no es inspeccionable.
            if Path(rel).name.lower() in JSON_NO_DATOS:
                return ("omitir",)
            return _clasificar_texto("texto", rel, texto, True)
        if r == "profundo":
            # Ronda 8: anidamiento que json.loads no puede recorrer (RecursionError): sin PII por texto → no inspeccionable.
            return _no_tabular(rel, [texto], con_rut=True) or ("no_insp", "anidamiento JSON excesivo")
        if r is None:
            # JSON ilegible y no truncado (p. ej. JSONC de configuración que ni la conversión relajada lee). Ronda 7: se
            # revisan igual sus valores con forma de PII (RUT, email real, teléfono → pii_no_tabular, media); si no hay,
            # un .json se omite como antes, pero un .json5/.jsonc (formato de datos explícito, ronda 8) queda no
            # inspeccionable: no se pudo leer su estructura (fail-closed, sin pase).
            nt = _no_tabular(rel, [texto], con_rut=True)
            if nt:
                return nt
            if Path(rel).suffix.lower() in EXT_JSON_RELAJADO:
                return ("no_insp", "; ".join(x for x in ("JSON5/JSONC no legible sin librerías",
                                                        _nota_descartados([texto], False)) if x))
            return ("omitir",)
        # Ronda 8: `recorte` (r[3]) = el recorrido de claves y valores se cortó (tope o profundidad) o hubo líneas
        # JSONL ilegibles; con el archivo truncado (> _MAX_DATOS) pasa lo mismo: sin PII detectada no queda limpio.
        recorte = r[3] or truncado
        nota_recorte = "; ".join(x for x in (
            f"truncado: solo se leyeron {_MAX_DATOS // 1024} KiB" if truncado else "",
            "recorrido de claves y valores acotado (tope o profundidad) o líneas JSONL ilegibles" if r[3] else "",
            _nota_descartados(r[1], False)) if x)
        if r[0] == "config":
            # Ronda 6: JSON que no es una lista de registros (configuración, manifiesto): sus claves no son columnas.
            # Con raíz LISTA (forma de datos) un RUT válido sigue siendo crítico (ronda 6). Ronda 7: con raíz OBJETO
            # (antes se omitía entera) los valores con forma de RUT, email real o teléfono +56 → pii_no_tabular (media).
            # Ronda 8: los valores incluyen las CLAVES (un correo usado como clave cuenta).
            if r[2]:
                pii = _clasificar_pii([], r[1], solo_valores_fuertes=True)
                if pii:
                    return ("pii", pii)
            nt = _no_tabular(rel, r[1], con_rut=not r[2])
            if nt:
                return nt
            return ("no_insp", nota_recorte) if recorte else ("omitir",)
        columnas, valores, personas, _ = r
        # Ronda 8: valores anidados y claves incluidos (meta.correo, contactos: [...]) y teléfonos +56 por valor.
        pii = _clasificar_pii(columnas, valores, salud_ambigua=personas, telefonos=True)
        if pii:
            return ("pii", pii)
        return ("no_insp", nota_recorte) if recorte else ("limpio",)


NOTA_TEST = "en carpeta de test, verificar que sea ficticio"


def _hallazgo_pii(rel, pii, historial=False):
    """pii_tabular (crítica|alta) o, en una carpeta/archivo de test o fixture (comun.es_test_o_fixture), pii_en_test
    (media, ronda 6): datos que parecen personales en pruebas suelen ser ficticios, pero no se da por hecho (sin
    pase de DAT-PII-REPO; ver analizar)."""
    detectadas, conteos, critica = pii
    if conteos.get("solo_relleno") and not comun.es_test_o_fixture(rel):
        # Ronda 8 (propuesta del implementador, pendiente de confirmar): un archivo de datos cuya única PII por valor es
        # relleno evidente (RUT 11.111.111-1, móviles de dígitos repetidos), sin columnas personales ni correos reales,
        # no es crítico ni bloquea: pii_no_tabular (media, DAT-PII-TEST), visible y sin pase de DAT-PII-REPO.
        return _hallazgo_no_tabular(rel, {"email": 0, "telefono": conteos.get("telefono", 0),
                                          "telefono_relleno": conteos.get("telefono_relleno", 0),
                                          "rut": conteos["rut"], "rut_relleno": conteos.get("rut_relleno", 0),
                                          "email_descartado": 0, "solo_relleno": True}, historial)
    partes = []
    if detectadas:
        partes.append("columnas con datos personales o de salud: " + ", ".join(detectadas[:10]))
    if conteos["rut"] or conteos["email"] or conteos.get("telefono"):
        partes.append(f"valores con forma de RUT válido: {conteos['rut']}"
                      + (f" (de ellos con dígitos repetidos, relleno evidente: {conteos['rut_relleno']})"
                         if conteos.get("rut_relleno") else "")
                      + f"; con forma de email: {conteos['email']}"
                      + (f"; con forma de teléfono (+56): {conteos['telefono']}" if conteos.get("telefono") else ""))
    donde = (" en el historial de git (ya no está en el árbol actual, pero cualquiera que clone el repositorio lo "
             "recupera)" if historial else ": queda en el historial de git aunque se borre después")
    if comun.es_test_o_fixture(rel):
        return comun.hallazgo(
            NOMBRE, "pii_en_test", rel, None if historial else 1,
            f"Archivo de datos de test o fixture con datos que parecen personales ({NOTA_TEST})"
            + (" en el historial de git" if historial else "") + ". Si son reales, sacarlos del repositorio (y del "
            "historial) y reemplazarlos por datos sintéticos; si son ficticios, usar dominios reservados "
            "(@example.com, @example.test) y RUT de prueba evidentes.",
            f"ruta: {rel}{' (historial)' if historial else ''}; " + "; ".join(partes) + f" (valores no expuestos; "
            f"{NOTA_TEST})", "media")
    return comun.hallazgo(
        NOMBRE, "pii_tabular", rel, None if historial else 1,
        "Archivo de datos versionado con datos personales" + (" o de salud" if critica else "") + donde
        + ". Sacarlo del repositorio (y del historial), reemplazarlo por datos sintéticos y evaluar la notificación "
        "que exija la ley de datos personales.",
        f"ruta: {rel}{' (historial)' if historial else ''}; " + "; ".join(partes) + " (valores no expuestos)",
        "critica" if critica else "alta")


def _hallazgo_no_tabular(rel, c, historial=False):
    """Ronda 7: pii_no_tabular (media) — archivo versionado (o del historial) que NO es una lista de registros
    (configuración, estado o memoria de una herramienta) con valores con forma de email real o teléfono. Evidencia: solo
    conteos por tipo, nunca valores. Mapea a DAT-PII-TEST (media, sin bloqueo global) e impide el pase no_trackeado."""
    partes = [f"valores con forma de email (no reservado ni buzón de sistema): {c['email']}",
              f"con forma de teléfono (+56): {c['telefono']}"
              + (f" (de ellos con dígitos repetidos, relleno evidente: {c['telefono_relleno']})"
                 if c.get("telefono_relleno") else "")]
    if c.get("rut"):
        partes.append(f"con forma de RUT válido: {c['rut']}"
                      + (f" (de ellos con dígitos repetidos, relleno evidente: {c['rut_relleno']})"
                         if c.get("rut_relleno") else ""))
    if c["email_descartado"]:
        partes.append(f"descartados por dominio reservado o buzón de sistema: {c['email_descartado']}")
    if c.get("solo_relleno"):  # ronda 8: forma corta (la evidencia se corta a 300 caracteres)
        partes = [f"RUT válido: {c['rut']} (relleno: {c.get('rut_relleno', 0)})",
                  f"teléfono (+56): {c['telefono']} (relleno: {c.get('telefono_relleno', 0)})"]
    return comun.hallazgo(
        NOMBRE, "pii_no_tabular", rel, None if historial else 1,
        "Archivo versionado no tabular (configuración, estado o memoria de una herramienta) con valores que parecen "
        "datos personales" + (" en el historial de git" if historial else "") + ". Verificar si son reales; si lo "
        "son, sacarlos del repositorio (y del historial) o ignorar el archivo en .gitignore; si son ficticios, usar "
        "dominios reservados (@example.com, @example.test).",
        f"ruta: {rel}{' (historial)' if historial else ''}; "
        + ("solo valores de relleno evidente (sin columnas personales ni correos reales); "
           if c.get("solo_relleno") else "archivo no tabular; ") + "; ".join(partes)
        + " (valores no expuestos)", "media")


def _etiqueta_no_insp(rel, r, historial=False):
    """«ruta (historial; nota)» para la lista de no inspeccionables (ronda 7: la nota explica truncado y descartes)."""
    extras = (["historial"] if historial else []) + ([r[1]] if len(r) > 1 and r[1] else [])
    return f"{rel} ({'; '.join(extras)})" if extras else rel


def inspeccionar_datos(proyecto, versionados, conf):
    """Ronda 3 (PV-R2-01) y 4 (PV-R3-10/11). (hallazgos pii_tabular, nº de archivos de datos inspeccionados,
    [no inspeccionables], nº declarados sintéticos) de los archivos de datos versionados que no son confidenciales."""
    hallazgos, inspeccionados, no_inspeccionables, sinteticos = [], 0, [], 0
    for rel in sorted(versionados):
        if raiz_confidencial(rel, conf) is not None:
            continue  # ya cuenta como trackeado (o sintético declarado); su contenido no se lee aquí
        ruta = Path(proyecto) / rel
        if _clase(rel) is None or not ruta.is_file() or ruta.is_symlink():
            continue
        r = inspeccionar_archivo(rel, lambda: _leer_acotado(ruta), conf)
        if r[0] == "sintetico":
            sinteticos += 1
        elif r[0] == "no_insp":
            no_inspeccionables.append(_etiqueta_no_insp(rel, r))
        elif r[0] == "limpio":
            inspeccionados += 1
        elif r[0] == "pii":
            inspeccionados += 1
            hallazgos.append(_hallazgo_pii(rel, r[1]))
        elif r[0] == "pii_nt":
            inspeccionados += 1
            hallazgos.append(_hallazgo_no_tabular(rel, r[1]))
    return hallazgos, inspeccionados, no_inspeccionables, sinteticos


def _leer_blob(proyecto, sha):
    """(texto, truncado) de los primeros _MAX_DATOS bytes de un blob de git; None si no se puede leer o es binario."""
    import subprocess
    try:
        proc = subprocess.Popen(["git", "--no-optional-locks", *git_seguro.argumentos(), "-C", str(proyecto),
                                 "cat-file", "blob", sha], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL, env=git_seguro.entorno())
    except OSError:
        return None
    try:
        crudo = proc.stdout.read(_MAX_DATOS + 1)
    finally:
        proc.kill()
        proc.stdout.close()
        proc.wait()
    truncado = len(crudo) > _MAX_DATOS
    crudo = crudo[:_MAX_DATOS]
    if not crudo and not truncado:
        return "", False
    if b"\0" in crudo[:4096]:
        return None
    return crudo.decode("utf-8-sig", errors="replace"), truncado


def _tipos_objetos(proyecto, shas):
    """{sha: tipo} con git cat-file --batch-check (lee solo metadatos del objeto); None si git falla."""
    import subprocess
    if not shas:
        return {}
    try:
        r = subprocess.run(["git", "--no-optional-locks", *git_seguro.argumentos(), "-C", str(proyecto), "cat-file",
                            "--batch-check=%(objectname) %(objecttype)"], input="\n".join(shas).encode() + b"\n",
                           capture_output=True, timeout=120, env=git_seguro.entorno())
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    tipos = {}
    for linea in r.stdout.decode("utf-8", "replace").splitlines():
        partes = linea.split()
        if len(partes) == 2:
            tipos[partes[0]] = partes[1]
    return tipos


def inspeccionar_historial(proyecto, versionados, conf):
    """Ronda 4 (PV-R3-12). Blobs del historial (git rev-list --all --objects) de rutas del proyecto que ya NO están en
    el árbol actual (o versiones anteriores de las que sí están): rutas confidenciales → trackeado_historial; archivos
    de datos → la misma inspección acotada. Devuelve (hallazgos, inspeccionados, [no inspeccionables], error|None)."""
    import subprocess
    rc, pref = git_seguro.ejecutar(proyecto, "rev-parse", "--show-prefix")
    if rc != 0 or pref is None:
        return [], 0, [], "no se pudo leer la ruta del proyecto dentro del repositorio"
    prefijo = pref.strip()
    try:
        r = subprocess.run(["git", "--no-optional-locks", *git_seguro.argumentos(), "-C", str(proyecto),
                            "rev-list", "--all", "--objects"], capture_output=True, timeout=120,
                           env=git_seguro.entorno(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return [], 0, [], "git rev-list no se pudo ejecutar"
    if r.returncode != 0:
        return [], 0, [], f"git rev-list terminó con código {r.returncode}"
    rc_s, actuales = _git_lista(proyecto, "ls-files", "-s", "-z")
    blobs_actuales = {x.split()[1] for x in (actuales or []) if len(x.split()) >= 2}
    vers = set(versionados)
    hallazgos, inspeccionados, no_insp, confid = [], 0, [], {}
    candidatos = []
    entradas = []
    for linea in r.stdout.decode("utf-8", "replace").splitlines():
        sha, _, ruta = linea.partition(" ")
        if not ruta or sha in blobs_actuales or not ruta.startswith(prefijo):
            continue
        entradas.append((sha, ruta[len(prefijo):]))
    # Ronda 6: rev-list --objects lista también ÁRBOLES (carpetas) con su ruta; una carpeta como pages/api/patients
    # no es un archivo borrado. Solo los blobs cuentan (git cat-file --batch-check; si falla, sin pase).
    tipos = _tipos_objetos(proyecto, sorted({s for s, _ in entradas}))
    if tipos is None:
        return [], 0, [], "git cat-file --batch-check no se pudo ejecutar"
    for sha, rel in entradas:
        if tipos.get(sha) != "blob" or raiz_confidencial(rel, conf) is not None:
            continue  # carpetas (árboles) y rutas confidenciales: estas no se leen nunca (ver abajo)
        if _clase(rel) is not None:
            candidatos.append((rel, sha))
    # Rutas confidenciales del historial: TODAS las rutas de archivo que algún commit tocó (git log --name-only, solo
    # nombres), no la ruta con la que rev-list encontró cada blob (git deduplica contenidos: un datos-reales/a.csv
    # borrado con el mismo contenido que un archivo vigente no aparecería). Solo se afirma «en el historial» si el
    # archivo ya NO está en el árbol actual (si está, cuenta como trackeado).
    rc_log, historicas = _git_lista(proyecto, "log", "--all", "-m", "--no-renames", "--format=", "--name-only", "-z")
    if rc_log is None or rc_log != 0:
        return [], 0, [], f"git log --name-only terminó con código {rc_log}"
    for ruta in sorted(set(historicas)):
        ruta = ruta.strip("\n")
        if not ruta.startswith(prefijo):
            continue
        rel = ruta[len(prefijo):]
        raiz = raiz_confidencial(rel, conf)
        if raiz is not None and rel not in vers and not es_sintetico_declarado(rel, conf):
            confid.setdefault(raiz, set()).add(rel)
    for raiz, rels in sorted(confid.items()):
        hallazgos.append(comun.hallazgo(
            NOMBRE, "trackeado_historial", raiz, None,
            "Datos confidenciales (personales o de salud) en el historial de git: se borraron del árbol, pero siguen "
            "en commits anteriores y cualquiera que clone el repositorio los recupera. Reescribir el historial "
            "(git filter-repo) y rotar o notificar según corresponda.",
            f"ruta: {raiz}; archivos en el historial: {len(rels)}", "critica"))
    if len(candidatos) > MAX_BLOBS_HISTORIAL:
        no_insp.append(f"historial: {len(candidatos)} versiones de archivos de datos (> {MAX_BLOBS_HISTORIAL})")
        candidatos = []
    ya, ya_nt = set(), {}
    for rel, sha in candidatos:
        res = inspeccionar_archivo(rel, lambda: _leer_blob(proyecto, sha), conf)
        if res[0] == "no_insp":
            no_insp.append(_etiqueta_no_insp(rel, res, historial=True))
        elif res[0] == "limpio":
            inspeccionados += 1
        elif res[0] == "pii":
            inspeccionados += 1
            if rel not in ya:
                ya.add(rel)
                hallazgos.append(_hallazgo_pii(rel, res[1], historial=True))
        elif res[0] == "pii_nt":
            inspeccionados += 1
            ya_nt.setdefault(rel, res[1])  # ronda 7: una versión por ruta basta (la primera con valores)
    for rel, c in sorted(ya_nt.items()):
        if rel not in ya:  # si otra versión ya dio pii_tabular (más grave), no se duplica
            hallazgos.append(_hallazgo_no_tabular(rel, c, historial=True))
    return hallazgos, inspeccionados, no_insp, None


def _sin_versionar_ni_ignorar(raiz, archivos, versionados, ignorados):
    """True si algún archivo local de la raíz no está versionado ni ignorado."""
    if raiz in ignorados:
        return False
    vers = set(versionados)
    return any(a not in vers and a not in ignorados for a in archivos)


def analizar(proyecto):
    proyecto = Path(proyecto).resolve()
    conf = cargar()
    raices = _inventario(proyecto, conf)

    rc, _ = _git_lista(proyecto, "rev-parse", "--is-inside-work-tree")
    if rc is None:
        return comun.resultado(estado="no_evaluado", motivo="git no se pudo ejecutar")
    en_repo = rc == 0

    trackeados = {}
    ignorados = set()
    versionados = []
    if en_repo:
        rc_ls, versionados = _git_lista(proyecto, "ls-files", "-z")
        if rc_ls is None or rc_ls != 0:
            return comun.resultado(estado="error", motivo=f"git ls-files terminó con código {rc_ls}")
        for ruta in versionados:
            r = raiz_confidencial(ruta, conf)
            if r is not None:
                trackeados.setdefault(r, []).append(ruta)
        rutas = [a for info in raices.values() for a in info["archivos"]] + list(raices)
        if rutas:
            entrada = b"\0".join(r.encode("utf-8") for r in rutas) + b"\0"
            rc_ci, salida = _git_lista(proyecto, "check-ignore", "--no-index", "--stdin", "-z", entrada=entrada)
            if rc_ci in (0, 1):
                ignorados = set(salida)

    hallazgos, pases, inventario = [], [], []
    sinteticos_trk = 0
    for r in sorted(set(raices) | set(trackeados)):
        info = raices.get(r, {"tipo": "versionado_sin_copia_local", "archivos": [], "bytes": 0})
        trk_r = trackeados.get(r, [])
        # AUD-SINT: los versionados declarados sintéticos por el creador salen como info (no críticos),
        # salvo que el inspector lea una cabecera DICOM que no parezca ficticia.
        sint_r = [a for a in trk_r if es_sintetico_declarado(a, conf)]
        if sint_r:
            veredictos = [inspeccionar_cabecera_dicom(proyecto / a)["veredicto"] for a in sint_r
                          if (proyecto / a).is_file() and not (proyecto / a).is_symlink()]
            no_ficticios = veredictos.count("no_ficticio")
            if no_ficticios:
                sint_r = []  # la evidencia contradice la declaración: vuelve a contar como versionado
            else:
                n_ok = veredictos.count("ficticio")
                cab = (f"; cabecera DICOM con tags de paciente vacíos o con patrón de valor ficticia en "
                       f"{n_ok}/{len(veredictos)}" if n_ok else "")
                hallazgos.append(comun.hallazgo(
                    NOMBRE, "sintetico_declarado", r, None,
                    "Archivo confidencial versionado: declarado sintético por el creador, verificar",
                    f"ruta: {r}; archivos versionados declarados sintéticos: {len(sint_r)}{cab}", "info"))
                sinteticos_trk += len(sint_r)
        n_trk = len(trk_r) - len(sint_r)
        nota_dicom = ""
        if trk_r and not sint_r and any(es_sintetico_declarado(a, conf) for a in trk_r):
            nota_dicom = ("; declarado sintético, pero no se pudo confirmar una cabecera DICOM ficticia "
                          "(valores no expuestos)")
        if not en_repo:
            en_ignore = None
        elif info["archivos"]:
            marcados = [a for a in info["archivos"] if a in ignorados or r in ignorados]
            en_ignore = True if len(marcados) == len(info["archivos"]) else (False if not marcados else "parcial")
        else:
            en_ignore = (r in ignorados) if r in raices else None
        inventario.append({"ruta": r, "tipo": info["tipo"], "archivos": len(info["archivos"]),
                           "bytes": info["bytes"], "en_gitignore": en_ignore, "trackeados": len(trk_r),
                           "sintetico_declarado": bool(trk_r) and len(sint_r) == len(trk_r)})
        if n_trk:
            hallazgos.append(comun.hallazgo(
                NOMBRE, "trackeado", r, None,
                "Datos confidenciales (personales o de salud) versionados en el repositorio git",
                f"ruta: {r}; archivos versionados: {n_trk}{nota_dicom}", "critica"))
        elif en_repo and info["archivos"] and _sin_versionar_ni_ignorar(r, info["archivos"], trk_r, ignorados):
            # Solo cuentan los archivos NO versionados (un sintético declarado y versionado no es
            # «sin versionar ni ignorado»; corrección de la re-auditoría de kine us, 2026-11-18).
            hallazgos.append(comun.hallazgo(
                NOMBRE, "sin_gitignore", r, None,
                "Carpeta o archivo confidencial sin versionar pero tampoco en .gitignore",
                f"ruta: {r}; archivos: {len(info['archivos'])}; en .gitignore: "
                f"{'parcial' if en_ignore == 'parcial' else 'no'}", "alta"))
    candidatos = set(raices) | set(trackeados)
    pii, n_datos, no_inspeccionables, n_sint_datos = ([], 0, [], 0) if not en_repo else inspeccionar_datos(
        proyecto, versionados, conf)
    hallazgos.extend(pii)
    n_hist, error_hist = 0, None
    if en_repo:
        h_hist, n_hist, ni_hist, error_hist = inspeccionar_historial(proyecto, versionados, conf)
        hallazgos.extend(h_hist)
        no_inspeccionables = list(no_inspeccionables) + ni_hist
    if not en_repo:
        # Sin repositorio git nada está versionado; DAT-PII-REPO trata del repositorio (ronda 1: no_aplica, no pass).
        res = comun.resultado(hallazgos, [], estado="no_aplica", motivo=(
            f"sin repositorio git: nada está versionado ({len(candidatos)} candidato(s) confidencial(es) local(es) "
            "en el inventario); si se crea el repositorio, re-auditar"))
        res["inventario"] = inventario
        res["patrones"] = conf
        return res
    if not candidatos and not versionados:
        res = comun.resultado(hallazgos, [], estado="no_aplica", motivo=(
            "repositorio git sin archivos versionados en el proyecto ni candidatos confidenciales: nada que evaluar"))
        res["inventario"] = inventario
        res["patrones"] = conf
        return res
    motivo_res = None
    graves = (".trackeado", ".pii_tabular", ".trackeado_historial")
    en_test = sorted({h["archivo"] for h in hallazgos if h["regla"].endswith(".pii_en_test")})
    no_tab = sorted({h["archivo"] for h in hallazgos if h["regla"].endswith(".pii_no_tabular")})
    if error_hist and not any(h["regla"].endswith(graves) for h in hallazgos):
        motivo_res = (f"no se pudo revisar el historial de git ({error_hist}): un archivo de datos borrado del árbol "
                      "puede seguir en commits anteriores (sin pase; fail-closed)")
    elif no_inspeccionables and not any(h["regla"].endswith(graves) for h in hallazgos):
        motivo_res = (f"{len(no_inspeccionables)} archivo(s) de datos versionado(s) no inspeccionable(s) en estático "
                      f"({', '.join(no_inspeccionables[:5])}{' …' if len(no_inspeccionables) > 5 else ''}): no se "
                      "puede afirmar que el repositorio no tenga datos personales (sin pase; revisar a mano)")
    elif en_test and not any(h["regla"].endswith(graves) for h in hallazgos):
        # Ronda 6: datos que parecen personales solo en tests/fixtures → hallazgo media (pii_en_test), sin crítico ni
        # bloqueo; tampoco pase (fail-closed): que sean ficticios lo confirma una persona.
        motivo_res = (f"{len(en_test)} archivo(s) de test o fixture con datos que parecen personales "
                      f"({', '.join(en_test[:5])}{' …' if len(en_test) > 5 else ''}): {NOTA_TEST} (sin pase; "
                      "hallazgo pii_en_test, severidad media)")
    elif no_tab and not any(h["regla"].endswith(graves) for h in hallazgos):
        # Ronda 7: valores con forma de email/teléfono en archivos versionados NO tabulares → pii_no_tabular (media);
        # no es crítico, pero tampoco hay pase (fail-closed): que no sean datos personales lo confirma una persona.
        motivo_res = (f"{len(no_tab)} archivo(s) versionado(s) no tabular(es) (o de datos con solo valores de relleno "
                      f"evidente) con valores que parecen datos personales "
                      f"({', '.join(no_tab[:5])}{' …' if len(no_tab) > 5 else ''}): verificar si son reales (sin "
                      "pase; hallazgo pii_no_tabular, severidad media)")
    elif not any(h["regla"].endswith(graves) for h in hallazgos):
        if candidatos:
            motivo = (f"ningún archivo confidencial versionado en git ({len(candidatos)} candidato(s) evaluado(s); "
                      f"{len(versionados)} archivos versionados contrastados con los patrones)")
        else:
            motivo = (f"ningún archivo confidencial versionado en git ({len(versionados)} archivos versionados "
                      "contrastados con los patrones; sin candidatos confidenciales locales)")
        if sinteticos_trk:
            motivo += (f", salvo {sinteticos_trk} declarado(s) sintético(s) por el creador "
                       "(config/confidencial.toml [sinteticos]; verificar)")
        motivo += (f"; {n_datos} archivo(s) de datos versionado(s) inspeccionado(s) sin columnas ni valores personales"
                   if n_datos else "; ningún archivo de datos versionado (CSV/TSV, JSON de registros, SQL, xlsx…)")
        if n_sint_datos:
            motivo += f"; {n_sint_datos} archivo(s) de datos en rutas declaradas sintéticas no inspeccionado(s)"
        motivo += (f"; historial git revisado: {n_hist} versión(es) anterior(es) de archivos de datos inspeccionada(s) "
                   "sin datos personales" if n_hist else "; historial git revisado: sin archivos de datos ni rutas "
                   "confidenciales fuera del árbol actual")
        pases.append(comun.pase(NOMBRE, "no_trackeado", motivo))
    res = comun.resultado(hallazgos, pases, motivo=motivo_res)
    res["inventario"] = inventario
    res["patrones"] = conf
    return res


def filtrar_osv(ruta_json, proyecto):
    """Quita de un osv.json los resultados cuyo source.path es confidencial. Devuelve cuántos quitó."""
    import json
    conf = cargar()
    ruta_json = Path(ruta_json)
    datos = json.loads(ruta_json.read_text(encoding="utf-8"))
    if not isinstance(datos, dict):
        return 0
    base = str(Path(proyecto).resolve()).rstrip("/") + "/"
    quedan, quitados = [], 0
    for res in datos.get("results") or []:
        ruta = str(((res or {}).get("source") or {}).get("path") or "")
        rel = ruta[len(base):] if ruta.startswith(base) else ruta
        if rel and not rel.startswith("/") and es_confidencial(rel, conf):
            quitados += 1
        else:
            quedan.append(res)
    if quitados:
        datos["results"] = quedan
        ruta_json.write_text(json.dumps(datos, ensure_ascii=False, indent=1), encoding="utf-8")
    return quitados


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:2] == ["--exclusiones", "semgrep"]:
        print("\n".join(exclusiones_semgrep()))
        return 0
    if argv[:1] == ["--patrones"]:
        conf = cargar()
        ambiguas = [f"{c} (solo archivos de datos)" for c in conf.get("carpetas_ambiguas") or []]
        print("\n".join(conf["carpetas"] + ambiguas + conf["archivos"]))
        return 0
    if argv[:1] == ["--filtrar-osv"]:
        if len(argv) != 3:
            print("uso: datos_confidenciales.py --filtrar-osv OSV.json PROYECTO", file=sys.stderr)
            return 2
        print(filtrar_osv(argv[1], argv[2]))
        return 0
    if argv[:1] == ["--config-gitleaks"]:
        if len(argv) != 3:
            print("uso: datos_confidenciales.py --config-gitleaks BASE SALIDA", file=sys.stderr)
            return 2
        Path(argv[2]).write_text(config_gitleaks(argv[1]), encoding="utf-8")
        return 0
    return comun.main_check(NOMBRE, analizar, argv)


if __name__ == "__main__":
    sys.exit(main())
