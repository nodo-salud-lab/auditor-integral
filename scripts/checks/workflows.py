#!/usr/bin/env python3
"""workflows — fallback de actionlint (DECISIONES #6; investigacion/13 §4.7). Cobertura parcial.

La seguridad de los workflows (inyección de expresiones, permisos, acciones sin SHA,
pull_request_target) la cubre zizmor (adaptador existente). Este fallback agrega solo sintaxis
mínima y la verificación "el CI corre lint/tests". Sin PyYAML (no es stdlib): análisis por líneas.

Subregla                 sev    → control
  sin_on / sin_jobs       media  → SEG-CICD
  job_sin_runs_on         media  → SEG-CICD
  tabulador               media  → SEG-CICD (YAML inválido)
  expresion_mal_cerrada   media  → SEG-CICD
  runner_obsoleto         baja   → SEG-CICD (lista a mantener; fechas de retiro NO VERIFICADAS)
  ci_sin_calidad          media  → COD-CI-BASICO (ningún `run:` ejecuta lint/typecheck/tests)
Pases: ok_sintaxis (→ SEG-CICD, parcial), ok_ci_calidad (sin mapear; el pase de COD-CI-BASICO lo emite archivos_clave
con calidad_ci()).
Ronda 1 de pases vacíos: la comprobación SEMÁNTICA del CI (ci_sin_calidad / ok_ci_calidad) corre SIEMPRE, también
cuando actionlint está instalado: actionlint valida sintaxis y expresiones, no que el CI ejecute lint o tests. Con
actionlint disponible se omiten solo las subreglas de sintaxis (las cubre la herramienta real).
Ronda 2 de pases vacíos: un comando cuenta solo si se EJECUTA (runs_efectivos / ejecuta_calidad): no dentro de un
echo/printf ni en un comentario de shell, no en jobs o pasos con `if: false` (o `${{ false }}`), y solo en workflows
que se disparan en push / pull_request / pull_request_target / merge_group (o en un workflow reutilizable que uno de
ellos llama con `uses: ./.github/workflows/…`). El título pide lint, typecheck Y tests; hoy basta uno de los tres
(decisión pendiente del investigador; ver el resumen de la ronda 2).
Ronda 3 de pases vacíos (PV-R2-02/03): además, el comando tiene que correr SIEMPRE y su fallo tiene que hacer fallar
el CI. Se modela bash -e (cortocircuito && / ||, `exit`, `set +e`, segundo plano, `!`, if/while/case), se descarta el
cuerpo de los heredocs, se evalúan `if:` (lógica de tres valores sobre github.event_name y las funciones de estado),
continue-on-error y `shell:` del job y del paso, los filtros branches / paths de los disparadores y los scripts de
package.json (`npm test` con un script inexistente o que no hace nada no cuenta). Resultado de calidad_ci: True
(pase), False (hallazgo ci_sin_calidad) o None (dudoso: ni pase ni hallazgo, motivo explícito).
Uso: workflows.py PROYECTO DIR_CRUDO
Ronda 4 (investigacion/16, PV-R3-07/08/09): un argumento cuenta solo si ES la herramienta o el subcomando de calidad
(`pytest`, `test`, `test:unit`, `scripts/test.js`), no si lo contiene (`generate-test-fixtures.js`, `deploy-test`,
`print('tests ok')`); `make X` / `just X` leen el Makefile/justfile y cuentan solo si la receta (o un prerrequisito)
ejecuta calidad; `npm test` exige que el CUERPO del script ejecute calidad (el nombre «test» ya no basta); `node --test`
y CLI con subcomando (`react-scripts test`, `ng test`, `next lint`) cuentan. LIMITACIÓN: task, tox y nox no leen su
configuración (cuentan por el nombre completo de la sesión o tarea).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "workflows"
REEMPLAZA = "actionlint"
HERRAMIENTAS_REALES = ("actionlint",)
RUNNERS_OBSOLETOS = ("ubuntu-16.04", "ubuntu-18.04", "ubuntu-20.04", "macos-10.15", "macos-11", "macos-12",
                     "windows-2016", "windows-2019")
RE_CALIDAD = re.compile(r"\b(lint|eslint|biome|ruff|flake8|pylint|test|tests|vitest|jest|mocha|pytest|unittest|"
                        r"tsc|typecheck|type-check|mypy|pyright|playwright|cypress|go\s+vet|cargo\s+(test|clippy))\b", re.I)
RE_CLAVE_RAIZ = re.compile(r"""^(?:"([^"]+)"|'([^']+)'|([\w-]+))\s*:""")


def _indent(linea):
    return len(linea) - len(linea.lstrip(" \t"))


def lineas_run(lineas):
    """[(n, texto)] de los comandos de `run:` (en línea o en bloque | / >). Ronda 2: sin las líneas de comentario de
    shell de los bloques (un `# npm test` no ejecuta nada). Ronda 3: sin el cuerpo de los heredocs."""
    return [(n, t) for n, t in _runs_de(lineas, 0, len(lineas)) if not t.lstrip().startswith("#")]


def _runs_de(lineas, ini, fin):
    """[(n, comando)] de los `run:` entre las líneas [ini, fin) (0-based), en orden."""
    return [x for _, cmds in _pasos_de(lineas, ini, fin) for x in cmds]


# Ronda 3: el cuerpo de un heredoc (`cat <<EOF … EOF`) es texto, no comandos.
RE_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][\w.-]*)\1")


def _sin_heredocs(cmds):
    salida, delim = [], None
    for n, t in cmds:
        if delim is not None:
            if t.strip() == delim:
                delim = None
            continue
        salida.append((n, t))
        m = RE_HEREDOC.search(t)
        if m:
            delim = m.group(2)
    return salida


def _pasos_de(lineas, ini, fin):
    """[(i_run, [(n, comando)])]: un elemento por cada `run:` entre [ini, fin) (i_run = índice 0-based de la línea
    `run:`). Las continuaciones con «\\» se unen; un bloque `>` se pliega en una sola línea; un valor entre comillas
    YAML se desentrecomilla; el cuerpo de los heredocs se descarta (ronda 3)."""
    salida = []
    i = ini
    while i < fin:
        m = re.match(r"^(\s*)(?:-\s+)?run\s*:\s*(.*)$", lineas[i])
        if not m:
            i += 1
            continue
        base = len(m.group(1))
        resto = m.group(2).strip()
        if resto and not resto.startswith(("|", ">")):
            if len(resto) >= 2 and resto[0] == resto[-1] and resto[0] in "'\"":
                resto = resto[1:-1]
            salida.append((i, [(i + 1, resto)]))
            i += 1
            continue
        plegado = resto.startswith(">")
        j = i + 1
        bloque = []
        while j < fin and (not lineas[j].strip() or _indent(lineas[j]) > base):
            if lineas[j].strip():
                bloque.append((j + 1, lineas[j].strip()))
            j += 1
        if plegado and bloque:
            bloque = [(bloque[0][0], " ".join(t for _, t in bloque if not t.startswith("#")))]
        unido, previo = [], None
        for n, t in bloque:
            if previo is not None:
                previo = (previo[0], previo[1][:-1] + " " + t)
            else:
                previo = (n, t)
            if not previo[1].endswith("\\"):
                unido.append(previo)
                previo = None
        if previo is not None:
            unido.append((previo[0], previo[1].rstrip("\\")))
        salida.append((i, _sin_heredocs(unido)))
        i = j
    return salida


# --- Ronda 2 de pases vacíos: qué cuenta como «el CI ejecuta lint/typecheck/tests» ---------------------------------
# Un comando cuenta solo si se EJECUTA: no dentro de un echo/printf ni en un comentario; no en un job o paso con
# `if: false`; y solo en workflows que se disparan en push / pull_request (o en un workflow reutilizable que uno de
# ellos llama con `uses: ./.github/workflows/…`).
# --- Ronda 3: además, el comando tiene que correr SIEMPRE y su fallo tiene que hacer fallar el CI --------------------
#   * semántica de cortocircuito del shell (bash -e de GitHub Actions): `true || npm test`, `false && npm test` y
#     `exit 0; npm run lint` nunca lo ejecutan; `npm test || true`, `|| exit 0`, `|| echo …`, `npm test &`,
#     `! npm test` y `set +e` enmascaran su fallo; `npm test && echo ok` seguido de otra línea también (bash -e no
#     termina por un fallo que no es el último comando de una lista && / ||);
#   * continue-on-error del job o del paso (literal true → nunca bloquea; expresión → dudoso);
#   * `if:` evaluado con lógica de tres valores (github.event_name, always(), success(), failure(), cancelled());
#   * filtros branches / branches-ignore / paths / paths-ignore / tags de los disparadores;
#   * `npm test` / `npm run X` / `pnpm X` / `yarn X` se cruzan con los scripts de package.json: un script inexistente
#     o que no ejecuta nada (`echo no tests && exit 0`) no cuenta.
# Cada aparición recibe una certeza: SIEMPRE (cuenta), QUIZAS (dudoso: ni pase ni hallazgo) o NUNCA (no cuenta).
EVENTOS_CI = frozenset({"push", "pull_request", "pull_request_target", "merge_group"})
NO_EJECUTAN = frozenset({"echo", "printf", "true", ":", "false", "exit", "cat", "set", "export", "cd", "mkdir",
                         "ls", "pwd", "sleep", "#"})
ENVOLTORIOS = frozenset({"sudo", "env", "time", "nice", "xvfb-run", "timeout", "command", "exec"})
LANZADORES = frozenset({"npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx", "deno", "node", "python", "python3", "py",
                        "uv", "uvx", "poetry", "pipenv", "pdm", "hatch", "tox", "nox", "go", "cargo", "make", "just",
                        "task", "dotnet", "mvn", "./mvnw", "gradle", "./gradlew", "rake", "bundle", "composer",
                        "php", "turbo", "nx", "lerna"})
RE_EVENTO = re.compile(r"[\w-]+")
NUNCA, QUIZAS, SIEMPRE = 0, 1, 2
# Builtins del shell que siempre terminan bien (no fallan por el proyecto).
OK_SIEMPRE = frozenset({"true", ":", "echo", "printf", "set", "export", "pwd", "sleep", "unset", "shopt", "alias",
                        "umask", "readonly", "local", "declare", "typeset", "hash"})
OPERADORES_SHELL = ("<<<", "<<-", "&>>", ">>", "<<", ">&", "<&", "&>", ">|", "&&", "||", "|&", ";;", ";", "&", "|",
                    "<", ">", "(", ")")
REDIRECCIONES = frozenset({"<<<", "<<-", "&>>", ">>", "<<", ">&", "<&", "&>", ">|", "<", ">"})
ABRE_COMPUESTO = frozenset({"if", "while", "until"})
ABRE_COMPUESTO_ENTERO = frozenset({"for", "case", "select"})
CIERRA_COMPUESTO = frozenset({"fi", "done", "esac", "}"})
PREFIJOS_COMPUESTO = frozenset({"then", "do", "else", "elif", "{"})
MAX_CAMINOS = 4096


def _tokens_shell(linea):
    """[(tipo, token)] con tipo "w" (palabra) u "op" (operador); None si no se puede analizar (comillas
    desbalanceadas): fail-closed, no cuenta."""
    import shlex
    try:
        lex = shlex.shlex(linea, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = "#"
        crudos = list(lex)
    except ValueError:
        return None
    res = []
    for t in crudos:
        if t and all(ch in ";&|()<>" for ch in t):
            i = 0
            while i < len(t):
                op = next((o for o in OPERADORES_SHELL if t.startswith(o, i)), t[i])
                res.append(("op", op))
                i += len(op)
        else:
            res.append(("w", t))
    return res


def _listas_shell(tokens):
    """[(terminador, [(op_previo, negado, [comando, …])])]: listas and-or (separadas por ; & o fin de línea) de
    tuberías (separadas por && / ||) de comandos simples (separados por | )."""
    listas, tuberias, tuberia, cmd = [], [], [], []
    op_prev, negado, saltar = None, False, False
    for tipo, t in tokens:
        if saltar:  # destino de una redirección (archivo, descriptor o delimitador de heredoc)
            saltar = False
            if tipo == "w":
                continue
        if tipo == "w":
            if t == "!" and not cmd and not tuberia:
                negado = not negado
                continue
            cmd.append(t)
            continue
        if t in REDIRECCIONES:
            saltar = True
            continue
        if t in ("(", ")"):
            continue
        if t in ("|", "|&"):
            tuberia.append(cmd)
            cmd = []
            continue
        tuberia.append(cmd)
        tuberias.append((op_prev, negado, [c for c in tuberia if c]))
        tuberia, cmd, negado = [], [], False
        if t in ("&&", "||"):
            op_prev = t
            continue
        listas.append(("&" if t == "&" else ";", tuberias))
        tuberias, op_prev = [], None
    if cmd or tuberia:
        tuberia.append(cmd)
        tuberias.append((op_prev, negado, [c for c in tuberia if c]))
    if tuberias:
        listas.append((";", tuberias))
    return listas


def _comandos_simples(linea):
    """Lista de comandos simples (listas de tokens) de una línea de shell, sin comentarios. None si no se puede
    analizar (comillas desbalanceadas): fail-closed, no cuenta."""
    tokens = _tokens_shell(linea)
    if tokens is None:
        return None
    return [c for _, tubs in _listas_shell(tokens) for _, _, cmds in tubs for c in cmds]


def _sin_prefijos(tokens):
    i = 0
    while i < len(tokens) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]) or tokens[i] in ENVOLTORIOS):
        i += 1
    return tokens[i:]


def _clase_comando(toks):
    """("ok" | "fail" | "otro" | "exit", codigo): "exit" lleva True si el código es distinto de 0, False si es 0 o
    desconocido (conservador: se trata como salida exitosa) y None si es `exit` sin argumento (estado previo)."""
    toks = _sin_prefijos(toks)
    if not toks:
        return "ok", None
    c = toks[0]
    if c == "false":
        return "fail", None
    if c in ("exit", "return"):
        if len(toks) < 2:
            return "exit", None
        return "exit", (toks[1].isdigit() and int(toks[1]) != 0)
    if c in OK_SIEMPRE:
        return "ok", None
    return "otro", None


def _clase_tuberia(cmds, negado, dentro_compuesto):
    if not cmds:
        clase = ("ok", None)
    elif len(cmds) == 1:
        clase = _clase_comando(cmds[0])
    else:
        clases = [_clase_comando(c)[0] for c in cmds]
        clase = ("ok", None) if all(k == "ok" for k in clases) else ("otro", None)
    if clase[0] == "exit" and dentro_compuesto:
        clase = ("otro", None)  # un exit dentro de if/while/case es condicional
    if negado:
        clase = {"ok": ("fail", None), "fail": ("ok", None)}.get(clase[0], clase)
    return clase


def _errexit_tras(cmds, errexit):
    if len(cmds) != 1:
        return errexit
    toks = _sin_prefijos(cmds[0])
    if not toks or toks[0] != "set":
        return errexit
    args = toks[1:]
    for k, a in enumerate(args):
        if a in ("-o", "+o") and k + 1 < len(args) and args[k + 1] == "errexit":
            errexit = a == "-o"
        elif re.fullmatch(r"-[a-zA-Z]+", a) and "e" in a:
            errexit = True
        elif re.fullmatch(r"\+[a-zA-Z]+", a) and "e" in a:
            errexit = False
    return errexit


def _ocurrencias(cmds, pred, errexit=True):
    """[(n, certeza)] de cada comando que cumple `pred` en un paso (lista [(n, línea)] de un `run:`), con la semántica
    de bash -e: SIEMPRE si corre en todo camino que no falló antes y su fallo hace fallar el paso; QUIZAS si corre
    solo en algunos caminos (o dentro de if/while/case); NUNCA si no corre o su fallo queda enmascarado."""
    unidades = []  # (n, terminador, tuberias)
    for n, linea in cmds:
        tokens = _tokens_shell(linea)
        if tokens is None:
            continue
        for term, tubs in _listas_shell(tokens):
            unidades.append((n, term, tubs))
    res = []
    vivo = SIEMPRE
    profundidad = 0
    for k, (n, term, tubs) in enumerate(unidades):
        ultima = k == len(unidades) - 1
        info = []
        for op, negado, cmds_t in tubs:
            limpios = []
            prof_cmd = profundidad
            for c in cmds_t:
                toks = list(c)
                while toks and toks[0] in PREFIJOS_COMPUESTO:
                    toks = toks[1:]
                if toks and toks[0] in ABRE_COMPUESTO:
                    profundidad += 1
                    toks = toks[1:]
                elif toks and toks[0] in ABRE_COMPUESTO_ENTERO:
                    profundidad += 1
                    toks = []
                elif toks and toks[0] in CIERRA_COMPUESTO:
                    profundidad = max(0, profundidad - 1)
                    toks = []
                prof_cmd = max(prof_cmd, profundidad)
                if toks:
                    limpios.append(toks)
            coincide = any(pred(c) for c in limpios)
            info.append((op, _clase_tuberia(limpios, negado, prof_cmd > 0), coincide, prof_cmd > 0, limpios, negado))
        caminos = [{"st": None, "term": None, "ej": (), "res": {}}]
        desborde = False
        for i, (op, (clase, codigo), _, _, _, _) in enumerate(info):
            nuevos = []
            for c in caminos:
                corre = c["term"] is None and (i == 0 or (op == "&&" and c["st"] == "ok")
                                               or (op == "||" and c["st"] == "fail"))
                if not corre:
                    nuevos.append(c)
                    continue
                if clase == "exit":
                    distinto_de_cero = (c["st"] == "fail") if codigo is None else codigo
                    nuevos.append(dict(c, term="fallo" if distinto_de_cero else "ok", ej=c["ej"] + (i,)))
                    continue
                salidas = {"ok": ("ok",), "fail": ("fail",)}.get(clase, ("ok", "fail"))
                for s in salidas:
                    nuevos.append(dict(c, st=s, ej=c["ej"] + (i,), res=dict(c["res"], **{str(i): s})))
            caminos = nuevos
            if len(caminos) > MAX_CAMINOS:
                desborde = True
                break
        ultimo_i = len(info) - 1
        destinos = []
        for c in caminos:
            if term == "&":
                destinos.append("sigue")
            elif c["term"] == "ok":
                destinos.append("fin_ok")
            elif c["term"] == "fallo":
                destinos.append("fallo")
            elif c["st"] == "fail":
                fin_lista = bool(c["ej"]) and c["ej"][-1] == ultimo_i
                destinos.append("fallo" if (errexit and fin_lista) or ultima else "sigue_fallo")
            else:
                destinos.append("sigue")
        for i, (_, _, coincide, compuesto, _, negado) in enumerate(info):
            if not coincide:
                continue
            if negado:  # `! npm test`: su fallo se invierte en éxito
                res.append((n, NUNCA))
                continue
            if desborde:
                res.append((n, min(vivo, QUIZAS)))
                continue
            if term == "&":
                res.append((n, NUNCA))
                continue
            relevantes = [(c, d) for c, d in zip(caminos, destinos) if i in c["ej"] or d in ("fin_ok", "sigue")]
            ejecutan = [(c, d) for c, d in relevantes if i in c["ej"]]
            if not ejecutan:
                alcance = NUNCA
            elif len(ejecutan) == len(relevantes):
                alcance = SIEMPRE
            else:
                alcance = QUIZAS
            propaga = all(d == "fallo" for c, d in ejecutan if c["res"].get(str(i)) == "fail")
            hay_fallo = any(c["res"].get(str(i)) == "fail" for c, _ in ejecutan)
            if not propaga or not hay_fallo:
                cert = NUNCA
            else:
                cert = min(vivo, alcance, QUIZAS if compuesto else SIEMPRE)
            res.append((n, cert))
        for _, _, _, _, limpios, _ in info:
            errexit = _errexit_tras(limpios, errexit)
        if desborde:
            vivo = min(vivo, QUIZAS)
            continue
        siguen = [d for d in destinos if d == "sigue"]
        if not siguen:
            vivo = NUNCA
        elif "fin_ok" in destinos:
            vivo = min(vivo, QUIZAS)
    return res


def _certeza_paso(cmds, pred, errexit=True):
    return max((c for _, c in _ocurrencias(cmds, pred, errexit)), default=NUNCA)


# --- scripts de package.json (ronda 3) -------------------------------------------------------------------------------
GESTORES_SCRIPTS = frozenset({"npm", "pnpm", "yarn", "bun"})
FLAGS_CON_VALOR = frozenset({"--filter", "-F", "-C", "--dir", "--prefix", "-w", "--workspace", "--cwd", "--cache",
                             "--loglevel", "--reporter"})
BUILTINS_PNPM_YARN = frozenset({
    "install", "i", "add", "remove", "rm", "uninstall", "un", "up", "update", "upgrade", "exec", "dlx", "create",
    "init", "link", "unlink", "why", "outdated", "audit", "publish", "pack", "store", "config", "cache", "info",
    "list", "ls", "import", "rebuild", "rb", "prune", "fetch", "patch", "patch-commit", "deploy", "env", "setup",
    "workspace", "workspaces", "dedupe", "licenses", "global", "bin", "root", "node", "npm", "set", "plugin",
    "constraints", "version", "login", "logout", "tag", "dist-tag", "owner", "help", "ci", "approve-builds"})


def _script_llamado(toks):
    """Nombre del script de package.json que ejecuta `npm test`, `npm run X`, `pnpm X`, `yarn X`… o None."""
    toks = _sin_prefijos(toks)
    if not toks or toks[0] not in GESTORES_SCRIPTS:
        return None
    gestor = toks[0]
    args, saltar = [], False
    for t in toks[1:]:
        if saltar:
            saltar = False
            continue
        if t in FLAGS_CON_VALOR:
            saltar = True
            continue
        if t.startswith("-"):
            continue
        args.append(t)
    if not args:
        return None
    a = args[0]
    if a in ("run", "run-script", "rum", "urn"):
        return args[1] if len(args) > 1 else None
    if a in ("test", "t", "tst") and gestor != "bun":
        return "test"
    if a == "start" and gestor != "bun":
        return "start"
    if gestor in ("pnpm", "yarn") and a not in BUILTINS_PNPM_YARN:
        return a
    return None


RE_TARGET_MAKE = re.compile(r"^([A-Za-z0-9_.\-/]+(?:\s+[A-Za-z0-9_.\-/]+)*)\s*:(?![=:])\s*([^#=]*)")


def _targets(texto, recetas_con_tab=True):
    """{target: {"deps": [...], "receta": [líneas]}} de un Makefile (recetas con tabulador) o de un justfile (recetas
    indentadas con espacios o tabulador). Las líneas de continuación con «\\» se unen."""
    targets, actual, primero = {}, None, None
    lineas = texto.replace("\\\n", " ").splitlines()
    for linea in lineas:
        if linea.strip().startswith("#") or not linea.strip():
            continue
        if linea[:1] in ("\t", " ") and actual is not None:
            if recetas_con_tab and not linea.startswith("\t"):
                continue
            targets[actual]["receta"].append(linea.strip().lstrip("@-+").strip())
            continue
        m = RE_TARGET_MAKE.match(linea)
        actual = None
        if m and not linea.startswith((".PHONY", "export ", "define ")):
            nombres = m.group(1).split()
            deps = [d for d in re.split(r"\s+", m.group(2).strip()) if d and not d.startswith("$")]
            for nombre in nombres:
                targets.setdefault(nombre, {"deps": [], "receta": []})["deps"].extend(deps)
                primero = primero or nombre
            actual = nombres[0]
    if primero:
        targets.setdefault("", targets[primero])  # target por defecto (sin argumentos)
    return targets


def scripts_proyecto(proyecto):
    """{"hay_package_json": bool, "por_nombre": {script: [cuerpos]}, "make": {target: …} | None,
    "just": {receta: …} | None} de todos los package.json del proyecto y del Makefile / justfile de la raíz."""
    import json
    proyecto = Path(proyecto)
    make = just = None
    for nombre in ("GNUmakefile", "makefile", "Makefile"):
        if (proyecto / nombre).is_file():
            make = _targets(comun.leer(proyecto / nombre) or "")
    for nombre in ("justfile", "Justfile", ".justfile"):
        if (proyecto / nombre).is_file():
            just = _targets(comun.leer(proyecto / nombre) or "", recetas_con_tab=False)
    por_nombre, hay = {}, False
    for p in comun.recorrer(Path(proyecto), nombres={"package.json"}):
        hay = True
        try:
            datos = json.loads(comun.leer(p) or "")
        except json.JSONDecodeError:
            continue
        scripts = datos.get("scripts") if isinstance(datos, dict) else None
        if isinstance(scripts, dict):
            for k, v in scripts.items():
                if isinstance(v, str):
                    por_nombre.setdefault(k, []).append(v)
    return {"hay_package_json": hay, "por_nombre": por_nombre, "make": make, "just": just}


def _token_calidad(t):
    """Ronda 4 (PV-R3-07): un argumento cuenta como calidad solo si ES el nombre de la herramienta o del subcomando
    (`pytest`, `test`, `test:unit`, `scripts/test.js`), no si lo contiene (`generate-test-fixtures.js`,
    `deploy-test`, `print('tests ok')`)."""
    base = t.rsplit("/", 1)[-1]
    candidatos = {base, base.split(":", 1)[0], base.rsplit(".", 1)[0] if "." in base[1:] else base}
    # Ronda 6 (stack): un ARCHIVO de test por convención (`node test/dsp.test.mjs`, `python tests/test_api.py`) es
    # ejecutar tests; antes solo contaba `scripts/test.js` (COD-CI-BASICO falso positivo en bandas-cineticas).
    return any(c and RE_CALIDAD.fullmatch(c) for c in candidatos) or bool(RE_ARCHIVO_TEST_CONVENCION.fullmatch(base))


RE_ARCHIVO_TEST_CONVENCION = re.compile(r"[\w.-]+\.(?:test|spec)\.[cm]?[jt]sx?|test_\w+\.py|\w+_test\.(?:py|go)")


FLAGS_TEST_NODE = frozenset({"--test"})


def _target_calidad(toks, scripts, prof):
    """make/just (ronda 4, PV-R3-08): el target se lee del Makefile/justfile y cuenta solo si su receta (o la de un
    prerrequisito) ejecuta lint, typecheck o tests. Sin archivo, sin target, con -C/-f o con prof agotada → False."""
    gestor = toks[0].rsplit("/", 1)[-1]
    tabla = (scripts or {}).get("make" if gestor == "make" else "just")
    if not tabla or prof >= 3 or any(t in ("-C", "-f", "--file", "--directory", "--justfile") or
                                     t.startswith(("-C", "-f", "--file=", "--directory=", "--justfile="))
                                     for t in toks[1:]):
        return False
    pedidos = [t for t in toks[1:] if not t.startswith("-") and "=" not in t] or [""]
    vistos = set()

    def calidad_de(nombre, nivel):
        if nombre in vistos or nivel > 5 or nombre not in tabla:
            return False
        vistos.add(nombre)
        t = tabla[nombre]
        if any(calidad_de(d, nivel + 1) for d in t["deps"]):
            return True
        return any(_certeza_paso([(1, l)], lambda x: es_calidad(x, scripts, prof + 1), errexit=False) == SIEMPRE
                   for l in t["receta"])

    return any(calidad_de(n, 0) for n in pedidos)


def _es_comando_real(toks):
    return _clase_comando(toks)[0] == "otro" and bool(_sin_prefijos(toks))


def es_calidad(toks, scripts=None, prof=0):
    """True si el comando simple (tokens) ejecuta lint, typecheck o tests. Con `scripts` (scripts_proyecto) un
    `npm test` / `npm run X` cuenta solo si el script existe y hace algo (ronda 3)."""
    toks = _sin_prefijos(toks)
    if not toks:
        return False
    cmd = toks[0].rsplit("/", 1)[-1] if not toks[0].startswith("./") else toks[0]
    if cmd in NO_EJECUTAN:
        return False
    if RE_CALIDAD.fullmatch(cmd):
        return True
    args = [t for t in toks[1:6] if not t.startswith("-")]
    if cmd not in LANZADORES:
        # Ronda 4: CLI de framework con subcomando de calidad (react-scripts test, ng test, next lint, vue-cli-service
        # test:unit). Solo el primer argumento posicional, como nombre completo.
        return bool(args) and args[0] == toks[1] and _token_calidad(args[0])
    if cmd in ("make", "just"):
        return _target_calidad(toks, scripts, prof)
    nombre = _script_llamado(toks)
    if nombre is not None and scripts and scripts.get("hay_package_json"):
        for cuerpo in scripts["por_nombre"].get(nombre, []):
            if _certeza_paso([(1, cuerpo)], _es_comando_real, errexit=False) != SIEMPRE:
                continue  # script que no ejecuta nada (`echo no tests && exit 0`) o que enmascara su fallo
            # Ronda 4 (PV-R3-09): el NOMBRE del script («test») ya no basta: su cuerpo tiene que ejecutar lint,
            # typecheck o tests (`node --version` o `node -e 0` no cuentan).
            if prof < 3 and _certeza_paso([(1, cuerpo)], lambda t: es_calidad(t, scripts, prof + 1),
                                          errexit=False) == SIEMPRE:
                return True
        return False
    if cmd in ("node", "deno", "bun") and any(t in FLAGS_TEST_NODE for t in toks[1:]):
        return True  # node --test (runner de tests nativo)
    return any(_token_calidad(t) for t in args)


def ejecuta_calidad(comando, scripts=None):
    """True si la línea de shell EJECUTA SIEMPRE lint, typecheck o tests y su fallo hace fallar el paso (un echo, un
    printf, un comentario, `true || npm test` o `npm test || true` no cuentan)."""
    return _certeza_paso([(1, comando)], lambda t: es_calidad(t, scripts)) == SIEMPRE


# --- condiciones de GitHub Actions (`if:`) con lógica de tres valores (ronda 3) ---------------------------------------
_DESCONOCIDO = object()
RE_TOKEN_EXPR = re.compile(r"\s*(\|\||&&|==|!=|<=|>=|<|>|!|\(|\)|,|'(?:[^']|'')*'|\"[^\"]*\"|-?\d+(?:\.\d+)?"
                           r"|[A-Za-z_][\w.\-*]*(?:\[[^\]]*\][\w.\-*]*)*)")


def _tokens_expr(texto):
    tokens, pos = [], 0
    texto = texto.strip()
    while pos < len(texto):
        m = RE_TOKEN_EXPR.match(texto, pos)
        if not m or m.end() == pos:
            return None
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def _evaluar_expr(texto, evento):
    """True / False / _DESCONOCIDO para la condición con github.event_name = evento; None si no se puede leer."""
    tokens = _tokens_expr(texto)
    if not tokens:
        return None
    pos = [0]

    def ver():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def tomar():
        pos[0] += 1
        return tokens[pos[0] - 1]

    def verdad(v):
        if v is _DESCONOCIDO:
            return _DESCONOCIDO
        return bool(v) and v != 0

    def o():
        izq = y()
        while ver() == "||":
            tomar()
            der = y()
            vi, vd = verdad(izq), verdad(der)
            izq = True if (vi is True or vd is True) else (_DESCONOCIDO if _DESCONOCIDO in (vi, vd) else False)
        return izq

    def y():
        izq = unario()
        while ver() == "&&":
            tomar()
            der = unario()
            vi, vd = verdad(izq), verdad(der)
            izq = False if (vi is False or vd is False) else (_DESCONOCIDO if _DESCONOCIDO in (vi, vd) else True)
        return izq

    def unario():
        if ver() == "!":
            tomar()
            v = verdad(unario())
            return _DESCONOCIDO if v is _DESCONOCIDO else not v
        return comparacion()

    def comparacion():
        izq = primario()
        if ver() in ("==", "!=", "<", ">", "<=", ">="):
            op = tomar()
            der = primario()
            if _DESCONOCIDO in (izq, der):
                return _DESCONOCIDO
            a = izq.lower() if isinstance(izq, str) else izq
            b = der.lower() if isinstance(der, str) else der
            if op == "==":
                return a == b
            if op == "!=":
                return a != b
            return _DESCONOCIDO
        return izq

    def primario():
        t = tomar() if ver() is not None else None
        if t is None:
            raise ValueError("expresión incompleta")
        if t == "(":
            v = o()
            if ver() != ")":
                raise ValueError("paréntesis sin cerrar")
            tomar()
            return v
        if t[0] in "'\"":
            return t[1:-1].replace("''", "'")
        if re.fullmatch(r"-?\d+(?:\.\d+)?", t):
            return float(t)
        bajo = t.lower()
        if ver() == "(":
            tomar()
            prof = 1
            while prof and ver() is not None:
                x = tomar()
                prof += {"(": 1, ")": -1}.get(x, 0)
            if prof:
                raise ValueError("llamada sin cerrar")
            return {"always": True, "success": True, "cancelled": False, "failure": False}.get(bajo, _DESCONOCIDO)
        if bajo in ("true", "false"):
            return bajo == "true"
        if bajo == "null":
            return None
        if bajo == "github.event_name":
            return evento
        return _DESCONOCIDO

    try:
        v = verdad(o())
    except (ValueError, IndexError):
        return None
    if pos[0] != len(tokens):
        return None
    return v


def _certeza_condicion(valor, eventos):
    """Certeza de que un job/paso con `if: valor` corre (SIEMPRE / QUIZAS / NUNCA) en alguno de los eventos."""
    if valor is None:
        return SIEMPRE
    v = valor.split(" #", 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1].strip()
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", v, re.S)
    v = m.group(1) if m else v
    if not v:
        return SIEMPRE
    resultados = [_evaluar_expr(v, e) for e in sorted(eventos or EVENTOS_CI)]
    if any(r is True for r in resultados):
        return SIEMPRE
    if resultados and all(r is False for r in resultados):
        return NUNCA
    return QUIZAS


def _certeza_continue_on_error(valor):
    """continue-on-error: ausente/false → SIEMPRE (el fallo bloquea); true → NUNCA; expresión → QUIZAS."""
    if valor is None:
        return SIEMPRE
    v = valor.split(" #", 1)[0].strip().strip("'\"").strip()
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", v)
    v = (m.group(1) if m else v).strip().lower()
    if v in ("false", "0", ""):
        return SIEMPRE
    if v in ("true", "1"):
        return NUNCA
    return QUIZAS


def _certeza_shell(valor):
    if valor is None:
        return SIEMPRE
    v = valor.split(" #", 1)[0].strip().strip("'\"").strip()
    return SIEMPRE if v in ("bash", "sh") or v.startswith(("bash ", "sh ")) else QUIZAS


def _valor_desactivado(valor):
    """Compatibilidad (ronda 2): True si la condición es literalmente falsa."""
    return _certeza_condicion(valor, EVENTOS_CI) == NUNCA


# --- disparadores y filtros (ronda 3) --------------------------------------------------------------------------------
def _flujo(texto):
    """Lee una colección YAML en flujo ({a: {b: [x, y]}}, [a, b]) o un escalar. Devuelve dict / list / str / None."""
    pos = [0]
    s = texto.strip()

    def esp():
        while pos[0] < len(s) and s[pos[0]] in " \t\n":
            pos[0] += 1

    def escalar(fin):
        esp()
        if pos[0] < len(s) and s[pos[0]] in "'\"":
            q = s[pos[0]]
            j = s.index(q, pos[0] + 1)
            v = s[pos[0] + 1:j]
            pos[0] = j + 1
            return v
        j = pos[0]
        while j < len(s) and s[j] not in fin:
            j += 1
        v = s[pos[0]:j].strip()
        pos[0] = j
        return v if v not in ("", "null", "~") else None

    def valor(fin):
        esp()
        if pos[0] < len(s) and s[pos[0]] == "{":
            pos[0] += 1
            d = {}
            while True:
                esp()
                if pos[0] < len(s) and s[pos[0]] == "}":
                    pos[0] += 1
                    return d
                k = escalar(":,}")
                esp()
                v = None
                if pos[0] < len(s) and s[pos[0]] == ":":
                    pos[0] += 1
                    v = valor(",}")
                if k is not None:
                    d[k] = v
                esp()
                if pos[0] < len(s) and s[pos[0]] == ",":
                    pos[0] += 1
                elif pos[0] >= len(s):
                    return d
        if pos[0] < len(s) and s[pos[0]] == "[":
            pos[0] += 1
            lista = []
            while True:
                esp()
                if pos[0] < len(s) and s[pos[0]] == "]":
                    pos[0] += 1
                    return lista
                v = valor(",]")
                if v is not None:
                    lista.append(v)
                esp()
                if pos[0] < len(s) and s[pos[0]] == ",":
                    pos[0] += 1
                elif pos[0] >= len(s):
                    return lista
        return escalar(fin)

    try:
        return valor("")
    except (ValueError, IndexError):
        return None


def _lista_de(v):
    if v is None:
        return None
    if isinstance(v, list):
        return [str(x) for x in v if x is not None]
    if isinstance(v, dict):
        return list(v)
    return [str(v)]


def _bloque_lista(lineas, k, nivel):
    """Lista YAML (en flujo o en bloque `- x`) del valor de la clave de la línea k (nivel = su indentación)."""
    resto = lineas[k].split(":", 1)[1].split(" #", 1)[0].strip()
    if resto:
        return _lista_de(_flujo(resto))
    valores = []
    for l in lineas[k + 1:]:
        if not l.strip() or l.strip().startswith("#"):
            continue
        if _indent(l) <= nivel:
            break
        m = re.match(r"^\s*-\s*(.*)$", l)
        if m:
            v = m.group(1).split(" #", 1)[0].strip()
            valores.append(v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v)
    return valores


def disparadores_detalle(lineas):
    """{evento: {filtro: [patrones]}} de `on:` (en línea, lista, mapa en flujo o bloque); {} si no hay `on:`."""
    for i, linea in enumerate(lineas):
        m = re.match(r"""^(?:on|"on"|'on'|true)\s*:(.*)$""", linea)
        if not m:
            continue
        resto = m.group(1).split(" #", 1)[0].strip()
        if resto:
            v = _flujo(resto)
            if isinstance(v, dict):
                return {str(e): ({k: _lista_de(x) for k, x in f.items()} if isinstance(f, dict) else {})
                        for e, f in v.items()}
            return {e: {} for e in (_lista_de(v) or [])}
        eventos, nivel, actual, nivel_filtro = {}, None, None, None
        for k in range(i + 1, len(lineas)):
            l = lineas[k]
            if not l.strip() or l.strip().startswith("#"):
                continue
            if _indent(l) == 0:
                break
            nivel = _indent(l) if nivel is None else nivel
            if _indent(l) == nivel:
                mm = re.match(r"^\s*(?:-\s*)?['\"]?([\w-]+)['\"]?\s*(:|$)", l)
                if mm:
                    actual = mm.group(1)
                    eventos[actual] = {}
                    resto_ev = l.split(":", 1)[1].split(" #", 1)[0].strip() if mm.group(2) == ":" else ""
                    if resto_ev.startswith("{"):
                        f = _flujo(resto_ev)
                        if isinstance(f, dict):
                            eventos[actual] = {kk: _lista_de(x) for kk, x in f.items()}
                    nivel_filtro = None
                continue
            if actual is None:
                continue
            nivel_filtro = _indent(l) if nivel_filtro is None else nivel_filtro
            if _indent(l) == nivel_filtro:
                mf = re.match(r"^\s*([\w-]+)\s*:", l)
                if mf:
                    eventos[actual][mf.group(1)] = _bloque_lista(lineas, k, nivel_filtro)
        return eventos
    return {}


def disparadores(lineas):
    """Eventos de `on:` (en línea, lista, mapa en flujo o bloque). Vacío si no hay `on:`."""
    return set(disparadores_detalle(lineas))


def _regex_glob(patron):
    """Patrón de filtro de GitHub Actions (* no cruza «/», ** sí) → regex."""
    salida, i = "", 0
    while i < len(patron):
        if patron.startswith("**", i):
            salida += ".*"
            i += 2
        elif patron[i] == "*":
            salida += "[^/]*"
            i += 1
        elif patron[i] == "?":
            salida += "."
            i += 1
        else:
            salida += re.escape(patron[i])
            i += 1
    return re.compile(salida + r"\Z")


def _coincide_filtro(patrones, valor):
    ok = False
    for p in patrones:
        neg = p.startswith("!")
        if _regex_glob(p[1:] if neg else p).match(valor):
            ok = not neg
    return ok


class _Contexto:
    """Ramas y archivos del proyecto para evaluar filtros (perezoso)."""

    def __init__(self, proyecto):
        self.proyecto = Path(proyecto)
        self._ramas = None
        self._archivos = None

    @property
    def ramas(self):
        if self._ramas is None:
            ramas = {"main", "master"}
            try:
                import git_seguro
                cod, salida = git_seguro.ejecutar(self.proyecto, "for-each-ref", "--format=%(refname:short)",
                                                  "refs/heads", "refs/remotes")
                if cod == 0 and salida:
                    for r in salida.split():
                        ramas.add(r.split("/", 1)[1] if r.startswith("origin/") else r)
            except ImportError:
                pass
            self._ramas = sorted(ramas)
        return self._ramas

    @property
    def archivos(self):
        if self._archivos is None:
            lista = []
            for p in comun.recorrer(self.proyecto):
                lista.append(comun.rel(self.proyecto, p))
                if len(lista) >= 50_000:
                    break
            self._archivos = lista
        return self._archivos


def _certeza_evento(filtros, ctx):
    """Certeza de que el evento se dispara en el uso normal del repositorio según sus filtros."""
    cert = SIEMPRE
    if not filtros:
        return cert
    ramas = filtros.get("branches")
    if ramas is not None and not any(_coincide_filtro(ramas, r) for r in ctx.ramas):
        cert = QUIZAS
    ignorar = filtros.get("branches-ignore")
    if ignorar is not None and all(_coincide_filtro(ignorar, r) for r in ctx.ramas):
        cert = QUIZAS
    if filtros.get("tags") is not None and ramas is None:
        cert = QUIZAS  # solo etiquetas: no corre en cada push
    rutas = filtros.get("paths")
    if rutas is not None and not any(_coincide_filtro(rutas, a) for a in ctx.archivos):
        cert = QUIZAS
    ign_rutas = filtros.get("paths-ignore")
    if ign_rutas is not None and all(_coincide_filtro(ign_rutas, a) for a in ctx.archivos):
        cert = QUIZAS
    return cert


def _certeza_workflow(texto, ctx):
    """(certeza, eventos activos): la máxima de sus eventos de push / PR, según sus filtros."""
    detalle = disparadores_detalle(texto.splitlines())
    activos = {e: f for e, f in detalle.items() if e in EVENTOS_CI}
    if not activos:
        return NUNCA, set()
    return max(_certeza_evento(f or {}, ctx) for f in activos.values()), set(activos)


# --- jobs y pasos -----------------------------------------------------------------------------------------------------
def _jobs(lineas):
    """[(nombre, ini, fin)] (0-based, [ini, fin) = cuerpo del job) dentro del bloque raíz `jobs:`."""
    raiz = [n for n, l in enumerate(lineas) if l and not l[0].isspace() and not l.startswith("#")]
    ini_jobs = next((n for n in raiz if re.match(r"^jobs\s*:", lineas[n])), None)
    if ini_jobs is None:
        return []
    fin_jobs = next((n for n in raiz if n > ini_jobs), len(lineas))
    utiles_ = [n for n in range(ini_jobs + 1, fin_jobs) if lineas[n].strip() and not lineas[n].strip().startswith("#")]
    if not utiles_:
        return []
    nivel = min(_indent(lineas[n]) for n in utiles_)
    cabeceras = [n for n in utiles_ if _indent(lineas[n]) == nivel and re.match(r"\s*[\w-]+\s*:", lineas[n])]
    res = []
    for k, n in enumerate(cabeceras):
        hasta = cabeceras[k + 1] if k + 1 < len(cabeceras) else fin_jobs
        res.append((lineas[n].strip().split(":", 1)[0], n + 1, hasta))
    return res


def _clave_en_nivel(lineas, ini, fin, clave):
    """Valor de `clave:` en el nivel más externo del bloque [ini, fin), o None."""
    utiles_ = [n for n in range(ini, fin) if lineas[n].strip() and not lineas[n].strip().startswith("#")]
    if not utiles_:
        return None
    nivel = min(_indent(lineas[n]) for n in utiles_)
    for n in utiles_:
        m = re.match(r"^\s*" + re.escape(clave) + r"\s*:\s*(.*)$", lineas[n])
        if m and _indent(lineas[n]) == nivel:
            return m.group(1)
    return None


def _clave_del_paso(lineas, n_run, ini_job, clave):
    """Valor de `clave:` del paso (elemento de lista) que contiene la línea n_run (0-based), o None."""
    k = n_run
    while k >= ini_job:
        m = re.match(r"^(\s*)-\s+", lineas[k])
        if m and (k == n_run or _indent(lineas[k]) < _indent(lineas[n_run])):
            break
        k -= 1
    if k < ini_job:
        return None
    item = _indent(lineas[k])
    col = len(re.match(r"^(\s*-\s+)", lineas[k]).group(1))
    fin = k + 1
    while fin < len(lineas) and (not lineas[fin].strip() or _indent(lineas[fin]) > item):
        fin += 1
    for j in range(k, fin):
        linea = lineas[j]
        texto = linea[col:] if j == k else linea
        if j == k or _indent(linea) == col:
            m = re.match(r"^\s*" + re.escape(clave) + r"\s*:\s*(.*)$", texto)
            if m:
                return m.group(1)
    return None


def _paso_desactivado(lineas, n_run, ini_job):
    """Compatibilidad (ronda 2): True si el paso tiene `if:` literalmente falso."""
    return _valor_desactivado(_clave_del_paso(lineas, n_run, ini_job, "if") or "true")


def _certeza_job(lineas, ini, fin, eventos):
    return min(_certeza_condicion(_clave_en_nivel(lineas, ini, fin, "if"), eventos),
               _certeza_continue_on_error(_clave_en_nivel(lineas, ini, fin, "continue-on-error")))


def pasos_efectivos(texto, eventos=EVENTOS_CI):
    """[(certeza, [(n, comando)])] de cada `run:` de cada job, con la certeza de que corre y de que su fallo bloquea
    (if:, continue-on-error y shell del job y del paso; ronda 3). Sin las líneas de comentario."""
    lineas = texto.splitlines()
    salida = []
    for _, ini, fin in _jobs(lineas):
        c_job = _certeza_job(lineas, ini, fin, eventos)
        if c_job == NUNCA:
            continue
        for i_run, cmds in _pasos_de(lineas, ini, fin):
            c_paso = min(_certeza_condicion(_clave_del_paso(lineas, i_run, ini, "if"), eventos),
                         _certeza_continue_on_error(_clave_del_paso(lineas, i_run, ini, "continue-on-error")),
                         _certeza_shell(_clave_del_paso(lineas, i_run, ini, "shell")))
            if c_paso == NUNCA:
                continue
            cmds = [(n, c) for n, c in cmds if not c.lstrip().startswith("#")]
            if cmds:
                salida.append((min(c_job, c_paso), cmds))
    return salida


def runs_efectivos(texto):
    """[(n, comando)] de los `run:` que pueden ejecutarse: fuera de jobs o pasos con `if:` falso o continue-on-error
    verdadero y sin comentarios."""
    return [x for _, cmds in pasos_efectivos(texto) for x in cmds]


def _reutilizables(texto, eventos):
    """[(workflow local llamado, certeza del job que lo llama)] (`uses: ./.github/workflows/…`)."""
    lineas = texto.splitlines()
    res = []
    for _, ini, fin in _jobs(lineas):
        c_job = _certeza_job(lineas, ini, fin, eventos)
        if c_job == NUNCA:
            continue
        uses = _clave_en_nivel(lineas, ini, fin, "uses")
        if uses:
            u = uses.split(" #", 1)[0].strip().strip("'\"")
            if u.startswith("./.github/workflows/"):
                res.append((u[len("./"):].split("@", 1)[0], c_job))
    return res


def reutilizables_llamados(texto):
    """Workflows locales que llaman los jobs activos (`uses: ./.github/workflows/x.yml`)."""
    return {u for u, _ in _reutilizables(texto, EVENTOS_CI)}


def pasos_ci(proyecto):
    """([(archivo, certeza, [(n, comando)])], [workflows leídos]) de los pasos de los workflows que corren en push/PR
    (directamente o como workflow reutilizable llamado por uno de ellos)."""
    proyecto = Path(proyecto)
    textos = {}
    for p in _archivos(proyecto):
        t = comun.leer(p)
        if t is not None:
            textos[fb.rel(proyecto, p)] = t
    ctx = _Contexto(proyecto)
    cert, eventos = {}, {}
    for a, t in textos.items():
        cert[a], eventos[a] = _certeza_workflow(t, ctx)
    cambio = True
    while cambio:
        cambio = False
        for a in sorted(textos):
            if cert[a] == NUNCA:
                continue
            for llamado, c_job in _reutilizables(textos[a], eventos[a] or EVENTOS_CI):
                nuevo = min(cert[a], c_job)
                if llamado in textos and nuevo > cert[llamado]:
                    cert[llamado], eventos[llamado] = nuevo, eventos[llamado] | eventos[a]
                    cambio = True
    pasos = []
    for a in sorted(textos):
        if cert[a] == NUNCA:
            continue
        for c, cmds in pasos_efectivos(textos[a], eventos[a] or EVENTOS_CI):
            pasos.append((a, min(cert[a], c), cmds))
    return pasos, sorted(textos)


def comandos_ci(proyecto):
    """[(archivo, n, comando)] de los `run:` que pueden ejecutarse en los workflows que corren en push/PR."""
    pasos, leidos = pasos_ci(proyecto)
    return [(a, n, c) for a, cert, cmds in pasos if cert > NUNCA for n, c in cmds], leidos


def evaluar_ci(proyecto, pred, errexit=True):
    """(True | None | False, (archivo, n) de la primera aparición que cuenta, [workflows leídos]).
    True: algún comando que cumple `pred` corre SIEMPRE en push/PR y su fallo hace fallar el CI. None: solo hay
    apariciones dudosas (filtros que no coinciden, `if:` desconocido, continue-on-error con expresión…): ni pase ni
    hallazgo. False: ninguna aparición cuenta."""
    pasos, leidos = pasos_ci(proyecto)
    mejor, donde = NUNCA, None
    for a, c, cmds in pasos:
        if c == NUNCA:
            continue
        for n, cert in _ocurrencias(cmds, pred, errexit):
            cc = min(c, cert)
            if cc > mejor:
                mejor, donde = cc, (a, n)
    return (True if mejor == SIEMPRE else None if mejor == QUIZAS else False), donde, leidos


def analizar_archivo(arch, texto, hallazgos):
    lineas = texto.splitlines()

    def h(sub, n, mensaje, ev, sev):
        hallazgos.append(comun.hallazgo(NOMBRE, sub, arch, n, mensaje, ev, sev))

    raiz = {}
    for n, linea in enumerate(lineas, 1):
        if linea and not linea[0].isspace() and not linea.startswith("#"):
            m = RE_CLAVE_RAIZ.match(linea)
            if m:
                raiz.setdefault((m.group(1) or m.group(2) or m.group(3)), n)
    if not any(k in raiz for k in ("on", "true")):
        h("sin_on", 1, "El workflow no declara `on:` (disparadores).", arch, "media")
    if "jobs" not in raiz:
        h("sin_jobs", 1, "El workflow no declara `jobs:`.", arch, "media")
    else:
        inicio = raiz["jobs"]
        fin = min([v for v in raiz.values() if v > inicio] or [len(lineas) + 1])
        bloque = [(n, lineas[n - 1]) for n in range(inicio + 1, fin) if lineas[n - 1].strip()
                  and not lineas[n - 1].strip().startswith("#") and "\t" not in lineas[n - 1][:_indent(lineas[n - 1])]]
        if bloque:
            nivel_job = min(_indent(l) for _, l in bloque)
            jobs = [(n, l) for n, l in bloque if _indent(l) == nivel_job and re.match(r"\s*[\w-]+\s*:", l)]
            for k, (n, l) in enumerate(jobs):
                hasta = jobs[k + 1][0] if k + 1 < len(jobs) else fin
                cuerpo = [x for m_, x in bloque if n < m_ < hasta]
                nivel = min((_indent(x) for x in cuerpo), default=None)
                claves = {re.match(r"\s*([\w-]+)\s*:", x).group(1) for x in cuerpo
                          if nivel is not None and _indent(x) == nivel and re.match(r"\s*[\w-]+\s*:", x)}
                if not ({"runs-on", "uses"} & claves):
                    h("job_sin_runs_on", n, f"El job «{l.strip().rstrip(':')}» no tiene `runs-on:` ni `uses:`.", l.strip(), "media")
    for n, linea in enumerate(lineas, 1):
        if linea.strip().startswith("#"):
            continue
        if "\t" in linea[:_indent(linea)]:
            h("tabulador", n, "Tabulador en la indentación: YAML inválido.", linea.replace("\t", "\\t").strip(), "media")
        if linea.count("${{") != linea.count("}}"):
            h("expresion_mal_cerrada", n, "Expresión `${{ … }}` sin cerrar o con llaves desbalanceadas.", linea.strip(), "media")
        m = re.match(r"\s*runs-on\s*:\s*\[?\s*['\"]?([\w.-]+)", linea)
        if m and m.group(1) in RUNNERS_OBSOLETOS:
            h("runner_obsoleto", n, f"Runner {m.group(1)} retirado o en retiro por GitHub.", linea.strip(), "baja")
    return any(ejecuta_calidad(t) for _, t in runs_efectivos(texto)) and bool(disparadores(lineas) & EVENTOS_CI)


def _archivos(proyecto):
    proyecto = Path(proyecto)
    return [p for p in fb.recorrer(proyecto, {".yml", ".yaml"}, desde=".github/workflows")
            if p.parent == proyecto / ".github" / "workflows"]


def calidad_ci(proyecto):
    """(True | None | False, [workflows leídos]): True si algún `run:` de un workflow de push/PR ejecuta SIEMPRE lint,
    typecheck o tests y su fallo hace fallar el CI; None si solo hay apariciones dudosas (ni pase ni hallazgo); False
    si ninguna cuenta. Comprobación semántica compartida con archivos_clave (pase de COD-CI-BASICO). Ronda 2: no
    cuentan echo/printf, comentarios, jobs o pasos con `if: false` ni workflows que solo se disparan a mano o por
    calendario. Ronda 3: cortocircuito y enmascarado de shell, heredocs, continue-on-error, `if:` y filtros de los
    disparadores, y scripts de package.json inexistentes o vacíos."""
    scripts = scripts_proyecto(proyecto)
    tri, _, leidos = evaluar_ci(proyecto, lambda toks: es_calidad(toks, scripts))
    return tri, leidos


def analizar(proyecto, crudo=None, solo_calidad=False):
    proyecto = Path(proyecto)
    archivos = _archivos(proyecto)
    if not archivos:
        return fb.resultado(REEMPLAZA, estado="no_aplica", motivo="no hay .github/workflows/*.yml")
    hallazgos = []
    for p in archivos:
        texto = comun.leer(p)
        if texto is not None:
            analizar_archivo(fb.rel(proyecto, p), texto, hallazgos)
    calidad = calidad_ci(proyecto)[0]
    pases = []
    motivo_dudoso = None
    if solo_calidad:
        hallazgos = []  # la sintaxis la valida la herramienta real (actionlint)
    elif not hallazgos:
        pases.append(fb.pase(NOMBRE, "sintaxis", f"{len(archivos)} workflows con estructura mínima válida"))
    if calidad is True:
        pases.append(fb.pase(NOMBRE, "ci_calidad", "Algún `run:` ejecuta lint, typecheck o tests"))
    elif calidad is None:
        motivo_dudoso = ("lint/typecheck/tests aparecen en el CI solo en condiciones dudosas (filtros branches/paths "
                         "que no coinciden, `if:` no evaluable, continue-on-error con expresión o fuera de un "
                         "if/while): no se puede afirmar que corran y bloqueen en cada push o PR")
    else:
        hallazgos.append(comun.hallazgo(NOMBRE, "ci_sin_calidad", fb.rel(proyecto, archivos[0]), None,
                                        "Ningún paso `run:` que se ejecute en push o pull_request corre lint, "
                                        "typecheck ni tests de forma que su fallo haga fallar el CI (no cuentan "
                                        "echo/printf, comentarios, heredocs, `true || npm test`, `npm test || true`, "
                                        "continue-on-error, jobs o pasos con `if:` falso, scripts de package.json "
                                        "vacíos o inexistentes ni workflows manuales o programados).",
                                        ", ".join(fb.rel(proyecto, p) for p in archivos[:3]), "media"))
    res = fb.resultado(REEMPLAZA, hallazgos, pases)
    if motivo_dudoso:
        res["motivo"] = motivo_dudoso
    if solo_calidad:
        res["motivo"] = ((motivo_dudoso + "; ") if motivo_dudoso else "") + (
            "actionlint disponible: solo se evaluó la calidad del CI (lint/typecheck/tests); "
            "la sintaxis la valida actionlint")
    return res


def main(argv=None):
    """Como fallback.main, pero con la herramienta real disponible NO se omite: corre la parte semántica."""
    def envoltura(proyecto, crudo=None):
        real = fb.herramienta_real_disponible(crudo, HERRAMIENTAS_REALES)
        return analizar(proyecto, crudo=crudo, solo_calidad=bool(real))
    return comun.main_check(NOMBRE, envoltura, argv, argumentos=lambda p, c: {"crudo": c})


if __name__ == "__main__":
    sys.exit(main())
