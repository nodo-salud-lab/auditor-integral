#!/usr/bin/env python3
"""complejidad — fallback de lizard (DECISIONES #6; investigacion/13 §4.9). Cobertura parcial.

Python: `ast` (McCabe): 1 + if/elif, for, async for, while, except, expresión condicional, cada `for` e
`if` de comprensiones, case de match, assert, y (n-1) por cada and/or. Las funciones anidadas se
miden aparte (no suman a la externa).
JS/TS/JSX/TSX (heurística): se quitan comentarios y cadenas (conservando saltos de línea), se detectan
funciones (function, métodos, flechas con llaves), se delimita el cuerpo por llaves y se cuenta
if/for/while/case/catch/&&/||/??/ternario, excluyendo funciones anidadas; como lizard, cada parámetro
con valor por defecto suma 1. Las flechas sin llaves no se miden (limitación declarada).
En .tsx/.jsx (Anexo C, M-05) los condicionales dentro del JSX ({c && <X/>}, {a ? <A/> : <B/>}) no
suman: son renderizado condicional; los callbacks con llaves dentro del JSX se miden aparte.

Subregla          sev                                  → control
  ccn_alta         baja (media si > 2× umbral)          → COD-COMPLEJIDAD
  funcion_larga    info (> 80 líneas; ESTIMACIÓN)
  archivo_grande   info (> 500 líneas de código; ESTIMACIÓN)
Pase ok_ccn con el resumen (funciones, CCN máx y media). Umbral: umbral.complejidad_ciclomatica_max
(15 = DEFAULT_CCN_THRESHOLD de lizard). Uso: complejidad.py PROYECTO DIR_CRUDO
"""
import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "complejidad"
REEMPLAZA = "lizard"
HERRAMIENTAS_REALES = ("lizard",)
EXT_JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
EXT_JSX = {".jsx", ".tsx"}
LARGO_FUNCION = 80
LARGO_ARCHIVO = 500
NO_FUNCIONES = {"if", "for", "while", "switch", "catch", "function", "return", "with", "else", "do", "try", "new",
                "typeof", "await", "yield", "super", "constructor_"}


# --- Python ---------------------------------------------------------------------------------------
class _Contador(ast.NodeVisitor):
    def __init__(self):
        self.ccn = 1

    def generic_visit(self, nodo):
        if isinstance(nodo, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)):
            self.ccn += 1
        elif isinstance(nodo, ast.comprehension):
            self.ccn += 1 + len(nodo.ifs)
        elif isinstance(nodo, ast.BoolOp):
            self.ccn += len(nodo.values) - 1
        elif hasattr(ast, "match_case") and isinstance(nodo, ast.match_case):
            self.ccn += 1
        super().generic_visit(nodo)

    def visit_FunctionDef(self, nodo):  # anidadas: se miden aparte
        pass

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef


def funciones_python(ruta, texto):
    try:
        arbol = ast.parse(texto, filename=str(ruta))
    except (SyntaxError, ValueError):
        return []
    salida = []
    for nodo in ast.walk(arbol):
        if isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef)):
            c = _Contador()
            for hijo in nodo.body:
                c.visit(hijo)
            salida.append({"nombre": nodo.name, "linea": nodo.lineno, "ccn": c.ccn,
                           "lineas": (getattr(nodo, "end_lineno", nodo.lineno) or nodo.lineno) - nodo.lineno + 1})
    return sorted(salida, key=lambda f: f["linea"])


# --- JS / TS --------------------------------------------------------------------------------------
RE_LIMPIAR = re.compile(r"/\*.*?\*/|//[^\n]*|`(?:\\.|[^`\\])*`|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)
RE_FUNCION = re.compile(r"\bfunction\b\s*\*?\s*([\w$]*)\s*\(")
RE_FLECHA = re.compile(r"(?:([\w$]+)\s*[:=]\s*)?(?:async\s+)?(?:<[^<>(){};=]*>\s*)?(\([^()]*(?:\([^()]*\)[^()]*)*\)|[\w$]+)\s*(?::\s*[^=;{}()]+)?=>\s*\{")
RE_METODO = re.compile(r"(?m)^[ \t]*(?:(?:public|private|protected|static|async|get|set|override|readonly)\s+)*\*?\s*"
                       r"([\w$]+)\s*(\([^()]*(?:\([^()]*\)[^()]*)*\))\s*(?::\s*[^{;=]+)?\{")
RE_DECISION = re.compile(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?\?(?!=)|\?(?![.?:])")
RE_DEFECTO = re.compile(r"(?<![=!<>])=(?![=>])")


RE_TEXTO_JSX = re.compile(r"(<[A-Za-z][\w.:-]*(?:\s[^<>]*)?>|</[A-Za-z][\w.:-]*>)([^<>{}]*)")


def _neutralizar_texto_jsx(texto):
    """Comillas sueltas en texto JSX (<p>Don't</p>) abrirían una cadena falsa: se reemplazan por espacio.
    Solo en segmentos tras una etiqueta que no parecen código (sin ; = ( ) [ ])."""
    def repl(m):
        seg = m.group(2)
        if re.search(r"[;=()\[\]]", seg):
            return m.group(0)
        return m.group(1) + re.sub(r"['\"`]", " ", seg)
    return RE_TEXTO_JSX.sub(repl, texto)


def limpiar_js(texto):
    texto = _neutralizar_texto_jsx(texto)
    return RE_LIMPIAR.sub(lambda m: "''" + "\n" * m.group(0).count("\n"), texto)


def _cierre(texto, abre):
    prof = 0
    for i in range(abre, len(texto)):
        c = texto[i]
        if c == "{":
            prof += 1
        elif c == "}":
            prof -= 1
            if prof == 0:
                return i
    return len(texto) - 1


def _params(texto, pos_parentesis):
    """Texto entre el '(' en pos y su ')' correspondiente."""
    prof = 0
    for i in range(pos_parentesis, len(texto)):
        if texto[i] == "(":
            prof += 1
        elif texto[i] == ")":
            prof -= 1
            if prof == 0:
                return texto[pos_parentesis + 1:i]
    return ""


# --- JSX (Anexo C, M-05): los condicionales del JSX ({c && <X/>}, {a ? <A/> : <B/>}) son renderizado
# condicional, no ramas de la lógica del componente: en .tsx/.jsx no suman al CCN de la función.
RE_JSX_PREVIO = re.compile(r"(?:[(=,?:{\[&|>]|\breturn)\s*$")
RE_JSX_INICIO = re.compile(r"<(?:>|[A-Za-z_$][\w$.:-]*(?=[\s/>]))")


def _es_inicio_jsx(t, i):
    if t[i] != "<" or not RE_JSX_INICIO.match(t, i):
        return False
    m = re.match(r"<([A-Za-z_$][\w$]*)\s+extends\b", t[i:i + 80])
    if m:  # genérico <T extends X>
        return False
    return bool(RE_JSX_PREVIO.search(t[max(0, i - 40):i]))


def _expr_jsx(t, i, rangos, n):
    """t[i] == '{': devuelve el índice de su '}' registrando los elementos JSX anidados; None si no cierra."""
    prof = 0
    while i < n:
        c = t[i]
        if c == "{":
            prof += 1
        elif c == "}":
            prof -= 1
            if prof == 0:
                return i
        elif c == "<" and _es_inicio_jsx(t, i):
            fin = _elemento_jsx(t, i, rangos, n)
            if fin is None:
                return None
            i = fin
        i += 1
    return None


def _elemento_jsx(t, i, rangos, n):
    """t[i] == '<' de un elemento JSX: índice de su último '>' (y lo registra en rangos); None si no cierra."""
    inicio = i
    i += 1
    # etiqueta de apertura con atributos
    while i < n:
        c = t[i]
        if c == "{":
            fin = _expr_jsx(t, i, rangos, n)
            if fin is None:
                return None
            i = fin
        elif c == "/" and i + 1 < n and t[i + 1] == ">":
            rangos.append((inicio, i + 1))
            return i + 1
        elif c == ">":
            break
        i += 1
    else:
        return None
    i += 1
    # hijos hasta el cierre
    while i < n:
        c = t[i]
        if c == "{":
            fin = _expr_jsx(t, i, rangos, n)
            if fin is None:
                return None
            i = fin
        elif c == "<" and i + 1 < n and t[i + 1] == "/":
            fin = t.find(">", i)
            if fin < 0:
                return None
            rangos.append((inicio, fin))
            return fin
        elif c == "<" and RE_JSX_INICIO.match(t, i):
            fin = _elemento_jsx(t, i, rangos, n)
            if fin is None:
                return None
            i = fin
        i += 1
    return None


def rangos_jsx(t):
    """Rangos [inicio, fin] de los elementos JSX (también los anidados en expresiones) de un texto limpio."""
    rangos, i, n = [], 0, len(t)
    while i < n:
        if t[i] == "<" and _es_inicio_jsx(t, i):
            fin = _elemento_jsx(t, i, rangos, n)
            if fin is not None:
                i = fin
        i += 1
    return rangos


def funciones_js(texto, jsx=False):
    t = limpiar_js(texto)
    jsx_rangos = rangos_jsx(t) if jsx else []
    candidatas = {}
    for m in RE_FUNCION.finditer(t):
        p_ini = m.end() - 1
        params = _params(t, p_ini)
        abre = t.find("{", p_ini + len(params) + 2)
        if abre < 0:
            continue
        candidatas.setdefault(abre, (m.group(1) or "<anónima>", m.start(), params))
    for m in RE_FLECHA.finditer(t):
        p = m.group(2)
        candidatas.setdefault(m.end() - 1, (m.group(1) or "<flecha>", m.start(), p[1:-1] if p.startswith("(") else ""))
    for m in RE_METODO.finditer(t):
        if m.group(1) in NO_FUNCIONES:
            continue
        candidatas.setdefault(m.end() - 1, (m.group(1), m.start(1), m.group(2)[1:-1]))
    funcs = []
    for abre, (nombre, inicio, params) in candidatas.items():
        funcs.append({"nombre": nombre, "inicio": inicio, "abre": abre, "cierra": _cierre(t, abre), "params": params})
    funcs.sort(key=lambda f: f["abre"])
    salida = []
    for f in funcs:
        anidadas = [(g["abre"], g["cierra"]) for g in funcs if f["abre"] < g["abre"] <= f["cierra"]]
        cuerpo = list(t[f["abre"]:f["cierra"] + 1])
        for a, c in anidadas:
            for i in range(a - f["abre"], min(c - f["abre"] + 1, len(cuerpo))):
                if cuerpo[i] != "\n":
                    cuerpo[i] = " "
        for a, c in jsx_rangos:  # JSX que empieza dentro de esta función (no el que la contiene)
            if f["abre"] < a <= f["cierra"]:
                for i in range(a - f["abre"], min(c - f["abre"] + 1, len(cuerpo))):
                    if cuerpo[i] != "\n":
                        cuerpo[i] = " "
        cuerpo = "".join(cuerpo)
        # parámetros por defecto (nivel superior y desestructuración), como lizard
        defectos = len(RE_DEFECTO.findall(f["params"]))
        ccn = 1 + len(RE_DECISION.findall(cuerpo)) + defectos
        linea = t.count("\n", 0, f["inicio"]) + 1
        fin = t.count("\n", 0, f["cierra"]) + 1
        salida.append({"nombre": f["nombre"], "linea": linea, "ccn": ccn, "lineas": fin - linea + 1})
    return salida


def lineas_codigo(texto, es_py):
    if es_py:
        return sum(1 for l in texto.splitlines() if l.strip() and not l.strip().startswith("#"))
    return sum(1 for l in limpiar_js(texto).splitlines() if l.strip())


def es_entorno_virtual(carpeta):
    """True si `carpeta` es un entorno virtual de Python: tiene pyvenv.cfg o lib/python*/site-packages.
    Ronda 6: un entorno con nombre libre (.venv312, .nox/paquete) es código de terceros, no del proyecto."""
    carpeta = Path(carpeta)
    try:
        if (carpeta / "pyvenv.cfg").is_file():
            return True
        lib = carpeta / "lib"
        return lib.is_dir() and any((x / "site-packages").is_dir() for x in lib.glob("python*"))
    except OSError:
        return False


def en_entorno_virtual(proyecto, ruta, cache):
    """True si alguna carpeta entre `proyecto` (excluido) y el archivo `ruta` es un entorno virtual."""
    proyecto = Path(proyecto)
    try:
        partes = Path(ruta).relative_to(proyecto).parts[:-1]
    except ValueError:
        return False
    actual = proyecto
    for parte in partes:
        actual = actual / parte
        if actual not in cache:
            cache[actual] = es_entorno_virtual(actual)
        if cache[actual]:
            return True
    return False


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    limite = fb.umbral("complejidad_ciclomatica_max", 15)
    hallazgos, todas, n_arch = [], [], 0
    venvs = {}
    for p in fb.recorrer(proyecto, EXT_JS | {".py"}):
        if p.name.endswith((".min.js", ".d.ts")):
            continue
        if en_entorno_virtual(proyecto, p, venvs):
            continue  # código de terceros instalado en un entorno virtual (ronda 6)
        texto = comun.leer(p)
        if texto is None:
            continue
        n_arch += 1
        arch = fb.rel(proyecto, p)
        es_py = p.suffix == ".py"
        funcs = funciones_python(p, texto) if es_py else funciones_js(texto, jsx=p.suffix.lower() in EXT_JSX)
        todas.extend(funcs)
        for f in funcs:
            if f["ccn"] > limite:
                sev = "media" if f["ccn"] > 2 * limite else "baja"
                hallazgos.append(comun.hallazgo(NOMBRE, "ccn_alta", arch, f["linea"], f"{f['nombre']} (CCN {f['ccn']} > {limite})",
                                                fb.evidencia_linea(texto, f["linea"]), sev))
            if f["lineas"] > LARGO_FUNCION:
                hallazgos.append(comun.hallazgo(NOMBRE, "funcion_larga", arch, f["linea"],
                                                f"{f['nombre']}: {f['lineas']} líneas (> {LARGO_FUNCION})",
                                                fb.evidencia_linea(texto, f["linea"]), "info"))
        loc = lineas_codigo(texto, es_py)
        if loc > LARGO_ARCHIVO:
            hallazgos.append(comun.hallazgo(NOMBRE, "archivo_grande", arch, None, f"{loc} líneas de código (> {LARGO_ARCHIVO})",
                                            f"{arch}: {loc} líneas", "info"))
    pases = []
    if todas and not any(h["regla"].endswith(".ccn_alta") for h in hallazgos):
        maximo = max(f["ccn"] for f in todas)
        media = sum(f["ccn"] for f in todas) / len(todas)
        pases.append(fb.pase(NOMBRE, "ccn", f"{len(todas)} funciones en {n_arch} archivos, CCN máx {maximo}, "
                             f"media {media:.1f}"))
    return fb.resultado(REEMPLAZA, hallazgos, pases)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))
