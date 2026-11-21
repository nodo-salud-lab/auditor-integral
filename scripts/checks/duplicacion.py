#!/usr/bin/env python3
"""duplicacion — fallback de jscpd (DECISIONES #6; investigacion/13 §4.2). Cobertura parcial.

Algoritmo (stdlib): tokenización con una regex única (comentarios descartados), normalización tipo 2
(identificadores → I, números → N, cadenas → S; palabras clave se conservan), ventana deslizante de
MIN_TOKENS tokens con hash blake2b, fusión de ventanas consecutivas del mismo par de archivos (clon
maximal), descarte de clones con < MIN_LINEAS líneas o solapados consigo mismos.
MIN_TOKENS = 50 y MIN_LINEAS = 5: defaults documentados de jscpd 5.x. No detecta clones tipo 3.

Subregla             sev                                    → control
  bloque_duplicado    baja (máx. 5 por archivo + "y N más")  → COD-DUPLICACION
  porcentaje_global   baja (media si > 2× umbral)            → COD-DUPLICACION
Pase ok_porcentaje_global si dup % ≤ umbral.duplicacion_global (5 %).
Uso: duplicacion.py PROYECTO DIR_CRUDO
"""
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402
from complejidad import en_entorno_virtual  # noqa: E402  (ronda 6: mismo criterio de entorno virtual)

NOMBRE = "duplicacion"
REEMPLAZA = "jscpd"
HERRAMIENTAS_REALES = ("jscpd",)
MIN_TOKENS = 50
MIN_LINEAS = 5
MAX_POR_ARCHIVO = 5
EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".vue", ".svelte", ".go", ".java", ".rb", ".php",
       ".css", ".scss"}
PALABRAS_CLAVE = frozenset("""
if else for while do switch case break continue return function const let var class extends new this super
import export from default try catch finally throw async await yield typeof instanceof in of null undefined
true false void delete static get set interface type enum implements public private protected readonly
def lambda pass raise with as elif except global nonlocal None True False and or not is self yield print
func go package struct map chan defer select range
""".split())
RE_TOKEN = re.compile(
    r"(?P<com>/\*.*?\*/|//[^\n]*)|(?P<cad>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)"
    r"|(?P<id>[A-Za-z_$][\w$]*)|(?P<num>\d+(?:\.\d+)?)|(?P<op>[{}()\[\];,.<>=!+\-*/%&|^~?:@#]+)", re.S)
RE_COMENTARIO_PY = re.compile(r"#[^\n]*")


def tokens(texto, es_py):
    if es_py:
        texto = RE_COMENTARIO_PY.sub("", texto)
    salida = []
    linea, ultimo = 1, 0
    for m in RE_TOKEN.finditer(texto):
        linea += texto.count("\n", ultimo, m.start())
        ultimo = m.start()
        tipo = m.lastgroup
        if tipo == "com":
            continue
        v = m.group(0)
        if tipo == "cad":
            norm = "S"
        elif tipo == "id":
            norm = v if v in PALABRAS_CLAVE else "I"
        elif tipo == "num":
            norm = "N"
        else:
            norm = v
        salida.append((norm, linea))
    return salida


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    archivos, toks = [], []
    venvs = {}
    for p in fb.recorrer(proyecto, EXT):
        n = p.name.lower()
        if ".min." in n or n.endswith(".d.ts") or "-lock" in n:
            continue
        if en_entorno_virtual(proyecto, p, venvs):
            continue  # código de terceros instalado en un entorno virtual (ronda 6)
        texto = comun.leer(p)
        if texto is None:
            continue
        archivos.append(fb.rel(proyecto, p))
        toks.append(tokens(texto, p.suffix == ".py"))
    if not archivos:
        return fb.resultado(REEMPLAZA, estado="no_aplica", motivo="no hay archivos de código")
    indice = {}
    for fi, ts in enumerate(toks):
        for i in range(len(ts) - MIN_TOKENS + 1):
            clave = hashlib.blake2b(" ".join(t for t, _ in ts[i:i + MIN_TOKENS]).encode(), digest_size=8).digest()
            indice.setdefault(clave, []).append((fi, i))
    pares = set()
    for occ in indice.values():
        if len(occ) < 2:
            continue
        a = occ[0]
        for b in occ[1:]:
            pares.add((a[0], b[0], b[1] - a[1], a[1]) if a <= b else (b[0], a[0], a[1] - b[1], b[1]))
    corridas = []
    for clave in sorted(pares):
        fa, fbb, delta, ia = clave
        if corridas and corridas[-1][:3] == (fa, fbb, delta) and corridas[-1][4] == ia - 1:
            corridas[-1][4] = ia
        else:
            corridas.append([fa, fbb, delta, ia, ia])
    dup_lineas = {}
    clones = []
    for fa, fbb, delta, ini, fin in corridas:
        ib_ini, ib_fin = ini + delta, fin + delta
        if fa == fbb and ib_ini <= fin + MIN_TOKENS - 1:
            continue  # solapado consigo mismo
        ta, tb = toks[fa], toks[fbb]
        la = (ta[ini][1], ta[fin + MIN_TOKENS - 1][1])
        lb = (tb[ib_ini][1], tb[ib_fin + MIN_TOKENS - 1][1])
        if la[1] - la[0] + 1 < MIN_LINEAS:
            continue
        clones.append((fa, la, fbb, lb))
        for f, (x, y) in ((fa, la), (fbb, lb)):
            dup_lineas.setdefault(f, set()).update(range(x, y + 1))
    # Varias ventanas repetidas dentro de un mismo clon generan corridas con otro desfase: los clones
    # del mismo par de archivos que se solapan en ambos lados se fusionan en uno solo.
    fusion = []
    for fa, la, fbb, lb in sorted(clones):
        u = next((u for u in fusion if u[0] == fa and u[2] == fbb and la[0] <= u[1][1] and u[1][0] <= la[1]
                  and lb[0] <= u[3][1] and u[3][0] <= lb[1]), None)
        if u:
            u[1] = (min(u[1][0], la[0]), max(u[1][1], la[1]))
            u[3] = (min(u[3][0], lb[0]), max(u[3][1], lb[1]))
        else:
            fusion.append([fa, la, fbb, lb])
    clones = [tuple(c) for c in fusion]
    hallazgos = []
    por_archivo = {}
    for fa, la, fbb, lb in clones:
        por_archivo.setdefault(fa, []).append((la, fbb, lb))
    textos = {}
    for fa, lista in sorted(por_archivo.items()):
        for k, (la, fbb, lb) in enumerate(lista):
            if k == MAX_POR_ARCHIVO:
                hallazgos.append(comun.hallazgo(NOMBRE, "bloque_duplicado", archivos[fa], None,
                                                f"… y {len(lista) - MAX_POR_ARCHIVO} bloques duplicados más en este archivo",
                                                f"{len(lista)} clones", "baja"))
                break
            if fa not in textos:
                textos[fa] = comun.leer(proyecto / archivos[fa]) or ""
            ev = " ".join(comun.linea_texto(textos[fa], n).strip() for n in (la[0], la[0] + 1))
            hallazgos.append(comun.hallazgo(NOMBRE, "bloque_duplicado", archivos[fa], la[0],
                                            f"Bloque de {la[1] - la[0] + 1} líneas duplicado con {archivos[fbb]}:{lb[0]}-{lb[1]}",
                                            ev, "baja"))
    total = sum(len({l for _, l in ts}) for ts in toks)
    dup = sum(len(v & {l for _, l in toks[f]}) for f, v in dup_lineas.items())
    pct = 100.0 * dup / total if total else 0.0
    limite = fb.umbral("duplicacion_global", 5)
    pases = []
    ev = f"dup={pct:.1f} % ({dup}/{total} líneas)"
    if pct > limite:
        hallazgos.append(comun.hallazgo(NOMBRE, "porcentaje_global", None, None,
                                        f"Duplicación global {pct:.1f} % > {limite} % (umbral.duplicacion_global)", ev,
                                        "media" if pct > 2 * limite else "baja"))
    else:
        pases.append(fb.pase(NOMBRE, "porcentaje_global", f"Duplicación global {ev} ≤ {limite} %"))
    return fb.resultado(REEMPLAZA, hallazgos, pases)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))
