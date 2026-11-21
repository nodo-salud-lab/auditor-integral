"""Acceso al catálogo canónico de controles (catalogo/controles.toml).

Funciones públicas:
  cargar_catalogo()            lista de controles (dicts) en el orden del TOML.
  cargar_perfil_riesgo()       banderas y reglas contextuales (perfil_riesgo.toml).
  control_por_regla(h, r)      ID del control canónico para la regla "h:r" de una
                               herramienta, según mapea_reglas (fnmatch; gana el patrón
                               más específico).
  evaluar_condicion(c, p)      evalúa una condición sobre perfil.json SIN eval: parser
                               mínimo con lógica de tres valores (True/False/None).
  controles_aplicables(p, g)   controles aplicables al perfil con gate <= g, con la
                               severidad contextual aplicada.
  conteo_evidencia_pass()      controles por categoría de evidencia_pass y los que cambiaron de
                               categoría respecto de la regla anterior (sin «pases vacíos»).

Solo biblioteca estándar.
"""

import copy
import fnmatch
import re
import tomllib
from pathlib import Path, PurePosixPath

RAIZ = Path(__file__).resolve().parent.parent
RUTA_CONTROLES = RAIZ / "catalogo" / "controles.toml"
RUTA_PERFIL_RIESGO = RAIZ / "catalogo" / "perfil_riesgo.toml"

GATES = ("N1", "N2", "N3", "N4", "N5")
SEVERIDADES = ("info", "baja", "media", "alta", "critica")  # de menor a mayor
# Directorios de salida de build: un secreto aquí está en el bundle del cliente.
DIRS_BUNDLE = frozenset({"dist", "build", ".next", "out"})
SUFIJO_BUNDLE = "-bundle"
MARCA_REGLAS_PROPIAS = "vibe-coding."


class ErrorCondicion(ValueError):
    """Condición mal formada o con operaciones no permitidas."""


# --------------------------------------------------------------------------- carga

def cargar_catalogo(ruta=None):
    """Devuelve la lista de controles de controles.toml."""
    with open(ruta or RUTA_CONTROLES, "rb") as f:
        return tomllib.load(f)["control"]


EVIDENCIAS_PASS = ("ausencia_suficiente", "checks_pass", "no_demostrable_estatico")


def conteo_evidencia_pass(catalogo=None):
    """{"por_categoria": {categoría: n}, "cambiaron": [ids]}.

    Antes de evidencia_pass, todo control sin `exige_checks_pass` podía pasar porque su herramienta corrió sin
    hallazgos (equivalía a «ausencia_suficiente» sin precondición de alcance). «cambiaron» lista los que ya no son
    ausencia_suficiente. Un control sin el campo cuenta como checks_pass (default fail-closed)."""
    catalogo = catalogo if catalogo is not None else cargar_catalogo()
    por = {k: 0 for k in EVIDENCIAS_PASS}
    cambiaron = []
    for c in catalogo:
        ev = c.get("evidencia_pass") or "checks_pass"
        por[ev] = por.get(ev, 0) + 1
        if not c.get("exige_checks_pass") and ev != "ausencia_suficiente":
            cambiaron.append(c["id"])
    return {"por_categoria": por, "cambiaron": sorted(cambiaron)}


def cargar_perfil_riesgo(ruta=None):
    with open(ruta or RUTA_PERFIL_RIESGO, "rb") as f:
        return tomllib.load(f)


def indice_por_id(catalogo):
    return {c["id"]: c for c in catalogo}


def expandir_patron_ids(patron, ids):
    """IDs (de un iterable o dict) que coinciden con un patrón fnmatch, en orden."""
    return [i for i in ids if fnmatch.fnmatchcase(i, patron)]


def expandir_patrones(patrones, ids):
    vistos = []
    for p in patrones:
        for i in expandir_patron_ids(p, ids):
            if i not in vistos:
                vistos.append(i)
    return vistos


# --------------------------------------------------------------------------- regla -> control

def _especificidad(patron):
    """Más caracteres literales = más específico; a igualdad, menos comodines."""
    comodines = patron.count("*") + patron.count("?")
    literales = len(re.sub(r"\[[^\]]*\]|[*?]", "", patron))
    return (literales, -comodines)


def _es_bundle(archivo):
    if not archivo:
        return False
    partes = PurePosixPath(str(archivo).replace("\\", "/")).parts
    return any(p in DIRS_BUNDLE for p in partes[:-1])


def _normalizar_regla(herramienta, regla):
    # semgrep antepone la ruta del archivo de reglas al check_id
    # (reglas.semgrep.vibe-coding.x → vibe-coding.x).
    if herramienta == "semgrep":
        i = regla.find(MARCA_REGLAS_PROPIAS)
        if i > 0 and regla[i - 1] == ".":
            return regla[i:]
    return regla


def normalizar_regla(herramienta, regla):
    """Versión pública de la normalización de IDs de regla (usada por los normalizadores)."""
    return _normalizar_regla(herramienta, regla)


def control_por_regla(herramienta, regla, catalogo=None, archivo=None):
    """ID del control canónico para (herramienta, regla), o None si nada coincide.

    Con `archivo` dentro de dist/, build/, .next/ u out/, se prueba primero
    "<herramienta>-bundle:<regla>" (p. ej. gitleaks-bundle:* → SEG-SECRETO-BUNDLE).
    """
    if catalogo is None:
        catalogo = cargar_catalogo()
    regla = _normalizar_regla(herramienta, regla)
    claves = []
    if _es_bundle(archivo):
        claves.append(f"{herramienta}{SUFIJO_BUNDLE}:{regla}")
    claves.append(f"{herramienta}:{regla}")
    for clave in claves:
        mejor, mejor_esp = None, None
        for control in catalogo:
            for patron in control.get("mapea_reglas", []):
                if fnmatch.fnmatchcase(clave, patron):
                    esp = _especificidad(patron)
                    if mejor_esp is None or esp > mejor_esp:  # empate: gana el primero
                        mejor, mejor_esp = control["id"], esp
        if mejor is not None:
            return mejor
    return None


# --------------------------------------------------------------------------- condiciones

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<par>[()])
    | (?P<op>==|!=|>=|<=|>|<)
    | (?P<cad>'[^'\\]*'|"[^"\\]*")
    | (?P<num>-?\d+(?:\.\d+)?)
    | (?P<nom>[A-Za-z_][A-Za-z0-9_]*)
    )""", re.X)
_PALABRAS = {"and", "or", "not", "true", "false", "siempre"}


def _tokenizar(texto):
    if not isinstance(texto, str):
        raise ErrorCondicion("la condición debe ser texto")
    tokens, pos = [], 0
    texto = texto.rstrip()
    while pos < len(texto):
        m = _TOKEN.match(texto, pos)
        if not m or m.end() == pos:
            raise ErrorCondicion(f"carácter no permitido en la posición {pos}: {texto[pos:pos + 10]!r}")
        pos = m.end()
        tipo = m.lastgroup
        valor = m.group(tipo)
        if tipo == "nom" and valor in _PALABRAS:
            tipo = valor
        tokens.append((tipo, valor))
    if not tokens:
        raise ErrorCondicion("condición vacía")
    return tokens


class _Parser:
    """expr := and ('or' and)* ; and := un ('and' un)* ;
    un := 'not' un | prim ; prim := '(' expr ')' | 'siempre' | nombre [op literal]"""

    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def _ver(self):
        return self.t[self.i][0] if self.i < len(self.t) else None

    def _tomar(self, tipo=None):
        if self.i >= len(self.t):
            raise ErrorCondicion("condición incompleta")
        tok = self.t[self.i]
        if tipo and tok[0] != tipo:
            raise ErrorCondicion(f"se esperaba {tipo}, llegó {tok[1]!r}")
        self.i += 1
        return tok

    def analizar(self):
        arbol = self._or()
        if self.i != len(self.t):
            raise ErrorCondicion(f"token inesperado {self.t[self.i][1]!r}")
        return arbol

    def _or(self):
        nodos = [self._and()]
        while self._ver() == "or":
            self._tomar()
            nodos.append(self._and())
        return nodos[0] if len(nodos) == 1 else ("or", nodos)

    def _and(self):
        nodos = [self._un()]
        while self._ver() == "and":
            self._tomar()
            nodos.append(self._un())
        return nodos[0] if len(nodos) == 1 else ("and", nodos)

    def _un(self):
        if self._ver() == "not":
            self._tomar()
            return ("not", self._un())
        return self._prim()

    def _prim(self):
        tipo = self._ver()
        if tipo == "par" and self.t[self.i][1] == "(":
            self._tomar()
            nodo = self._or()
            tok = self._tomar("par")
            if tok[1] != ")":
                raise ErrorCondicion("se esperaba ')'")
            return nodo
        if tipo == "siempre":
            self._tomar()
            return ("const", True)
        if tipo == "nom":
            nombre = self._tomar()[1]
            if self._ver() == "op":
                op = self._tomar()[1]
                return ("cmp", nombre, op, self._literal())
            return ("flag", nombre)
        raise ErrorCondicion(f"token inesperado {self.t[self.i][1]!r}" if tipo else "condición incompleta")

    def _literal(self):
        tipo, valor = self._tomar()
        if tipo == "cad":
            return valor[1:-1]
        if tipo == "num":
            return float(valor) if "." in valor else int(valor)
        if tipo in ("true", "false"):
            return tipo == "true"
        raise ErrorCondicion(f"se esperaba un literal, llegó {valor!r}")


def _analizar(cond):
    return _Parser(_tokenizar(cond)).analizar()


def validar_condicion(cond):
    """Lanza ErrorCondicion si la condición no es válida."""
    arbol = _analizar(cond)
    _validar_tipos(arbol)
    return arbol


def _validar_tipos(nodo):
    tipo = nodo[0]
    if tipo in ("and", "or"):
        for n in nodo[1]:
            _validar_tipos(n)
    elif tipo == "not":
        _validar_tipos(nodo[1])
    elif tipo == "cmp":
        _, _, op, lit = nodo
        if op in ("<", "<=", ">", ">=") and (isinstance(lit, bool) or not isinstance(lit, (int, float))):
            raise ErrorCondicion(f"el operador {op} requiere un número")


def nombres_en_condicion(cond):
    """Conjunto de banderas que usa una condición."""
    nombres = set()

    def recorrer(n):
        if n[0] in ("and", "or"):
            for x in n[1]:
                recorrer(x)
        elif n[0] == "not":
            recorrer(n[1])
        elif n[0] in ("cmp", "flag"):
            nombres.add(n[1])

    recorrer(validar_condicion(cond))
    return nombres


def _banderas(perfil):
    if isinstance(perfil, dict) and isinstance(perfil.get("banderas"), dict):
        return perfil["banderas"]
    return perfil or {}


def _igual(v, lit):
    # Sin coerciones: true no es igual a 1 ni a "true".
    if isinstance(v, bool) or isinstance(lit, bool):
        return isinstance(v, bool) and isinstance(lit, bool) and v == lit
    return v == lit


def _evaluar(nodo, b):
    tipo = nodo[0]
    if tipo == "const":
        return nodo[1]
    if tipo == "or":
        vals = [_evaluar(n, b) for n in nodo[1]]
        return True if True in vals else (None if None in vals else False)
    if tipo == "and":
        vals = [_evaluar(n, b) for n in nodo[1]]
        return False if False in vals else (None if None in vals else True)
    if tipo == "not":
        v = _evaluar(nodo[1], b)
        return None if v is None else not v
    if tipo == "flag":
        v = b.get(nodo[1])
        return None if v is None else bool(v)
    _, nombre, op, lit = nodo  # cmp
    v = b.get(nombre)
    if v is None:
        return None
    if op in ("==", "!="):
        igual = _igual(v, lit)
        return igual if op == "==" else not igual
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ErrorCondicion(f"{nombre} no es numérico; no admite {op}")
    return {"<": v < lit, "<=": v <= lit, ">": v > lit, ">=": v >= lit}[op]


def evaluar_condicion(cond, perfil):
    """Evalúa `cond` sobre perfil.json (o su dict de banderas).

    Devuelve True, False o None (desconocido: alguna bandera necesaria es null o falta).
    Lógica de Kleene: `x or desconocido` es True si x es True; `x and desconocido`
    es False si x es False. Nunca ejecuta código: lanza ErrorCondicion si la
    expresión no respeta la gramática.
    """
    return _evaluar(validar_condicion(cond), _banderas(perfil))


# --------------------------------------------------------------------------- aplicables

def _num_gate(gate):
    if gate not in GATES:
        raise ValueError(f"gate inválido: {gate!r} (válidos: {', '.join(GATES)})")
    return GATES.index(gate)


def _aplicar_regla(control, regla):
    if "gate" in regla and _num_gate(regla["gate"]) < _num_gate(control["gate"]):
        control["gate"] = regla["gate"]
    if "severidad_base" in regla and (
            SEVERIDADES.index(regla["severidad_base"]) > SEVERIDADES.index(control["severidad_base"])):
        control["severidad_base"] = regla["severidad_base"]
    if regla.get("bloquea_global"):
        control["bloquea_global"] = True
    control.setdefault("reglas_contextuales", []).append(regla["id"])


def controles_aplicables(perfil, gate_max="N5", catalogo=None, perfil_riesgo=None):
    """Controles aplicables al perfil con gate <= gate_max (tras la severidad contextual).

    Cada control devuelto es una copia con el campo extra `aplicabilidad`:
      "aplica"       la condición es verdadera;
      "desconocida"  falta la respuesta de alguna bandera (el control se mantiene para
                     que salga no_evaluado; no se asume la respuesta).
    Los controles con condición falsa (no_aplica) se omiten. Las reglas contextuales
    solo se aplican cuando su condición es verdadera.
    """
    limite = _num_gate(gate_max)
    if catalogo is None:
        catalogo = cargar_catalogo()
    if perfil_riesgo is None:
        perfil_riesgo = cargar_perfil_riesgo()
    ids = [c["id"] for c in catalogo]
    reglas = [(r, set(expandir_patrones(r["controles"], ids)))
              for r in perfil_riesgo.get("regla_contextual", [])
              if evaluar_condicion(r["condicion"], perfil) is True]

    resultado = []
    for original in catalogo:
        estado = evaluar_condicion(original["condicion"], perfil)
        if estado is False:
            continue
        control = copy.deepcopy(original)
        control["aplicabilidad"] = "aplica" if estado else "desconocida"
        for regla, afectados in reglas:
            if control["id"] in afectados:
                _aplicar_regla(control, regla)
        if _num_gate(control["gate"]) <= limite:
            resultado.append(control)
    return resultado
