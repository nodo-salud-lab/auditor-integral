#!/usr/bin/env python3
"""Métricas de validación del auditor contra la verdad de terreno (§11.3, §11.5).

Cruza el hallazgos.jsonl de una corrida con validacion/verdad-terreno.toml y
calcula sensibilidad (global, por gate, por severidad y por control), VPP
(precisión) y proporción de controles limpios disparados (FP en limpios), cada
una con IC95 % de Wilson. Exporta CSV para Jamovi/SPSS.

Reglas de coincidencia (documentadas para el informe de validación):
  1. Un hallazgo coincide con un defecto si comparten `control` y `archivo`
     (rutas normalizadas). Defectos con `ausencia = true` coinciden solo por
     control.
  2. Si ambos tienen línea, |línea_hallazgo − línea_defecto| ≤ tolerancia
     (por defecto 3). Si el defecto tiene `paquete`, se ignora la línea y el
     hallazgo debe nombrar el paquete (evidencia, regla o archivo).
  3. Asignación uno a uno, de menor a mayor distancia: un hallazgo cuenta para
     un solo defecto y un defecto para un solo hallazgo.
  4. Los hallazgos no asignados a un defecto son FP para la VPP y se atribuyen,
     como máximo, al control limpio compatible más cercano (mismas reglas 1-2).
  5. Con --tras-triage se excluyen los hallazgos con triage.veredicto o
     estado_hallazgo = "falso_positivo" (VPP después del triage, §11.3).

Solo biblioteca estándar.
"""

import argparse
import csv
import json
import math
import re
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

Z95 = 1.959963984540054
SUBCONJUNTOS = ("todo", "reservado", "desarrollo", "f1")


# ---------------------------------------------------------------- Wilson
def wilson(x, n, z=Z95):
    """IC de Wilson para una proporción x/n. Devuelve (inf, sup) o (None, None) si n = 0."""
    if n < 0 or x < 0 or x > n:
        raise ValueError(f"valores inválidos: x={x}, n={n}")
    if n == 0:
        return (None, None)
    p = x / n
    z2 = z * z
    denom = 1 + z2 / n
    centro = (p + z2 / (2 * n)) / denom
    medio = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    inf = 0.0 if x == 0 else max(0.0, centro - medio)
    sup = 1.0 if x == n else min(1.0, centro + medio)
    return (inf, sup)


# ---------------------------------------------------------------- utilidades
def normalizar_ruta(ruta, raiz=None):
    if ruta is None:
        return ""
    r = str(ruta).replace("\\", "/")
    if raiz:
        base = str(raiz).replace("\\", "/").rstrip("/") + "/"
        if r.startswith(base):
            r = r[len(base):]
    partes = [p for p in r.split("/") if p not in ("", ".")]
    return "/".join(partes)


def _menciona_paquete(hallazgo, paquete):
    texto = " ".join([
        str(hallazgo.get("evidencia") or ""),
        str(hallazgo.get("ubicacion", {}).get("archivo") or ""),
        json.dumps(hallazgo.get("fuente") or [], ensure_ascii=False),
    ])
    patron = r"(?<![A-Za-z0-9@/._-])" + re.escape(paquete) + r"(?![A-Za-z0-9/._-])"
    return re.search(patron, texto) is not None


def _distancia(hallazgo, entrada, raiz, tolerancia):
    """Distancia hallazgo↔entrada (defecto o limpio) o None si no son compatibles."""
    if hallazgo.get("control") != entrada["control"]:
        return None
    ubic = hallazgo.get("ubicacion") or {}
    if not entrada.get("ausencia"):
        if normalizar_ruta(ubic.get("archivo"), raiz) != normalizar_ruta(entrada["archivo"]):
            return None
    if entrada.get("paquete"):
        return 0 if _menciona_paquete(hallazgo, entrada["paquete"]) else None
    lh, le = ubic.get("linea"), entrada.get("linea")
    if lh is None or le is None:
        return 0
    d = abs(int(lh) - int(le))
    return d if d <= tolerancia else None


def _es_falso_positivo(h):
    triage = h.get("triage") or {}
    return h.get("estado_hallazgo") == "falso_positivo" or triage.get("veredicto") == "falso_positivo"


def filtrar(entradas, subconjunto):
    """Subconjunto de defectos o limpios: todo | reservado | desarrollo | f1 (detectable_en_F1)."""
    if subconjunto not in SUBCONJUNTOS:
        raise ValueError(f"subconjunto desconocido: {subconjunto}")
    if subconjunto == "reservado":
        return [e for e in entradas if e.get("reservado")]
    if subconjunto == "desarrollo":
        return [e for e in entradas if not e.get("reservado")]
    if subconjunto == "f1":
        return [e for e in entradas if e.get("detectable_en_F1", True)]
    return list(entradas)


def filtrar_extra(entradas, dominio=None, gate=None, solo_f1=False):
    """Filtros combinables: dominio (prefijo del control, p. ej. SEG), gate (N1…) y detectable_en_F1."""
    r = list(entradas)
    if dominio:
        r = [e for e in r if str(e.get("control", "")).split("-", 1)[0] == dominio]
    if gate:
        r = [e for e in r if e.get("gate") == gate]
    if solo_f1:
        r = [e for e in r if e.get("detectable_en_F1", True)]
    return r


# ---------------------------------------------------------------- cruce
def cruzar(hallazgos, defectos, limpios, tolerancia=3, raiz=None, tras_triage=False, defectos_fuera=None):
    """Cruza hallazgos con la verdad de terreno. Devuelve un dict con el detalle y los conteos.

    defectos_fuera: defectos sembrados que quedaron fuera del subconjunto medido (p. ej. los
    reservados al medir 'desarrollo'). Un hallazgo no asignado que coincide con uno de ellos es un
    verdadero positivo de otro subconjunto: no se cuenta como FP ni dispara controles limpios.
    """
    hs = [h for h in hallazgos if not (tras_triage and _es_falso_positivo(h))]

    # Asignación conjunta sobre los defectos medidos y los excluidos del subconjunto, para que un
    # hallazgo que corresponde a un defecto excluido no se acredite a uno medido (ni al revés).
    n_medidos = len(defectos)
    todos = list(defectos) + list(defectos_fuera or [])
    pares = []
    for i, h in enumerate(hs):
        for j, d in enumerate(todos):
            dist = _distancia(h, d, raiz, tolerancia)
            if dist is not None:
                pares.append((dist, j, i))
    pares.sort()
    h_asignado, d_asignado = {}, {}
    for dist, j, i in pares:
        if i in h_asignado or j in d_asignado:
            continue
        h_asignado[i], d_asignado[j] = j, i

    det_defectos = {}
    for j, d in enumerate(defectos):
        i = d_asignado.get(j)
        det_defectos[d["id"]] = {"detectado": i is not None, "hallazgo": hs[i].get("id") if i is not None else None}

    fuera = {i for i, j in h_asignado.items() if j >= n_medidos}

    disparados = defaultdict(list)
    for i, h in enumerate(hs):
        if i in h_asignado:
            continue
        candidatos = []
        for k, l in enumerate(limpios):
            dist = _distancia(h, l, raiz, tolerancia)
            if dist is not None:
                candidatos.append((dist, k))
        if candidatos:
            _, k = min(candidatos)
            disparados[k].append(h.get("id"))

    det_limpios = {l["id"]: {"disparado": k in disparados, "hallazgos": disparados.get(k, [])}
                   for k, l in enumerate(limpios)}

    vp = len(h_asignado) - len(fuera)
    return {
        "defectos": det_defectos,
        "limpios": det_limpios,
        "vp": vp,
        "fp": len(hs) - vp - len(fuera),
        "fn": len(defectos) - vp,
        "fp_limpios": sum(1 for v in det_limpios.values() if v["disparado"]),
        "n_hallazgos": len(hs) - len(fuera),
        "fuera_de_subconjunto": len(fuera),
        "tolerancia": tolerancia,
        "tras_triage": tras_triage,
    }


# ---------------------------------------------------------------- resumen
def _fila(metrica, estrato, x, n):
    inf, sup = wilson(x, n)
    return {"metrica": metrica, "estrato": estrato, "x": x, "n": n,
            "proporcion": (x / n) if n else None, "ic95_inf": inf, "ic95_sup": sup}


def resumen(resultado, defectos, limpios):
    """Filas (métrica, estrato, x, n, proporción, IC95 %) para sensibilidad, VPP y FP en limpios."""
    filas = []
    det = resultado["defectos"]
    detectado = lambda d: det[d["id"]]["detectado"]  # noqa: E731

    filas.append(_fila("sensibilidad", "global", sum(detectado(d) for d in defectos), len(defectos)))
    for clave in ("gate", "severidad", "control"):
        grupos = defaultdict(list)
        for d in defectos:
            grupos[d.get(clave, "?")].append(d)
        for valor in sorted(grupos):
            g = grupos[valor]
            filas.append(_fila("sensibilidad", f"{clave}={valor}", sum(detectado(d) for d in g), len(g)))

    filas.append(_fila("vpp", "global", resultado["vp"], resultado["vp"] + resultado["fp"]))
    filas.append(_fila("fp_limpios", "global", resultado["fp_limpios"], len(limpios)))
    grupos = defaultdict(list)
    for l in limpios:
        grupos[l["control"]].append(l)
    for valor in sorted(grupos):
        g = grupos[valor]
        filas.append(_fila("fp_limpios", f"control={valor}",
                           sum(resultado["limpios"][l["id"]]["disparado"] for l in g), len(g)))
    return filas


def exportar_csv(resultado, defectos, limpios, carpeta):
    """Escribe metricas_resumen.csv, metricas_defectos.csv y metricas_limpios.csv (punto decimal)."""
    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)
    rutas = []

    ruta = carpeta / "metricas_resumen.csv"
    campos = ["metrica", "estrato", "x", "n", "proporcion", "ic95_inf", "ic95_sup"]
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        for f in resumen(resultado, defectos, limpios):
            w.writerow({k: ("" if f[k] is None else (f"{f[k]:.4f}" if isinstance(f[k], float) else f[k]))
                        for k in campos})
    rutas.append(ruta)

    ruta = carpeta / "metricas_defectos.csv"
    campos = ["id", "control", "archivo", "linea", "gate", "severidad", "detectable_en_F1", "reservado", "detectado"]
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        for d in defectos:
            w.writerow({"id": d["id"], "control": d["control"], "archivo": d["archivo"],
                        "linea": d.get("linea", ""), "gate": d.get("gate", ""),
                        "severidad": d.get("severidad", ""),
                        "detectable_en_F1": int(bool(d.get("detectable_en_F1", True))),
                        "reservado": int(bool(d.get("reservado"))),
                        "detectado": int(resultado["defectos"][d["id"]]["detectado"])})
    rutas.append(ruta)

    ruta = carpeta / "metricas_limpios.csv"
    campos = ["id", "control", "archivo", "linea", "reservado", "disparado"]
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=campos)
        w.writeheader()
        for l in limpios:
            w.writerow({"id": l["id"], "control": l["control"], "archivo": l["archivo"],
                        "linea": l.get("linea", ""), "reservado": int(bool(l.get("reservado"))),
                        "disparado": int(resultado["limpios"][l["id"]]["disparado"])})
    rutas.append(ruta)
    return rutas


# ---------------------------------------------------------------- E/S
def leer_hallazgos(ruta):
    hallazgos = []
    with open(ruta, encoding="utf-8") as fh:
        for n, linea in enumerate(fh, 1):
            if linea.strip():
                try:
                    hallazgos.append(json.loads(linea))
                except json.JSONDecodeError as e:
                    raise SystemExit(f"{ruta}:{n}: JSON inválido ({e})")
    return hallazgos


def avisos_tope(ruta, hallazgos):
    """Avisos si el archivo recibido trae el tope de 5 instancias por (control, archivo) (REAUDITORIA.md §R2.6): las
    métricas de validación deben calcularse sobre hallazgos_todos.jsonl, que no lo aplica."""
    ruta = Path(ruta)
    avisos = []
    hermano = ruta.with_name("hallazgos_todos.jsonl")
    if ruta.name == "hallazgos.jsonl" and hermano.is_file():
        avisos.append(f"se recibió {ruta.name} (con tope de instancias por control y archivo) y existe {hermano}: "
                      "las métricas de validación deben calcularse sobre hallazgos_todos.jsonl (sin tope); con el "
                      "tope se pierden defectos detectados (p. ej. D06)")
    extra = sum(int(h.get("instancias_extra") or 0) for h in hallazgos if isinstance(h, dict))
    if extra:
        avisos.append(f"los hallazgos traen el tope aplicado ({extra} instancias descartadas en instancias_extra): "
                      "use hallazgos_todos.jsonl")
    return avisos


def leer_verdad(ruta):
    with open(ruta, "rb") as fh:
        datos = tomllib.load(fh)
    return datos.get("defecto", []), datos.get("limpio", [])


def _fmt(v):
    return "—" if v is None else f"{v:.2f}".replace(".", ",")


def main(argv=None, salida=None):
    salida = salida or sys.stdout
    ap = argparse.ArgumentParser(description="Métricas del auditor frente a la verdad de terreno (brazo A).")
    ap.add_argument("--hallazgos", required=True, help="hallazgos.jsonl de la corrida")
    ap.add_argument("--verdad", default=str(Path(__file__).with_name("verdad-terreno.toml")))
    ap.add_argument("--raiz", default=None, help="prefijo a quitar de las rutas de los hallazgos")
    ap.add_argument("--tolerancia", type=int, default=3, help="± líneas (por defecto 3)")
    ap.add_argument("--subconjunto", choices=SUBCONJUNTOS, default="todo",
                    help="reservado = medición final; desarrollo = el resto; f1 = detectable_en_F1")
    ap.add_argument("--dominio", default=None, help="solo defectos/limpios de este dominio (SEG, DAT, …)")
    ap.add_argument("--gate", default=None, help="solo defectos de este gate (N1, N2, …)")
    ap.add_argument("--solo-f1", action="store_true", help="solo defectos detectable_en_F1 (combinable)")
    ap.add_argument("--tras-triage", action="store_true", help="excluye hallazgos marcados falso_positivo")
    ap.add_argument("--csv", default=None, help="carpeta donde exportar los CSV")
    a = ap.parse_args(argv)

    todos_defectos, limpios = leer_verdad(a.verdad)
    defectos = filtrar_extra(filtrar(todos_defectos, a.subconjunto), a.dominio, a.gate, a.solo_f1)
    if a.subconjunto in ("reservado", "desarrollo"):
        limpios = filtrar(limpios, a.subconjunto)
    if a.dominio:
        limpios = filtrar_extra(limpios, dominio=a.dominio)
    ids = {d["id"] for d in defectos}
    fuera = [d for d in todos_defectos if d["id"] not in ids]
    hallazgos = leer_hallazgos(a.hallazgos)
    for aviso in avisos_tope(a.hallazgos, hallazgos):
        print(f"ADVERTENCIA: {aviso}", file=sys.stderr)
    if a.dominio:
        hallazgos = [h for h in hallazgos if str(h.get("control", "")).split("-", 1)[0] == a.dominio]
    r = cruzar(hallazgos, defectos, limpios, tolerancia=a.tolerancia, raiz=a.raiz, tras_triage=a.tras_triage,
               defectos_fuera=fuera)

    filtros = " · ".join(x for x in (a.dominio and f"dominio {a.dominio}", a.gate and f"gate {a.gate}",
                                     a.solo_f1 and "solo detectable_en_F1") if x)
    print(f"Subconjunto: {a.subconjunto} · tolerancia ±{a.tolerancia} · tras triage: {a.tras_triage}"
          + (f" · {filtros}" if filtros else ""), file=salida)
    print(f"Hallazgos: {r['n_hallazgos']} · VP {r['vp']} · FP {r['fp']} · FN {r['fn']}"
          f" · coinciden con defectos fuera del subconjunto: {r['fuera_de_subconjunto']}", file=salida)
    for id_, v in sorted(r["defectos"].items()):
        if not v["detectado"]:
            print(f"FN {id_}", file=salida)
    for f in resumen(r, defectos, limpios):
        print(f"{f['metrica']:<13} {f['estrato']:<34} {f['x']:>3}/{f['n']:<3} "
              f"{_fmt(f['proporcion'])} IC95 % [{_fmt(f['ic95_inf'])}; {_fmt(f['ic95_sup'])}]", file=salida)
    if a.csv:
        for ruta in exportar_csv(r, defectos, limpios, a.csv):
            print(f"CSV: {ruta}", file=salida)
    return 0


if __name__ == "__main__":
    sys.exit(main())
