#!/usr/bin/env python3
"""Comparación de calidad entre brazos (F3; PLAN_MAESTRO §10 F3, §11.2-§11.4) y recall de F3 en kine us.

Brazos sobre la app sembrada (verdad de terreno: validacion/verdad-terreno.toml):
  A  auditor completo: corrida determinista + veredictos LLM aplicados con 'bin/auditar veredictos'
     (triage + hallazgos_ia), una copia de la corrida por cada corrida LLM (c1, c2).
  B  LLM puro (hallazgos_todos.jsonl de cada corrida del comparador).
  C  herramientas sin triage: la corrida determinista tal cual.
  D  semgrep solo con reglas del registry (p/owasp-top-ten): hallazgos de C cuya fuente es semgrep con una regla
     que no es propia (prefijo 'vibe-coding.').

Métricas: las de metricas.py (cruzar), por subconjunto (todo, desarrollo, reservado): sensibilidad global y
SEG·N1, VPP y FP en controles limpios, con IC95 % de Wilson. Estabilidad c1/c2: % de acuerdo y κ de Cohen sobre
los veredictos con la misma clave (agente, control, hallazgo_id).

Kine us: recall de F3 contra los hallazgos CONFIRMADOS de la revisión libre con verificación adversarial
(validacion/brazo-c-kine-us/confirmados-revision-libre.toml). Reglas (fail-closed: si no hay evidencia
explícita, el ítem no se cuenta como recuperado):
  - ítem falso_positivo: lo recupera la IA solo si un veredicto falso_positivo apunta a su hallazgo_id. El
    determinista nunca lo recupera (no descarta falsos positivos).
  - ítem verdadero: la IA lo recupera con un triage verdadero/incierto sobre su hallazgo_id o con un veredicto
    fail/incierto de control sobre uno de sus controles; el determinista, con un hallazgo de uno de sus controles
    y, si el ítem declara archivos, en uno de ellos (comparación por sufijo de ruta). Un hallazgo sin archivo
    (ausencia) coincide por control solo si el ítem no declara archivos.

Solo biblioteca estándar. Uso: ver main() (--app, --kine).
"""

import argparse
import json
import sys
import tomllib
from collections import Counter
from pathlib import Path

_AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(_AQUI))
sys.path.insert(0, str(_AQUI.parent / "scripts"))

import metricas  # noqa: E402

PREFIJO_PROPIO = "vibe-coding."
VEREDICTOS_POSITIVOS_CONTROL = ("fail", "incierto")
VEREDICTOS_POSITIVOS_HALLAZGO = ("verdadero", "incierto")


# ---------------------------------------------------------------- estabilidad
def _clave(x):
    return (x.get("agente"), x.get("control"), x.get("hallazgo_id"))


def acuerdo(v1, v2):
    """% de acuerdo y κ de Cohen entre dos corridas de veredictos, sobre las claves comunes."""
    a = {_clave(x): x.get("veredicto") for x in v1}
    b = {_clave(x): x.get("veredicto") for x in v2}
    comunes = sorted(set(a) & set(b), key=str)
    n = len(comunes)
    res = {"n_comunes": n, "solo_1": len(set(a) - set(b)), "solo_2": len(set(b) - set(a)),
           "acuerdos": 0, "pct": None, "kappa": None, "desacuerdos": []}
    if not n:
        return res
    acu = sum(a[k] == b[k] for k in comunes)
    po = acu / n
    ca, cb_ = Counter(a[k] for k in comunes), Counter(b[k] for k in comunes)
    pe = sum((ca[c] / n) * (cb_[c] / n) for c in set(ca) | set(cb_))
    kappa = 1.0 if pe == 1 and po == 1 else ((po - pe) / (1 - pe) if pe < 1 else None)
    res.update(acuerdos=acu, pct=po, kappa=kappa,
               desacuerdos=[(k, a[k], b[k]) for k in comunes if a[k] != b[k]])
    return res


# ---------------------------------------------------------------- brazos
def brazo_d(hallazgos):
    """Hallazgos con al menos una fuente semgrep de una regla del registry (no propia)."""
    return [h for h in hallazgos
            if any(f.get("herramienta") == "semgrep" and not str(f.get("regla") or "").startswith(PREFIJO_PROPIO)
                   for f in (h.get("fuente") or []))]


def hallazgos_despues(corrida):
    """hallazgos_todos.jsonl con el triage aplicado + hallazgos_ia (requiere decisiones_ia.json: fail-closed)."""
    import veredictos  # scripts/veredictos.py
    corrida = Path(corrida)
    if not (corrida / veredictos.DECISIONES).is_file():
        raise FileNotFoundError(f"falta {corrida / veredictos.DECISIONES}: aplique antes 'bin/auditar veredictos'")
    hs = metricas.leer_hallazgos(corrida / "hallazgos_todos.jsonl")
    return veredictos.hallazgos_para_gates(corrida, hs)


def _prop(x, n):
    return {"x": x, "n": n, "p": (x / n) if n else None, "ic": metricas.wilson(x, n)}


def metricas_brazo(hallazgos, defectos_todos, limpios_todos, subconjunto="todo", tras_triage=False, tolerancia=3):
    defectos = metricas.filtrar(defectos_todos, subconjunto)
    limpios = metricas.filtrar(limpios_todos, subconjunto) if subconjunto in ("reservado", "desarrollo") \
        else list(limpios_todos)
    ids = {x["id"] for x in defectos}
    fuera = [x for x in defectos_todos if x["id"] not in ids]
    r = metricas.cruzar(hallazgos, defectos, limpios, tolerancia=tolerancia, tras_triage=tras_triage,
                        defectos_fuera=fuera)
    seg_n1 = metricas.filtrar_extra(defectos, dominio="SEG", gate="N1")
    det = r["defectos"]
    return {
        "subconjunto": subconjunto, "tras_triage": tras_triage,
        "sens_global": _prop(sum(det[x["id"]]["detectado"] for x in defectos), len(defectos)),
        "sens_seg_n1": _prop(sum(det[x["id"]]["detectado"] for x in seg_n1), len(seg_n1)),
        "vpp": _prop(r["vp"], r["vp"] + r["fp"]),
        "fp_limpios": _prop(r["fp_limpios"], len(limpios)),
        "fn": sorted(k for k, x in det.items() if not x["detectado"]),
        "n_hallazgos": r["n_hallazgos"],
    }


def detectados(hallazgos, defectos_todos, ids, tolerancia=3):
    r = metricas.cruzar(hallazgos, defectos_todos, [], tolerancia=tolerancia)
    return {i: r["defectos"][i]["detectado"] for i in ids}


# ---------------------------------------------------------------- kine us
def leer_confirmados(ruta):
    with open(ruta, "rb") as fh:
        return tomllib.load(fh).get("item", [])


def _archivo_coincide(archivo, archivos):
    if not archivos:
        return True
    if not archivo:
        return False
    a = str(archivo).replace("\\", "/")
    return any(a == x or a.endswith("/" + x) for x in archivos)


def recall_kine(items, veredictos_ia, hallazgos_det):
    res = []
    for it in items:
        ctrls = set(it["controles"])
        hid = it.get("hallazgo_id")
        archivos = it.get("archivos") or []
        sobre_h = [x for x in veredictos_ia if hid and x.get("hallazgo_id") == hid]
        de_ctrl = [x for x in veredictos_ia if not x.get("hallazgo_id") and x.get("control") in ctrls]
        if it["tipo"] == "falso_positivo":
            llm = any(x["veredicto"] == "falso_positivo" for x in sobre_h)
            contradice = any(x["veredicto"] in VEREDICTOS_POSITIVOS_HALLAZGO for x in sobre_h)
            completo = llm
        else:
            llm = (any(x["veredicto"] in VEREDICTOS_POSITIVOS_HALLAZGO for x in sobre_h)
                   or any(x["veredicto"] in VEREDICTOS_POSITIVOS_CONTROL for x in de_ctrl))
            contradice = any(x["veredicto"] == "falso_positivo" for x in sobre_h)
            det = any(hd.get("control") in ctrls and (
                (hid and hd.get("id") == hid) or
                _archivo_coincide((hd.get("ubicacion") or {}).get("archivo"), archivos))
                for hd in hallazgos_det)
            completo = llm or det
        res.append({"id": it["id"], "revisor": it.get("revisor"), "tipo": it["tipo"],
                    "controles": sorted(ctrls), "llm": llm, "completo": completo, "contradice": contradice,
                    "no_evaluado_ia": any(x["veredicto"] == "no_evaluado" for x in de_ctrl)})
    return res


# ---------------------------------------------------------------- CLI
def _leer_jsonl(ruta):
    return [json.loads(x) for x in Path(ruta).read_text(encoding="utf-8").splitlines() if x.strip()]


def _f(p):
    m = p
    if m["p"] is None:
        return f"{m['x']}/{m['n']} —"
    return f"{m['x']}/{m['n']} {m['p']:.2f} ({m['ic'][0]:.2f}-{m['ic'][1]:.2f})".replace(".", ",")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--verdad", default=str(_AQUI / "verdad-terreno.toml"))
    ap.add_argument("--brazo", action="append", default=[], metavar="NOMBRE=ARCHIVO|CORRIDA",
                    help="hallazgos_todos.jsonl o carpeta de corrida con decisiones_ia.json (repetible)")
    ap.add_argument("--brazo-d-desde", default=None, help="hallazgos_todos.jsonl del que derivar el brazo D")
    ap.add_argument("--json", default=None, help="escribe el resultado completo en JSON")
    a = ap.parse_args(argv)

    defectos, limpios = metricas.leer_verdad(a.verdad)
    brazos = {}
    for b in a.brazo:
        nombre, ruta = b.split("=", 1)
        p = Path(ruta)
        brazos[nombre] = hallazgos_despues(p) if p.is_dir() else metricas.leer_hallazgos(p)
    if a.brazo_d_desde:
        brazos["D"] = brazo_d(metricas.leer_hallazgos(a.brazo_d_desde))
    salida = {}
    for nombre, hs in brazos.items():
        for sub in ("todo", "desarrollo", "reservado"):
            for tt in (False, True):
                m = metricas_brazo(hs, defectos, limpios, sub, tras_triage=tt)
                salida[f"{nombre}|{sub}|{'tras' if tt else 'antes'}"] = m
                print(f"{nombre:<6} {sub:<10} {'tras' if tt else 'antes':<5} sens {_f(m['sens_global'])} · "
                      f"SEG·N1 {_f(m['sens_seg_n1'])} · VPP {_f(m['vpp'])} · FP limpios {_f(m['fp_limpios'])}")
    if a.json:
        Path(a.json).write_text(json.dumps(salida, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
