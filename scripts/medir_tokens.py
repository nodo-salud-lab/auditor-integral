#!/usr/bin/env python3
"""Tokens LLM reales desde transcripts de subagentes de Claude Code → tokens.json (PLAN_MAESTRO §9; F3 criterio 5).

Entrada: un directorio (se recorre recursivamente) con transcripts *.jsonl de Claude Code. Cada línea de respuesta
del modelo trae message.id y message.usage = {input_tokens, output_tokens, cache_read_input_tokens,
cache_creation_input_tokens}. Claude Code repite la misma respuesta en varias líneas (una por bloque de contenido):
se DEDUPLICA por message.id en todo el directorio, quedándose con la línea de mayor output_tokens (la final); un id
repetido entre archivos se cuenta una sola vez, para el primer archivo en orden alfabético.

Nombre del agente, en este orden: <archivo>.meta.json vecino con agentType/subagent_type/nombre; el campo
agentType/subagent_type/agentName de alguna línea; el nombre del archivo sin extensión. El prefijo del plugin
(«auditor-integral:triage-fp») se quita. Fase (config/presupuesto_tokens.toml): revisor-autorizacion → f4a,
revisor-arquitectura → f4b, revisor-ux → f4c, triage-fp → f4d, redactor-dueno → f6_informe, auditar-perfil → f1;
cualquier otro → orquestacion.

Salida (sin rutas absolutas ni contenido de los mensajes):
  {version_esquema, fuente (nombre de la carpeta), archivos, lineas_invalidas, mensajes_duplicados,
   definicion_total, por_agente: {agente: {input_tokens, output_tokens, cache_read_input_tokens,
   cache_creation_input_tokens, total, mensajes, fase}}, por_fase: {fase: total}, total: {… igual …},
   presupuesto (con --modo): {modo, meta, tope_meta, techo_duro, excede_meta, excede_techo_duro}}
total = input + output + cache_read + cache_creation (todo lo que el modelo procesó; las lecturas de caché se
cobran más barato, pero ocupan contexto). Las cifras son las que reporta la API: no se estiman.

Uso:  medir_tokens.py DIR_TRANSCRIPTS [--salida tokens.json] [--modo rapido|estandar|profundo]
      medir_tokens.py [DIR_TRANSCRIPTS] --corrida DIR_CORRIDA [--salida …] [--modo …]
--corrida (forma del skill /auditar, A1): sin DIR_TRANSCRIPTS busca los transcripts SOLO en DIR_CORRIDA/transcripts/
(la corrida misma no es fuente: trae veredictos.jsonl, que escribe la IA, y hallazgos*.jsonl); la salida por defecto
es DIR_CORRIDA/tokens.json. Los artefactos conocidos de una corrida (ARTEFACTOS_CORRIDA) nunca se leen como
transcripts, se pase la carpeta que se pase. Fail-closed: si no hay ningún mensaje con message.usage no se escribe
archivo (un total 0 se leería como medido y dentro de presupuesto); si la salida es la de --corrida y ya había un
tokens.json, se renombra a tokens.json.obsoleto para que el informe diga «no medido» y no muestre una cifra vieja.
"""
import argparse
import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import utiles  # noqa: E402

CAMPOS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
CLAVES_TIPO = ("agentType", "subagent_type", "agentName", "nombre")
FASE = {"revisor-autorizacion": "f4a_autorizacion", "revisor-arquitectura": "f4b_arquitectura_stride",
        "revisor-ux": "f4c_ux", "triage-fp": "f4d_triage", "redactor-dueno": "f6_informe",
        "auditar-perfil": "f1_perfil_flujograma"}
RUTA_PRESUPUESTO = utiles.RAIZ / "config" / "presupuesto_tokens.toml"
# *.jsonl que escriben los scripts o la IA en la corrida: no son transcripts de Claude Code (verificador A1)
ARTEFACTOS_CORRIDA = frozenset({"veredictos.jsonl", "hallazgos.jsonl", "hallazgos_todos.jsonl",
                                "hallazgos_ia.jsonl", "ejecuciones.jsonl"})
SUBCARPETA_TRANSCRIPTS = "transcripts"


def _num(x):
    return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else 0


def _nombre_meta(ruta):
    meta = ruta.with_name(ruta.name[:-len(".jsonl")] + ".meta.json")
    datos = utiles.leer_json(meta) if meta.is_file() else None
    if isinstance(datos, dict):
        for k in CLAVES_TIPO:
            if isinstance(datos.get(k), str) and datos[k].strip():
                return datos[k].strip()
    return None


def _limpiar(nombre):
    return nombre.split(":", 1)[1] if ":" in nombre else nombre


def _vacio():
    return {**{c: 0 for c in CAMPOS}, "total": 0, "mensajes": 0}


def medir(directorio, modo=None):
    directorio = Path(directorio)
    archivos = sorted((p for p in directorio.rglob("*.jsonl") if p.name not in ARTEFACTOS_CORRIDA),
                      key=lambda p: p.relative_to(directorio).as_posix()) if directorio.is_dir() else []
    mensajes = {}       # id → (agente, usage)
    duplicados = invalidas = 0
    for ruta in archivos:
        nombre = _nombre_meta(ruta)
        filas = []
        for linea in ruta.read_text(encoding="utf-8", errors="replace").splitlines():
            if not linea.strip():
                continue
            try:
                d = json.loads(linea)
            except ValueError:
                invalidas += 1
                continue
            if not isinstance(d, dict):
                invalidas += 1
                continue
            if nombre is None:
                for k in CLAVES_TIPO:
                    if isinstance(d.get(k), str) and d[k].strip():
                        nombre = d[k].strip()
                        break
            m = d.get("message")
            if isinstance(m, dict) and isinstance(m.get("usage"), dict) and isinstance(m.get("id"), str):
                filas.append((m["id"], {c: _num(m["usage"].get(c)) for c in CAMPOS}))
        agente = _limpiar(nombre or ruta.name[:-len(".jsonl")])
        for mid, uso in filas:
            if mid in mensajes:
                duplicados += 1
                previo_agente, previo = mensajes[mid]
                if previo_agente == agente and uso["output_tokens"] >= previo["output_tokens"]:
                    mensajes[mid] = (agente, uso)
                continue
            mensajes[mid] = (agente, uso)
    por_agente, total = {}, _vacio()
    for agente, uso in mensajes.values():
        a = por_agente.setdefault(agente, _vacio())
        for destino in (a, total):
            for c in CAMPOS:
                destino[c] += uso[c]
            destino["total"] += sum(uso.values())
            destino["mensajes"] += 1
    por_fase = {}
    for agente, a in sorted(por_agente.items()):
        a["fase"] = FASE.get(agente, "orquestacion")
        por_fase[a["fase"]] = por_fase.get(a["fase"], 0) + a["total"]
    res = {"version_esquema": "1", "fuente": directorio.name, "archivos": len(archivos),
           "lineas_invalidas": invalidas, "mensajes_duplicados": duplicados,
           "definicion_total": "input + output + cache_read + cache_creation (cifras de la API, sin estimar)",
           "por_agente": dict(sorted(por_agente.items())), "por_fase": dict(sorted(por_fase.items())),
           "total": total}
    if modo:
        pres = ((utiles.leer_toml(RUTA_PRESUPUESTO) or {}).get("total") or {}).get(modo) or {}
        res["presupuesto"] = {"modo": modo, "meta": pres.get("meta"), "tope_meta": pres.get("tope_meta"),
                              "techo_duro": pres.get("techo_duro"),
                              "excede_meta": bool(pres.get("meta")) and total["total"] > pres["meta"],
                              "excede_techo_duro": bool(pres.get("techo_duro")) and total["total"] > pres["techo_duro"]}
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="Suma tokens de transcripts de subagentes → tokens.json")
    ap.add_argument("directorio", nargs="?", metavar="DIR_TRANSCRIPTS")
    ap.add_argument("--corrida", metavar="DIR_CORRIDA",
                    help="carpeta de la corrida: salida por defecto <corrida>/tokens.json; sin DIR_TRANSCRIPTS, "
                         "los transcripts se buscan solo en <corrida>/transcripts/")
    ap.add_argument("--salida")
    ap.add_argument("--modo", choices=("rapido", "estandar", "profundo"))
    a = ap.parse_args(argv)
    if not (a.directorio or a.corrida):
        print("medir_tokens.py: indique DIR_TRANSCRIPTS o --corrida DIR_CORRIDA", file=sys.stderr)
        return 2
    for d in (a.directorio, a.corrida):
        if d and not Path(d).is_dir():
            print(f"medir_tokens.py: no es una carpeta: {d}", file=sys.stderr)
            return 2
    # sin DIR_TRANSCRIPTS: solo <corrida>/transcripts/ (puede no existir → no medido); nunca la corrida entera
    directorio = a.directorio or str(Path(a.corrida) / SUBCARPETA_TRANSCRIPTS)
    salida = a.salida or (str(Path(a.corrida) / "tokens.json") if a.corrida else None)
    res = medir(directorio, a.modo)
    if salida and not res["total"]["mensajes"]:
        aviso = ""
        if not a.salida and Path(salida).exists():
            # un tokens.json anterior se leería como medición de esta corrida: se aparta (no se borra)
            Path(salida).replace(Path(salida).with_name("tokens.json.obsoleto"))
            aviso = "; el tokens.json anterior se renombró a tokens.json.obsoleto"
        print(f"tokens: no medido: {res['archivos']} archivo(s) *.jsonl de transcripts sin mensajes con "
              f"message.usage; no se escribe tokens.json (un 0 no es una medición){aviso}", file=sys.stderr)
        return 0
    if salida:
        utiles.escribir_json(salida, res)
    else:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    t = res["total"]
    print(f"tokens: total {t['total']} en {t['mensajes']} mensajes de {len(res['por_agente'])} agente(s)"
          + (f"; techo duro {res['presupuesto']['techo_duro']}" if "presupuesto" in res else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
