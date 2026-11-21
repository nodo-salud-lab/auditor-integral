#!/usr/bin/env python3
"""meta.py — escribe crudo/<herramienta>.meta.json, el registro de cada ejecución de un adaptador.

Forma (común a adaptadores y chequeos propios):
  {
    "herramienta": "gitleaks", "version": "8.30.1" | null,
    "estado": "ok" | "parcial" | "error" | "ausente" | "timeout" | "no_aplica" | "no_evaluado",
    "exit_code": int | null, "duracion_s": float, "comando": str, "error": str | null,
    "salidas": ["gitleaks.json", ...],          # relativas a crudo/
    "ejecuciones": [{modo, comando, exit_code, duracion_s, salida, estado, error}],   # opcional
    ...extra                                    # campos propios del adaptador (p. ej. prefijo_git)
  }
Estados: ok = la herramienta corrió bien (con o sin hallazgos; p. ej. gitleaks exit 1/10);
parcial = corrió solo una parte (p. ej. semgrep sin el registro); error = falló;
ausente = no está instalada; timeout = superó el límite; no_aplica = no hay nada que analizar;
no_evaluado = no se pudo evaluar por una condición externa (p. ej. sin red).

Uso:
  meta.py --salida F --herramienta H --estado E [--version V] [--exit-code N] [--duracion S]
          [--comando C] [--error TXT | --error-archivo LOG] [--salidas a,b] [--ejecuciones-jsonl F]
          [--extra-json '{"k": "v"}']
"""
import argparse
import json
import re
import sys
from pathlib import Path

ESTADOS = ("ok", "parcial", "error", "ausente", "timeout", "no_aplica", "no_evaluado")
MAX_ERROR = 600
# Los mensajes de error de las herramientas pueden citar líneas del código: se enmascaran
# las cadenas con forma de credencial antes de guardarlas.
RE_CREDENCIAL = re.compile(r"(sk|rk|pk)_(live|test)_[A-Za-z0-9]{6,}|sk-[A-Za-z0-9_-]{16,}|"
                           r"(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
                           r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")


def limpiar_error(texto):
    if not texto:
        return None
    texto = re.sub(r"\x1b\[[0-9;]*m", "", texto)            # colores ANSI
    texto = RE_CREDENCIAL.sub(lambda m: m.group(0)[:4] + "****", texto)
    texto = " ".join(texto.split())
    if len(texto) > MAX_ERROR:
        texto = "…" + texto[-(MAX_ERROR - 1):]               # el final suele tener la causa
    return texto or None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--salida", required=True)
    ap.add_argument("--herramienta", required=True)
    ap.add_argument("--estado", required=True, choices=ESTADOS)
    ap.add_argument("--version")
    ap.add_argument("--exit-code", type=int)
    ap.add_argument("--duracion", type=float, default=0.0)
    ap.add_argument("--comando", default="")
    ap.add_argument("--error")
    ap.add_argument("--error-archivo")
    ap.add_argument("--salidas", default="")
    ap.add_argument("--ejecuciones-jsonl")
    ap.add_argument("--extra-json")
    a = ap.parse_args(argv)

    error = a.error
    if not error and a.error_archivo:
        try:
            error = Path(a.error_archivo).read_text(encoding="utf-8", errors="replace")
        except OSError:
            error = None
    datos = {
        "herramienta": a.herramienta,
        "version": a.version or None,
        "estado": a.estado,
        "exit_code": a.exit_code,
        "duracion_s": round(a.duracion, 3),
        "comando": a.comando,
        "error": limpiar_error(error) if a.estado != "ok" or error else None,
        "salidas": [s for s in a.salidas.split(",") if s],
    }
    if a.ejecuciones_jsonl:
        ejecuciones = []
        try:
            for linea in Path(a.ejecuciones_jsonl).read_text(encoding="utf-8").splitlines():
                if linea.strip():
                    e = json.loads(linea)
                    e["error"] = limpiar_error(e.get("error"))
                    ejecuciones.append(e)
        except (OSError, json.JSONDecodeError):
            pass
        datos["ejecuciones"] = ejecuciones
    if a.extra_json:
        datos.update(json.loads(a.extra_json))
    salida = Path(a.salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    tmp = salida.with_suffix(".tmp")
    tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(salida)
    return 0


if __name__ == "__main__":
    sys.exit(main())
