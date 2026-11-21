#!/usr/bin/env python3
"""resumen_corrida.py — lectura de 10 segundos de una corrida terminada (H-13 / mejora «auditar-aqui»).

Uso: resumen_corrida.py --corrida C

Lee SOLO C/gates.json y C/run.json y escribe en stderr unas pocas líneas: nivel demostrado y potencial,
«¿listo para datos reales?», bloqueos contados por control (no por entrada), cobertura por nivel, por qué
queda N0 cuando no hay bloqueos y las 3 rutas en orden de lectura (resumen-dueno → informe → hoja-de-ruta).

Fail-closed: no recalcula ni reinterpreta estados; solo cuenta lo que gates.json ya trae. Si gates.json
falta o no se puede leer, lo dice y termina con rc 1 (no inventa un nivel). Nunca lee crudo/ ni hallazgos.

Solo biblioteca estándar.
"""
import argparse
import json
import sys
from pathlib import Path

NIVELES = ("N1", "N2", "N3", "N4", "N5")
ORDEN_LECTURA = (("resumen-dueno.md", "resumen para la persona dueña"),
                 ("informe.md", "ir a «Qué hacer ahora»"),
                 ("hoja-de-ruta.md", "plan por niveles"))


def _leer(ruta):
    try:
        datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return datos if isinstance(datos, dict) else None


def _por_que_n0(gates):
    """Frase para N0 sin bloqueos: en qué dominios N1 no quedó demostrado, con cuántos fail y sin evaluar."""
    dominios = [d for d, v in (gates.get("dominios") or {}).items()
                if isinstance(v, dict) and v.get("activo") and v.get("nivel_demostrado") == "N0"]
    fallan, sin_eval = set(), set()
    for d in dominios:
        n1 = ((gates["dominios"][d].get("niveles") or {}).get("N1") or {})
        fallan.update(n1.get("fallidos") or [])
        sin_eval.update(n1.get("pendientes") or [])
    if not dominios:
        return "N0 sin bloqueos: gates.json no indica qué dominio lo deja en N0 (revise informe.md)."
    return (f"N0 porque N1 no quedó demostrado en {len(dominios)} dominio(s) ({', '.join(dominios)}): "
            f"{len(fallan)} control(es) de N1 fallan y {len(sin_eval)} quedan sin evaluar o pendientes de "
            "verificación manual.")


def lineas(corrida):
    corrida = Path(corrida)
    run = _leer(corrida / "run.json") or {}
    gates = _leer(corrida / "gates.json")
    cab = f"Corrida {run.get('id') or corrida.name} · modo {run.get('modo') or 's/d'}"
    if gates is None or not isinstance(gates.get("global"), dict):
        fallidas = [f for f, v in (run.get("fases") or {}).items()
                    if isinstance(v, dict) and v.get("estado") not in ("ok", None)]
        return [cab,
                "Sin gates.json legible: la corrida no llegó a calcular niveles; no hay nivel que informar.",
                "Fases con problema según run.json: " + (", ".join(fallidas) if fallidas else "ninguna registrada")], 1
    g = gates["global"]
    nd, np_ = g.get("nivel_demostrado", "s/d"), g.get("nivel_potencial", "s/d")
    bloqueos = [b for b in (g.get("bloqueos") or []) if isinstance(b, dict)]
    controles_bloq = sorted({b.get("control") for b in bloqueos if b.get("control")})
    salida = [cab,
              f"Nivel demostrado: {nd} ({g.get('hito') or 's/d'}) · potencial {np_}",
              f"¿Listo para datos reales?: {g.get('listo_datos_reales', 's/d')}"]
    if controles_bloq:
        muestra = ", ".join(controles_bloq[:5]) + (f" y {len(controles_bloq) - 5} más" if len(controles_bloq) > 5 else "")
        # Ronda 6 (DECISIONES.md #12): gates.json trae una entrada por control (con «tipos»/«motivos»); el número de
        # entradas solo se muestra si difiere (gates.json de una versión anterior).
        salida.append(f"Bloqueos: {len(controles_bloq)} control(es) ({muestra})"
                      + (f"; {len(bloqueos)} entrada(s) en gates.json" if len(bloqueos) != len(controles_bloq) else ""))
    else:
        salida.append("Bloqueos: 0 controles")
    cob = gates.get("cobertura_por_nivel") or {}
    partes = [f"{n} {cob[n].get('evaluados', 0)}/{cob[n].get('aplicables', 0)}"
              for n in NIVELES if isinstance(cob.get(n), dict) and cob[n].get("aplicables")]
    salida.append("Cobertura (evaluados/aplicables): " + (" · ".join(partes) if partes else "s/d")
                  + "; no_evaluado significa «no sabemos», no «está bien»")
    if nd == "N0" and not controles_bloq:
        salida.append(_por_que_n0(gates))
    salida.append("Leer en este orden:")
    for i, (nombre, para) in enumerate(ORDEN_LECTURA, 1):
        ruta = corrida / nombre
        salida.append(f"  {i}. {ruta}" + (f"  ({para})" if ruta.is_file() else "  (no generado)"))
    return salida, 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Resumen legible de una corrida (lee gates.json y run.json).")
    ap.add_argument("--corrida", required=True)
    a = ap.parse_args(argv)
    if not Path(a.corrida).is_dir():
        print(f"resumen_corrida: no es una carpeta: {a.corrida}", file=sys.stderr)
        return 2
    texto, rc = lineas(a.corrida)
    print("\n".join(texto), file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
