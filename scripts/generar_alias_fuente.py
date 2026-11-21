#!/usr/bin/env python3
"""Genera catalogo/alias_fuente.json: todos los IDs de checks de los informes 01-08.

Reglas:
  1. ID "definido": aparece como primera celda de una fila de tabla (``| VC-01 |``)
     en un informe 01-08. Se asigna a ese informe.
  2. ID "referenciado": aparece en el texto de un informe 01-08 sin estar definido
     en ninguna tabla (p. ej. UX-14, ING-01, ECO-02 citados en el informe 08).
  3. ID "implicito": numeración de los hallazgos de los informes 05 (UX), 06 (ING)
     y 07 (ECO) que esos informes no escriben como ID; la usan los informes 08 y
     09-diseno-A/B. Se incluye solo si aparece literalmente en 08 o 09.
     No se inventan IDs que no aparezcan en ningún documento.

Uso: python3 scripts/generar_alias_fuente.py  (sobrescribe el JSON).
"""

import json
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
INVESTIGACION = RAIZ / "investigacion"
SALIDA = RAIZ / "catalogo" / "alias_fuente.json"

PATRON_ID = re.compile(r"\b(VC|SEC|DB|INF|UX|ING|ECO|GAP)-(\d{2})\b")
PATRON_DEF = re.compile(r"^\|\s*\**((?:VC|SEC|DB|INF|UX|ING|ECO|GAP)-\d{2})\**\s*\|", re.M)
# Prefijos sin tabla propia: informe al que pertenece su numeración.
PREFIJO_IMPLICITO = {"UX": "05", "ING": "06", "ECO": "07"}


def _informe(ruta):
    return ruta.name[:2]


def generar():
    informes = sorted(INVESTIGACION.glob("0[1-8]-*.md"))
    disenos = sorted(INVESTIGACION.glob("09-*.md"))
    ids, origen = {}, {}

    for ruta in informes:
        for m in PATRON_DEF.finditer(ruta.read_text(encoding="utf-8")):
            ids.setdefault(m.group(1), _informe(ruta))
            origen.setdefault(m.group(1), "definido")

    for ruta in informes + disenos:
        texto = ruta.read_text(encoding="utf-8")
        for m in PATRON_ID.finditer(texto):
            i, pref = m.group(0), m.group(1)
            if i in ids:
                continue
            if pref in PREFIJO_IMPLICITO:
                ids[i] = PREFIJO_IMPLICITO[pref]
                origen[i] = "implicito" if ruta in disenos else "referenciado"
            elif ruta in informes:
                ids[i] = _informe(ruta)
                origen[i] = "referenciado"
            # Un ID VC/SEC/DB/INF/GAP que solo aparece en 09 no se agrega.

    orden = lambda i: (i.split("-")[0], int(i.split("-")[1]))  # noqa: E731
    return {
        "_descripcion": (
            "IDs de checks de los informes 01-08 (id -> informe). 'origen' indica si el ID "
            "está definido en una tabla del informe, solo referenciado en el texto, o es la "
            "numeración implícita de 05/06/07 usada por 08 y 09-diseno-A/B. Generado por "
            "scripts/generar_alias_fuente.py; no editar a mano."
        ),
        "ids": {i: ids[i] for i in sorted(ids, key=orden)},
        "origen": {i: origen[i] for i in sorted(ids, key=orden)},
    }


def main():
    datos = generar()
    SALIDA.write_text(json.dumps(datos, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(datos['ids'])} IDs -> {SALIDA}")


if __name__ == "__main__":
    main()
