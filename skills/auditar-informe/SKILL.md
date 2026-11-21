---
name: auditar-informe
description: "Regenera informe.md, resumen-dueno.md, hoja-de-ruta.md y merged.sarif de una corrida existente del auditor-integral a partir de su estado (estado.json, gates.json, veredictos aplicados), sin volver a escanear. Úsalo con /auditar-informe [ruta] o tras responder la entrevista, cargar evidencia manual o aplicar veredictos."
allowed-tools: Bash Read
---

# /auditar-informe — regenerar el informe desde el estado

No escanea ni llama a la IA: vuelve a calcular compuertas y a rellenar las plantillas con lo que ya está en
la corrida. Tope ≈ 1 k tokens.

## Uso

```
/auditar-informe [ruta] [--corrida DIR]
```

Sin `--corrida`, usa la corrida más reciente de `<ruta>/.auditoria/`.

## Procedimiento

1. Resuelve `P` (por defecto el directorio actual) y `C` (la corrida indicada o la última). Comillas
   siempre: las rutas pueden tener espacios. `A="${CLAUDE_PLUGIN_ROOT}/bin/auditar"`.
2. Si cambió el perfil o hay veredictos nuevos, recalcula; si no, basta con el informe:
   ```bash
   test -f "$C/veredictos.jsonl" && "$A" veredictos "$P" --salida "$C"
   "$A" gates "$P" --salida "$C"
   "$A" report "$P" --salida "$C"
   ```
   `report` reescribe `informe.md`, `resumen-dueno.md`, `hoja-de-ruta.md` y `merged.sarif` desde
   `estado.json`, `gates.json`, `roadmap.json`, `tokens.json` y, si valida, `redaccion-dueno.json`.
3. Lee solo `"$C/gates.json"` y las secciones «Qué hizo el auditor», «Qué falta» y «Qué hacer ahora» de
   `"$C/informe.md"`, y presenta: nivel demostrado y potencial y las rutas de los tres archivos, en orden de
   lectura (`resumen-dueno.md` → «Qué hacer ahora» de `informe.md` → `hoja-de-ruta.md`). Si el usuario pregunta
   qué cambió respecto de la corrida anterior, no compares informes a ojo: usa el script (solo lectura; lee
   `gates.json`, `estado.json`, `hallazgos.jsonl` y `run.json`, nunca `crudo/`):
   ```bash
   python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/comparar_corridas.py" --proyecto "$P"
   # o, con dos corridas concretas:
   python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/comparar_corridas.py" --antes "$C_ANTERIOR" --despues "$C"
   ```
   Si la salida trae «Aviso: corridas no comparables» (cambió el modo, la red o la versión), dilo antes que
   cualquier mejora o empeoramiento. rc 4 = no hay dos corridas.

## Reglas

- Prohibido leer `crudo/`, `hallazgos_todos.jsonl`, `node_modules/`, lockfiles o `.env*`.
- No edites `informe.md` a mano: todo cambio pasa por los datos de la corrida y las plantillas.
- No escribe fuera de `<ruta>/.auditoria/`. Si una fase devuelve 3 (pendiente) o 4 (sin corrida), dilo tal
  cual; no inventes resultados.
- El auditor no certifica seguridad ni cumplimiento legal.
