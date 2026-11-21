# Propuesta: ampliar `veredicto.schema.json` (v2) y agregar `redaccion.schema.json`

**Estado: BORRADOR** (F3-B, 2026-11-18). No se aplicó: el schema vigente sigue igual porque `scripts/veredictos.py`
(F3-A) valida contra él. Lo decide el investigador; si se aprueba, el cambio es aditivo y compatible hacia atrás
(todos los campos nuevos son opcionales).

## 1. Qué falta en el schema vigente

Revisado contra el contrato F3 (§3.3, §9, §10 F3 del PLAN_MAESTRO):

| Campo pedido | Schema vigente | Problema | Propuesta |
|---|---|---|---|
| `control`, `hallazgo_id`, `veredicto`, `razon`, `modelo` | Sí | — | Sin cambio. |
| `veredicto` ∈ {verdadero, falso_positivo, incierto, pass, fail} | Sí, más `no_evaluado` | — | Sin cambio (`no_evaluado` sirve para declarar «no pude juzgar»). |
| evidencia `archivo:línea` | `ubicaciones` (array, patrón `^.+:[0-9]+$`) | Cumple; el nombre difiere del pedido («evidencia») | Mantener `ubicaciones`. No agregar `evidencia` como texto libre: duplicaría código del repo en `veredictos.jsonl` y abriría una vía para filtrar secretos sin enmascarar. Agregar `maxItems: 3` (coincide con el tope de ≤ 3 fragmentos por agente). |
| `confianza` | No (`additionalProperties: false`) | Una línea con `confianza` se descarta entera | `"confianza": {"enum": ["alta", "media", "baja"]}`, opcional. |
| `tokens_estimados` | No | Ídem; sin él no se puede atribuir consumo por agente si `medir_tokens.py` no ve el transcript | `"tokens_estimados": {"type": "integer", "minimum": 0, "maximum": 20000}`, opcional. |
| `metodo` (cómo se verificó un `pass`) | No | Las pruebas de F3-A (`tests/test_f3a_veredictos.py`) exigen `metodo` para aceptar un `pass` LLM; con el schema vigente una línea con `metodo` no valida. Los prompts lo incluyen **solo** en `pass` (un pass sin él se descarta igual, así que no se pierde nada) | `"metodo": {"type": "string", "minLength": 1, "maxLength": 200}`, opcional. **Coordinar con F3-A**: si `veredictos.py` ya amplía el schema, esta fila sobra. |
| marca de inyección | No | Hoy va como prefijo `POSIBLE INYECCIÓN:` en `razon` (convención de los prompts) | `"inyeccion_detectada": {"type": "boolean"}`, opcional; `veredictos.py` podría contarla en el informe sin parsear texto. |
| `requiere_verificacion_humana` | Sí, opcional | Los prompts la exigen en todo juicio | Pasarla a `required` en v2 (sin ella, la línea se descarta: fail-closed). |
| `version_esquema` | No | No se puede distinguir v1 de v2 al validar | `"version_esquema": {"enum": ["1", "2"]}`, opcional (ausente = 1). |

### Bloque a agregar en `properties` (v2)

```json
"version_esquema": {"enum": ["1", "2"]},
"confianza": {"enum": ["alta", "media", "baja"]},
"tokens_estimados": {"type": "integer", "minimum": 0, "maximum": 20000},
"inyeccion_detectada": {"type": "boolean"},
"metodo": {"type": "string", "minLength": 1, "maxLength": 200}
```

`enum`, `type`, `minimum` y `maximum` están en el subconjunto que soporta `scripts/validar_schema.py`.
**`maxItems` no está soportado hoy**: el tope de 3 `ubicaciones` se aplica en `veredictos.py`, o se agrega
`maxItems` al validador con su test antes de ponerlo en el schema.

### Cómo se activa en los prompts

Los cuatro agentes de veredictos (`agents/revisor-autorizacion.md`, `revisor-arquitectura.md`, `triage-fp.md`,
`revisor-ux.md`) ya incluyen `confianza` y `tokens_estimados` **solo** si el orquestador les pasa
`schema_veredicto=2`. El skill `/auditar` pasa esa marca solo si `schemas/veredicto.schema.json` define
`confianza`. Así, aprobar la v2 no exige tocar los prompts y, mientras no se apruebe, ninguna línea se descarta
por campos de más.

## 2. Salida del `redactor-dueno`: schema propio (`redaccion.schema.json`)

El redactor no emite veredictos sobre controles: reescribe textos. Forzarlo a `veredicto.schema.json`
(`control` obligatorio, `veredicto` del enum) mezclaría juicios con redacción en `veredictos.jsonl`. Se propone un
archivo aparte, `<corrida>/redaccion-dueno.json`, con este schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://auditor-integral.local/schemas/redaccion.schema.json",
  "title": "Redacción del dueño (redactor-dueno)",
  "type": "object",
  "required": ["agente", "resumen", "por_que_importa", "modelo"],
  "additionalProperties": false,
  "properties": {
    "agente": {"const": "redactor-dueno"},
    "resumen": {"type": "string", "minLength": 1, "maxLength": 1600},
    "por_que_importa": {"type": "object"},
    "modelo": {"type": "string", "minLength": 1, "maxLength": 80}
  }
}
```

Las reglas que JSON Schema no expresa con el validador stdlib (≤ 200 palabras en `resumen`, ≤ 25 palabras por
ítem, claves de `por_que_importa` ⊆ controles de `roadmap.json`) ya las aplica `render_informe.validar_redaccion`
(F3-B, con tests en `tests/test_informe_secciones_f3.py`). Si no valida, el texto se descarta, el resumen usa la
plantilla y lo dice («texto del redactor descartado: …»).

## 3. Lo que esta propuesta no cambia

- La regla de `gates.py`: el LLM nunca convierte un `fail` determinista en `pass`; solo `falso_positivo` con razón.
- La regla (a) de `veredictos.py`: un `falso_positivo` sobre un hallazgo crítico o alto (`SEVERIDADES_FP_HUMANO`)
  nunca deja el control en `pass` ni en `no_aplica` (alcance 0): queda `no_evaluado` con motivo «falso positivo
  crítico según IA (…)» o «falso positivo alto según IA (…)» (si hay algún crítico, la etiqueta es «crítico»),
  seguido de «: requiere verificación humana; no hay pass sin ella»; o `fail` si hay otro hallazgo efectivo. Sobre
  medio/bajo el falso positivo válido descarta el hallazgo (sin cambio).
- `agente` sigue cerrado a los cinco subagentes del plugin.
- `razon` sigue ≤ 500 caracteres y pasa por `enmascarar.py` antes de cualquier informe.
