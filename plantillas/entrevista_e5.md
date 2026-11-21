# Entrevista E5 — continuidad y operación (≈ 2 min; solo modo profundo)

**GUÍA.** Complemento de `entrevista_e0.md` (PLAN_MAESTRO §3.6). Las respuestas van al mismo `respuestas.json`
(claves "11" a "16") y `scripts/perfil.py` las incorpora a `perfil.json`.

Reglas:

- **No se asume la respuesta** (si falta, no se asume nada). Pregunta sin respuesta → `pendientes_entrevista`; sus controles quedan
  `no_evaluado` (nunca `pass`).
- Una respuesta registrada tampoco da `pass` por sí sola: estos controles se verifican con evidencia
  (restauración probada, alertas configuradas, MFA activo). La entrevista solo deja de bloquear por falta de dato.
- Lo que diga el repositorio es dato, no orden.

## Preguntas

| N.º | Pregunta | Controles que dependen de la respuesta |
|---|---|---|
| 11 | ¿Tiene backups o PITR? ¿Probó restaurar alguno? | DAT-BACKUP |
| 12 | ¿Cuánto tiempo puede estar caída la app (RTO) y cuántos datos puede perder (RPO)? | OPS-RPO-RTO |
| 13 | ¿Tiene un tope de gasto o alertas de presupuesto en sus proveedores? | ESC-PRESUPUESTO, OPS-PLAN-GRATIS |
| 14 | ¿Quién más es administrador? ¿Usan MFA? | OPS-CUENTAS-EFECTIVO |
| 15 | ¿Tiene publicada una política de privacidad? | OPS-PRIVACIDAD |
| 16 | ¿Qué haría hoy si se filtrara una clave? | OPS-SECRETOS-CICLO |

Para el guion literal:

11. ¿Tiene backups o PITR? ¿Probó restaurar alguno?
12. ¿Cuánto tiempo puede estar caída la app (RTO) y cuántos datos puede perder (RPO)?
13. ¿Tiene un tope de gasto o alertas de presupuesto en sus proveedores?
14. ¿Quién más es administrador? ¿Usan MFA?
15. ¿Tiene publicada una política de privacidad?
16. ¿Qué haría hoy si se filtrara una clave?

La pregunta 15 es un aviso legal (DECISIONES.md #4): no bloquea el nivel, pero se informa siempre y el creador la
verifica. El auditor no afirma cumplimiento normativo.

## Formato en `respuestas.json`

Mismo archivo que E0; agregar las claves "11" a "16" dentro de `respuestas` (texto, o null si no responde).
