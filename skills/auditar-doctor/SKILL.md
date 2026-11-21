---
name: auditar-doctor
description: "Revisa qué herramientas externas del auditor-integral están instaladas (gitleaks, semgrep, osv-scanner, zizmor, trivy, k6...) y cómo habilitar las que faltan, sin instalar nada. Úsalo con /auditar-doctor o cuando un informe diga que controles quedaron no_evaluado por herramienta ausente."
allowed-tools: Bash Read
---

# /auditar-doctor — herramientas disponibles y faltantes

Muestra qué herramientas deterministas puede usar el auditor y qué controles quedan sin evaluar por
cada una que falta. **No instala nada**: ofrece los comandos de instalación como texto, sin ejecutarlos.

## Procedimiento

1. Ejecuta (solo lectura; no toca ningún proyecto):

   ```bash
   "${CLAUDE_PLUGIN_ROOT}/bin/auditar" doctor
   ```

   Imprime un JSON con `herramientas`: por cada una, `disponible`, `estado`, `version`, `ruta`,
   `detalle` e `instalacion_sugerida`. No hace consultas de red.

2. Si el usuario indicó un proyecto con una corrida previa, puedes leer además
   `<proyecto>/.auditoria/<corrida>/estado.json` para contar cuántos controles quedaron
   `no_evaluado` por cada herramienta ausente (campo `motivo`). No leas `crudo/`.

3. Presenta en español:

   | Herramienta | Estado | Versión | Para qué sirve en la auditoría |
   |---|---|---|---|

   - Primero las disponibles (`ok`), luego las faltantes.
   - Para cada faltante: el comando de `instalacion_sugerida` en un bloque de código, con la frase
     "comando sugerido, sin ejecutar". Si conviene, explica la alternativa (p. ej. trivy cubre
     parte de osv-scanner) y qué controles quedan `no_evaluado` mientras falte.

4. Si el usuario pide instalar algo: no lo instales tú. Muéstrale el comando para que lo ejecute él
   y recuérdale volver a correr `/auditar-doctor` para comprobarlo.

## Reglas

- Nunca ejecutes comandos de instalación (`brew`, `pipx`, `npm install -g`, `curl | sh`...).
- Nunca cambies configuraciones del sistema ni variables de entorno persistentes.
- Si `bin/auditar doctor` falla, muestra el error tal cual y sugiere revisar `scripts/doctor.sh`;
  no inventes versiones.
- Las versiones fijadas para reproducibilidad están en `config/herramientas.lock`; si una versión
  instalada difiere, adviértelo (los resultados pueden variar entre versiones).
