#!/usr/bin/env bash
# semgrep.sh — SAST con el paquete p/owasp-top-ten del registro + reglas propias vibe-coding.
# Uso: semgrep.sh PROYECTO DIR_CRUDO                         → crudo/semgrep.sarif
#
# - Siempre --metrics=off, sin chequeo de versión, excluye node_modules y .auditoria.
# - Un .semgrepignore o .gitignore del repo auditado NO puede ocultar archivos (corrección
#   post-verificación): --no-git-ignore y --x-ignore-semgrepignore-files (opción experimental de
#   semgrep 1.181; si una versión futura la quita, la ejecución falla y el meta queda en error, no en
#   un pass silencioso). Las exclusiones que antes daba el .semgrepignore por defecto de semgrep se
#   fijan aquí (EXCLUSIONES). El meta anota en ignores_proyecto los archivos de ignore presentes.
# - Se ejecuta desde la raíz del proyecto: las URIs del SARIF quedan relativas a ella.
# - El paquete del registro requiere red. Si falla (sin red, registro caído), se repite solo con las
#   reglas locales y el meta queda en estado "parcial" con el error registrado.
# - AUDITOR_SEMGREP_REGISTRO: config del registro a usar (por defecto p/owasp-top-ten; vacío = no usarlo).
# - AUDITOR_SIN_RED (distinto de vacío/0; el usuario no autorizó la red, D1): no se descarga el paquete del registro;
#   solo reglas locales y el meta queda «parcial» con «sin red (AUDITOR_SIN_RED)» (igual que un registro inaccesible).
# - Los check_id de las reglas propias llevan antepuesta la ruta (…reglas.semgrep.vibe-coding.<regla>);
#   catalogo.control_por_regla lo normaliza a vibe-coding.<regla>.
# - Rutas confidenciales (config/confidencial.toml, DECISIONES.md #3): cada patrón va como --exclude
#   (semgrep ancla a la raíz los patrones con "/": por eso "data/raw" va también como "**/data/raw").
#   Si no se pueden leer los patrones, el adaptador NO escanea (meta en error): sin exclusiones el
#   contenido confidencial llegaría al SARIF. El meta lista los patrones en exclusiones_confidenciales.
# - Alcance (sin «pases vacíos», ronda 1): sale de paths.scanned del JSON que semgrep escribe con --json-output (en la
#   carpeta temporal del adaptador; se borra al final), es decir, de lo que semgrep analizó DE VERDAD tras sus
#   exclusiones (--exclude, --max-target-bytes, lenguajes sin reglas). alcance.py --semgrep-json lo resume en
#   meta.alcance = {fuentes, fuentes_test, consultas_sql}: solo lenguajes con reglas de inyección (no .sh/.yaml/.json),
#   fuentes sin código de test. SEG-SAST-INY exige fuentes ≥ 1; DAT-SQL-CONCATENADO, consultas_sql ≥ 1 (si no, no_aplica).
#   Sin paths.scanned el meta queda sin alcance y nada pasa por ausencia (fail-closed).
#   Ronda 2: la cobertura la deciden las reglas que semgrep cargó DE VERDAD (tool.driver.rules del SARIF, --sarif):
#   Python cuenta solo con Flask/Django/Pyramid/Lambda; Kotlin y Scala no cuentan; con solo las reglas locales
#   (registro caído) solo cuenta JS/TS. El código escaneado sin reglas de inyección se registra en fuentes_sin_reglas
#   y consultas_sql_sin_reglas, y bloquea el pass de SEG-SAST-INY y DAT-SQL-CONCATENADO (alcance_excluyente).
# - Código de test (decisión de seguridad, ronda 1): las carpetas test/ y tests/ y los *_test.go SÍ se escanean y sus
#   hallazgos se reportan. Una exclusión por nombre de carpeta ocultaría código desplegado (p. ej. una ruta
#   app/api/test/route.ts de Next.js, un endpoint de prueba que quedó en producción); el costo es algún hallazgo en
#   fixtures de test, que el triage puede marcar. Ese código no cuenta como alcance de producción (fuentes_test aparte).
#   Siguen excluidos *.min.js (código de terceros minificado, cubierto por el análisis de dependencias) y los archivos
#   > 2 MB (--max-target-bytes).
# Exit codes de semgrep: 0 = terminó (con o sin hallazgos); ≥ 2 = error.
set -u
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
adaptador_iniciar semgrep AUDITOR_BIN_SEMGREP semgrep "$@"

VERSION="$(version_de "$BIN" --version)"
REGLAS="$RAIZ/reglas/semgrep/vibe-coding"
REGISTRO="${AUDITOR_SEMGREP_REGISTRO-p/owasp-top-ten}"
SALIDA="$CRUDO/semgrep.sarif"
# Equivalente al .semgrepignore por defecto de semgrep (que deja de aplicarse al ignorar los del repo).
# Sin test/, tests/ ni *_test.go: el código de test se escanea (ver la cabecera).
# Ronda 2: las carpetas de salida de build van ANCLADAS a la raíz (/build, /dist, /out, /.next, /vendor): sin la barra,
# semgrep excluye ese nombre en cualquier nivel y ocultaba código fuente (p. ej. src/build/handler.js).
EXCLUSIONES=(node_modules .auditoria .git /build /dist /.next /out /vendor .venv .tox .npm .yarn
             '*.min.js' .semgrep .semgrep_logs)
JSON_ALCANCE="$LOGS/semgrep-alcance.json"
BASE=(scan --sarif --output "$SALIDA" --json-output "$JSON_ALCANCE" --metrics=off --disable-version-check --quiet
      --no-git-ignore --x-ignore-semgrepignore-files --timeout 30 --max-target-bytes 2000000)
for e in "${EXCLUSIONES[@]}"; do BASE+=(--exclude "$e"); done
CONFIDENCIALES=()
if TEXTO_EXCL="$("$PY" "$RAIZ/scripts/checks/datos_confidenciales.py" --exclusiones semgrep)" && [ -n "$TEXTO_EXCL" ]; then
  while IFS= read -r e; do [ -n "$e" ] && CONFIDENCIALES+=("$e"); done <<<"$TEXTO_EXCL"
else
  escribir_meta error "" "" "" "no se pudieron leer los patrones de config/confidencial.toml: no se escanea (fail-closed)"
  limpiar_tmp
  exit 0
fi
for e in "${CONFIDENCIALES[@]}"; do BASE+=(--exclude "$e"); done

sarif_valido() { "${PYI[@]}" -c 'import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d.get("runs"), list)' "$1" 2>/dev/null; }

cd "$PROYECTO" || exit 1
rm -f "$SALIDA"
ESTADO=ok; ERROR=""
case "${AUDITOR_SIN_RED:-}" in
  ""|0) ;;
  *) if [ -n "$REGISTRO" ]; then
       ESTADO=parcial
       ERROR="sin red (AUDITOR_SIN_RED): no se descargó $REGISTRO del registro de semgrep; solo reglas locales"
       REGISTRO=""
     fi ;;
esac
if [ -n "$REGISTRO" ]; then
  ejecutar completo semgrep.sarif -- "$BIN" "${BASE[@]}" --config "$REGISTRO" --config "$REGLAS" .
  if [ "$ULTIMO_CODIGO" -le 1 ] && sarif_valido "$SALIDA"; then
    registrar_ejecucion completo semgrep.sarif ok
  else
    ERROR="no se pudo usar $REGISTRO (exit $ULTIMO_CODIGO; ¿sin red?): $(cola_log "$ULTIMO_LOG")"
    registrar_ejecucion completo "" error "$ERROR"
    ESTADO=parcial
    rm -f "$SALIDA"
  fi
fi
if [ -z "$REGISTRO" ] || [ "$ESTADO" = parcial ]; then
  ejecutar locales semgrep.sarif -- "$BIN" "${BASE[@]}" --config "$REGLAS" .
  if [ "$ULTIMO_CODIGO" -le 1 ] && sarif_valido "$SALIDA"; then
    registrar_ejecucion locales semgrep.sarif ok
  else
    ESTADO=error
    ERROR+="${ERROR:+ | }reglas locales: exit $ULTIMO_CODIGO: $(cola_log "$ULTIMO_LOG")"
    registrar_ejecucion locales "" error "$ERROR"
    rm -f "$SALIDA"
  fi
fi

SALIDAS=""; [ -f "$SALIDA" ] && SALIDAS="semgrep.sarif"
IGNORES=()
for f in .gitignore .semgrepignore; do [ -f "$PROYECTO/$f" ] && IGNORES+=("$f"); done
EXTRA="$("${PYI[@]}" -c 'import json,sys; c=[x for x in sys.argv[1:3] if x]; print(json.dumps({"configs": c, "ignores_proyecto": sys.argv[3:], "ignores_aplicados": False}))' \
  "$( [ "$ESTADO" = ok ] && printf '%s' "$REGISTRO")" "$REGLAS" "${IGNORES[@]+"${IGNORES[@]}"}")"
EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["exclusiones_confidenciales"]=sys.argv[2:]; print(json.dumps(d))' \
  "$EXTRA" "${CONFIDENCIALES[@]}")"
EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["exclusiones"]=sys.argv[2:]; print(json.dumps(d))' \
  "$EXTRA" "${EXCLUSIONES[@]}")"
if [ "$ESTADO" != error ] && [ -s "$JSON_ALCANCE" ] \
   && ALC="$("${PYI[@]}" "$ADAPT_DIR/alcance.py" "$PROYECTO" --semgrep-json "$JSON_ALCANCE" --sarif "$SALIDA")"; then
  EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["alcance"]=json.loads(sys.argv[2]); d["alcance_origen"]="semgrep paths.scanned"; print(json.dumps(d))' \
    "$EXTRA" "$ALC")"
fi
escribir_meta "$ESTADO" "$ULTIMO_CODIGO" "$ULTIMO_CMD" "$SALIDAS" "$ERROR" "$EXTRA"
limpiar_tmp
exit 0
