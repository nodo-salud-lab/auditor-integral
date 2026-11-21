#!/usr/bin/env bash
# osv.sh — vulnerabilidades conocidas (CVE/GHSA) en las dependencias declaradas en lockfiles.
# Uso: osv.sh PROYECTO DIR_CRUDO                             → crudo/osv.json
#
# osv-scanner scan source --config reglas/osv/vacio.toml --format json -r PROYECTO (consulta la API de
# OSV: requiere red). --config con un archivo propio vacío reemplaza los osv-scanner.toml del proyecto
# (corrección post-verificación: [[IgnoredVulns]] o [[PackageOverrides]] ignore=true no silencian CVE);
# el meta los lista en config_proyecto.
# Exit codes: 0 sin vulnerabilidades · 1 con vulnerabilidades (no es error)
#             128 no encontró lockfiles/paquetes → estado ok con osv.json = {"results": []}
#             otro (127 = error general, p. ej. sin red) → estado error.
# Rutas confidenciales (config/confidencial.toml): osv-scanner solo lee manifiestos y lockfiles (nombres y
# versiones de paquetes, no datos), pero los resultados cuyo source.path cae en una ruta confidencial se
# quitan de osv.json (datos_confidenciales.py --filtrar-osv) y se cuentan en meta.excluidos_confidenciales.
# Ronda 4 (PV-R3-01): meta.alcance.lockfiles_confidenciales = lockfiles en rutas confidenciales (sus resultados se
# filtran); los controles SEG-DEPS-CVE-* no pasan si es > 0 o si falta (alcance_excluyente).
# Alcance (sin «pases vacíos»): meta.alcance.lockfiles = nº de lockfiles fuera de node_modules (alcance.py; 0 si
# osv-scanner no encontró paquetes, exit 128). Sin lockfile, los SEG-DEPS-CVE-* quedan no_evaluado.
# Reproducibilidad (ronda 1): osv-scanner consulta la base OSV EN LÍNEA, que cambia (avisos nuevos, retirados como
# GHSA-fc5q-39xc-vjpf el 2026-11-18). El meta registra base_osv = {fuente, modo, consultada_utc, nota}: la fecha y
# hora UTC de la consulta (justo antes de ejecutar osv-scanner) es la «instantánea» de la base que vio esta corrida.
# Para reproducir un resultado hay que comparar contra esa fecha (el campo `modified`/`withdrawn` de cada aviso).
# Sin red (D1, investigacion/18): con AUDITOR_SIN_RED distinto de vacío/0 (el usuario no autorizó la red) NUNCA se consulta
# la API de OSV. Si la versión admite --offline (se mira `scan source --help`) y hay una base local ya descargada
# (osv_base_local.py: <RAIZ>/osv-scalibr/<Ecosistema>/all.zip), corre con --offline contra ella y el meta queda «parcial»
# (fail-closed: osv-scanner 2.7.0 con --offline devuelve 0 resultados SIN aviso para un ecosistema sin base, así que no
# puede respaldar un pass; los hallazgos sí se reportan). Sin base local o sin --offline NO se ejecuta: meta
# «no_evaluado» con error «sin red (AUDITOR_SIN_RED): …». Sin la variable, el comportamiento es el de siempre (en línea).
# Salidas del propio auditor (O1): osv-scanner recorría .auditoria/ de corridas anteriores (crudo/sbom.cdx.json) y los
# crudos crecían en cada corrida. Se excluyen con --x-exclude 'g:**/.auditoria' (cualquier profundidad; un nombre sin
# prefijo solo excluye el primer nivel, verificado con 2.7.0) y, si la carpeta de corrida (--salida) cae dentro del
# proyecto, también su ruta absoluta. meta.exclusiones las lista ([] si la versión no admite --x-exclude).
set -u
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
adaptador_iniciar osv AUDITOR_BIN_OSV osv-scanner "$@"

VERSION="$(version_de "$BIN" --version)"
SALIDA="$CRUDO/osv.json"
rm -f "$SALIDA"
CONF_OSV="$RAIZ/reglas/osv/vacio.toml"
AYUDA="$("$PY" "$CON_TIMEOUT" "$TIMEOUT_VERSION_S" "$BIN" scan source --help 2>&1 </dev/null || true)"

# O1: no escanear las salidas del auditor.
EXCLUSIONES=()
if grep -q -- '--x-exclude' <<<"$AYUDA"; then
  EXCLUSIONES=('g:**/.auditoria')
  CORRIDA_DIR="$(dirname "$CRUDO")"
  case "$CORRIDA_DIR/" in "$PROYECTO"/*) EXCLUSIONES+=("$CORRIDA_DIR") ;; esac
fi
ARGS_EXCL=()
for e in "${EXCLUSIONES[@]+"${EXCLUSIONES[@]}"}"; do ARGS_EXCL+=(--x-exclude "$e"); done
EXCL_JSON="$("${PYI[@]}" -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${EXCLUSIONES[@]+"${EXCLUSIONES[@]}"}")"

# D1: AUDITOR_SIN_RED.
RED=(); BASE_OSV=""; MOTIVO_SIN_RED=""
case "${AUDITOR_SIN_RED:-}" in
  ""|0) ;;
  *)
    if ! grep -Eq -- '--offline([^-]|$)' <<<"$AYUDA"; then
      MOTIVO_SIN_RED="sin red (AUDITOR_SIN_RED): esta versión de osv-scanner (${VERSION:-desconocida}) no admite --offline; no se consultó la API de OSV"
    elif BASE_LOCAL="$("${PYI[@]}" "$ADAPT_DIR/osv_base_local.py")"; then
      OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$("${PYI[@]}" -c 'import json,sys; print(json.loads(sys.argv[1])["raiz"])' "$BASE_LOCAL")"
      export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY
      RED=(--offline)
      BASE_OSV="$("${PYI[@]}" -c 'import json,sys; b=json.loads(sys.argv[1]); print(json.dumps({"fuente": "base OSV local ya descargada (osv-scanner --offline; sin red por AUDITOR_SIN_RED)", "modo": "local_sin_red", "ecosistemas": b["ecosistemas"], "actualizada_utc": b["actualizada_utc"], "consultada_utc": sys.argv[2], "nota": "--offline no avisa si falta la base de un ecosistema ni si está desactualizada: no basta para un pass"}, ensure_ascii=False))' \
        "$BASE_LOCAL" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    else
      MOTIVO_SIN_RED="sin red (AUDITOR_SIN_RED): no hay base OSV local descargada (se obtiene con osv-scanner --download-offline-databases, que requiere red); no se consultó la API de OSV"
    fi ;;
esac
if [ -n "$MOTIVO_SIN_RED" ]; then
  EXTRA="$("${PYI[@]}" -c 'import json,sys; print(json.dumps({"exclusiones": json.loads(sys.argv[1]), "base_osv": {"fuente": "ninguna", "modo": "no_consultada", "nota": "sin red por decisión del usuario (AUDITOR_SIN_RED)"}}, ensure_ascii=False))' "$EXCL_JSON")"
  escribir_meta no_evaluado "" "" "" "$MOTIVO_SIN_RED" "$EXTRA"
  limpiar_tmp
  exit 0
fi

CONSULTA_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ejecutar fuente osv.json -- "$BIN" scan source --config "$CONF_OSV" "${RED[@]+"${RED[@]}"}" \
  "${ARGS_EXCL[@]+"${ARGS_EXCL[@]}"}" --format json --output-file "$SALIDA" -r "$PROYECTO"

ESTADO=ok; ERROR=""; EXTRA='{}'
case "$ULTIMO_CODIGO" in
  0|1)
    if json_valido "$SALIDA"; then
      registrar_ejecucion fuente osv.json ok
      EXCL_OSV="$("$PY" "$RAIZ/scripts/checks/datos_confidenciales.py" --filtrar-osv "$SALIDA" "$PROYECTO")" || {
        ESTADO=error; ERROR="no se pudo filtrar rutas confidenciales"; rm -f "$SALIDA"; }
      EXTRA="{\"excluidos_confidenciales\": ${EXCL_OSV:-0}}"
    else
      ESTADO=error; ERROR="exit $ULTIMO_CODIGO sin JSON válido: $(cola_log "$ULTIMO_LOG")"
      registrar_ejecucion fuente "" error "$ERROR"
    fi ;;
  128)
    printf '{"results": []}' > "$SALIDA"
    EXTRA='{"nota": "osv-scanner no encontró lockfiles ni paquetes que analizar"}'
    registrar_ejecucion fuente osv.json ok ;;
  *)
    ESTADO=error; ERROR="exit $ULTIMO_CODIGO: $(cola_log "$ULTIMO_LOG")"
    registrar_ejecucion fuente "" error "$ERROR"
    rm -f "$SALIDA" ;;
esac

CONF_PROY=()
while IFS= read -r f; do CONF_PROY+=("${f#"$PROYECTO"/}"); done < <(
  find "$PROYECTO" \( -name node_modules -o -name .git -o -name .auditoria \) -prune -o \
       -type f -name osv-scanner.toml -print 2>/dev/null | LC_ALL=C sort)
EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["config_proyecto"]=sys.argv[2:]; print(json.dumps(d))' \
  "$EXTRA" "${CONF_PROY[@]+"${CONF_PROY[@]}"}")"
if [ -n "$BASE_OSV" ]; then  # sin red con base local: los hallazgos valen, pero no respaldan un pass
  if [ "$ESTADO" = ok ]; then
    ESTADO=parcial
    ERROR="sin red (AUDITOR_SIN_RED): se usó la base OSV local (--offline), que puede estar incompleta o desactualizada; no basta para un pass"
  else
    ERROR="sin red (AUDITOR_SIN_RED), base local: $ERROR"
  fi
fi
if { [ "$ESTADO" = ok ] || [ "$ESTADO" = parcial ]; } && ALC="$("${PYI[@]}" "$ADAPT_DIR/alcance.py" "$PROYECTO")"; then
  EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); a=json.loads(sys.argv[2]); d["alcance"]={"lockfiles": 0 if sys.argv[3]=="128" else a["lockfiles"], "lockfiles_confidenciales": a["lockfiles_confidenciales"]}; print(json.dumps(d))' \
    "$EXTRA" "$ALC" "$ULTIMO_CODIGO")"
fi
EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["base_osv"]=json.loads(sys.argv[3]) if sys.argv[3] else {"fuente": "https://api.osv.dev (consulta en línea de osv-scanner)", "modo": "en_linea", "consultada_utc": sys.argv[2], "nota": "la base OSV cambia en el tiempo: esta fecha es la instantánea consultada; para reproducir, comparar los avisos con su modified/withdrawn respecto de ella"}; d["exclusiones"]=json.loads(sys.argv[4]); print(json.dumps(d, ensure_ascii=False))' \
  "$EXTRA" "$CONSULTA_UTC" "$BASE_OSV" "$EXCL_JSON")"
SALIDAS=""; [ -f "$SALIDA" ] && SALIDAS="osv.json"
escribir_meta "$ESTADO" "$ULTIMO_CODIGO" "$ULTIMO_CMD" "$SALIDAS" "$ERROR" "$EXTRA"
limpiar_tmp
exit 0
