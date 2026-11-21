#!/usr/bin/env bash
# zizmor.sh — seguridad de los workflows de GitHub Actions.
# Uso: zizmor.sh PROYECTO DIR_CRUDO                          → crudo/zizmor.sarif
#
# Solo si existe .github/workflows con algún .yml/.yaml; si no, meta estado "no_aplica".
# Alcance: meta.alcance.workflows = nº de .yml/.yaml en .github/workflows (alcance.py).
# zizmor --format sarif --offline --persona regular --no-exit-codes --no-config .github/workflows
#   --offline:     sin red (las auditorías en línea necesitan GH_TOKEN; AUDITOR_ZIZMOR_EN_LINEA=1 las habilita)
#   --no-config:   un zizmor.yml del proyecto no puede desactivar auditorías
#   --no-exit-codes: el código de salida solo indica error (los hallazgos van al SARIF)
#   --persona regular: es la persona por defecto de zizmor (default) y la que recomienda su documentación
#                  para uso general y CI. Se mantiene a propósito (pendiente §6.4 de 10-f0-f1-resultados):
#                  `--persona auditor` agrega hallazgos de baja confianza y muchos falsos positivos (p. ej.
#                  recuperaría D51, permisos excesivos, a costa de ruido); `pedantic` suma estilo. Cambiarla
#                  exige re-medir la VPP en la validación.
#   Rutas confidenciales (config/confidencial.toml): zizmor solo lee .github/workflows/*.yml, que no
#                  coincide con ningún patrón confidencial; no hace falta excluir nada.
# zizmor informa las rutas relativas a la raíz del repo git que contiene al proyecto (no al cwd):
# el adaptador las reescribe relativas al proyecto y anota cuántas cambió en meta.uris_reescritas.
set -u
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
adaptador_iniciar zizmor AUDITOR_BIN_ZIZMOR zizmor "$@"

VERSION="$(version_de "$BIN" --version)"
SALIDA="$CRUDO/zizmor.sarif"
rm -f "$SALIDA"

if [ ! -d "$PROYECTO/.github/workflows" ] || \
   [ -z "$(find "$PROYECTO/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | head -n 1)" ]; then
  escribir_meta no_aplica "" "" "" "no hay workflows en .github/workflows"
  limpiar_tmp
  exit 0
fi

RED=(--offline)
# AUDITOR_SIN_RED (D1: el usuario no autorizó la red) manda sobre AUDITOR_ZIZMOR_EN_LINEA: siempre --offline.
case "${AUDITOR_SIN_RED:-}" in
  ""|0) [ "${AUDITOR_ZIZMOR_EN_LINEA:-0}" = "1" ] && [ -n "${GH_TOKEN:-}" ] && RED=() ;;
esac
cd "$PROYECTO" || exit 1
ejecutar workflows zizmor.sarif -- "$BIN" --format sarif "${RED[@]+"${RED[@]}"}" --persona regular \
  --no-exit-codes --no-config --no-progress .github/workflows
cp "$LOGS/workflows.stdout" "$SALIDA" 2>/dev/null

ESTADO=ok; ERROR=""; EXTRA='{}'
if [ "$ULTIMO_CODIGO" -eq 0 ] && json_valido "$SALIDA"; then
  registrar_ejecucion workflows zizmor.sarif ok
  PREFIJO="$(git -C "$PROYECTO" --no-optional-locks rev-parse --show-prefix 2>/dev/null || true)"
  EXTRA="$("${PYI[@]}" - "$SALIDA" "$PROYECTO" "$PREFIJO" <<'PYEOF'
import json, os, sys
ruta, proyecto, prefijo = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(ruta, encoding="utf-8"))
n = 0
def relativa(uri):
    if uri.startswith("file://"):
        uri = uri[7:]
    if os.path.isabs(uri):
        r = os.path.relpath(uri, proyecto)
        return r if not r.startswith("..") else uri
    if prefijo and uri.startswith(prefijo):
        return uri[len(prefijo):]
    return uri
for run in d.get("runs") or []:
    for res in run.get("results") or []:
        for loc in res.get("locations") or []:
            art = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
            if "uri" in art:
                nueva = relativa(art["uri"])
                if nueva != art["uri"]:
                    art["uri"] = nueva
                    n += 1
json.dump(d, open(ruta, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps({"uris_reescritas": n, "prefijo_git": prefijo.rstrip("/")}))
PYEOF
)"
else
  ESTADO=error; ERROR="exit $ULTIMO_CODIGO: $(cola_log "$ULTIMO_LOG")"
  registrar_ejecucion workflows "" error "$ERROR"
  rm -f "$SALIDA"
fi

SALIDAS=""; [ -f "$SALIDA" ] && SALIDAS="zizmor.sarif"
if [ "$ESTADO" = ok ] && ALC="$("${PYI[@]}" "$ADAPT_DIR/alcance.py" "$PROYECTO")"; then
  EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1] or "{}"); d["alcance"]={"workflows": json.loads(sys.argv[2])["workflows"]}; print(json.dumps(d))' \
    "${EXTRA:-}" "$ALC")"
fi
escribir_meta "$ESTADO" "$ULTIMO_CODIGO" "$ULTIMO_CMD" "$SALIDAS" "$ERROR" "$EXTRA"
limpiar_tmp
exit 0
