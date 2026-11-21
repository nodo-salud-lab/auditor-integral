#!/usr/bin/env bash
# gitleaks.sh — secretos en el working tree, en el historial git y en los bundles de build.
# Uso: gitleaks.sh PROYECTO DIR_CRUDO
#
# Tres ejecuciones (cada una con su línea en meta.ejecuciones):
#   dir     working tree sin node_modules ni carpetas de build   → crudo/gitleaks.json
#   git     historial completo (--all) si hay repo con commits    → crudo/gitleaks-git.json
#           (rutas relativas a la raíz del repo; meta.prefijo_git = ruta del proyecto dentro del repo)
#   bundle  dist/ build/ .next/ out/ aunque estén en .gitignore   → crudo/gitleaks-bundle.json
# Siempre con la configuración propia (reglas/gitleaks/*.toml): un .gitleaks.toml del proyecto no puede
# apagar reglas, y se ignoran los comentarios gitleaks:allow. LIMITACIÓN: gitleaks siempre aplica el
# .gitleaksignore de la carpeta escaneada (no hay opción para impedirlo): la del proyecto, la de la raíz
# del repo git (modo git) y la de cada carpeta de bundle. El meta las lista en `gitleaksignore`
# [{archivo, entradas}] (y la del proyecto también en gitleaksignore_proyecto); si alguna tiene
# entradas, el estado baja a "parcial": un repo no puede silenciar secretos y obtener un pass.
# Historial: git log recibe --no-ext-diff --no-textconv (un diff.<driver>.textconv del repo no se
# ejecuta). Si la ruta del proyecto dentro del repo tiene espacios u otros caracteres que gitleaks
# partiría en --log-opts, se escanea sin filtro de ruta y se filtra después por File (meta.filtro_prefijo).
# Las carpetas de bundle se pasan como ./<ruta> (una carpeta '-x' no se interpreta como opción).
# Rutas confidenciales (config/confidencial.toml, DECISIONES.md #3): en cada corrida se generan, en la
# carpeta temporal del adaptador, dos configuraciones que extienden arbol.toml y base.toml ([extend] path)
# y agregan una [[allowlists]] con las rutas confidenciales como expresiones regulares
# (datos_confidenciales.py --config-gitleaks). Vale para los tres modos (working tree, historial y bundles):
# gitleaks descarta esas rutas en su allowlist global de paths, que se evalúa antes de aplicar las reglas, de
# modo que ningún hallazgo, Match ni Secret sale de ahí al reporte. (gitleaks puede abrir el archivo para
# recorrerlo; lo que se garantiza es que nada de su contenido llega a crudo/.) Si no se puede generar la
# configuración, no se escanea (meta en error, fail-closed). El meta lista los patrones en
# exclusiones_confidenciales. Detectar que un archivo confidencial está versionado es tarea de
# checks/datos_confidenciales.py (solo metadatos), no de gitleaks.
# Ronda 4 (PV-R3-01): meta.alcance.codigo_confidencial = nº de archivos de código o .env* en rutas confidenciales (que
# gitleaks no escanea por la allowlist); SEG-SECRETO-REPO no pasa si es > 0 (alcance_excluyente), ni si falta.
# Alcance (sin «pases vacíos»): meta.alcance = {arbol, historial, bundles}: archivos del working tree que se
# pudieron escanear (alcance.py, solo nombres; 0 si el escaneo dir falló), 1/0 si el historial se escaneó bien y
# nº de carpetas de bundle escaneadas sin error. SEG-SECRETO-BUNDLE sin bundles → no_aplica («sin bundle»).
# Ronda 1 de pases vacíos: meta.alcance.commits = nº de commits del repo que tocan el proyecto (git rev-list --all
# --count, con la ruta del proyecto como pathspec si está dentro de un repo mayor); 0 si no hay repo o no tiene
# commits. SEG-SECRETO-REPO exige historial > 0 cuando commits > 0 (catálogo: alcance_condicional). Si hay un .git
# (en el proyecto o en una carpeta superior) pero git no puede leerlo, commits queda sin registrar y el estado baja a
# "parcial": no se puede saber si el historial debía escanearse (fail-closed).
# Exit codes de gitleaks: 0 sin hallazgos, 10 con hallazgos (forzado con --exit-code 10); otro = error.
# O3 (privacidad): gitleaks corre con --redact=100 y cada reporte pasa por gitleaks_redactar.py antes de quedar en
# crudo/: Secret/Match/Line enmascarados (aunque el binario ignore --redact) y, en vez del valor, AuditorHuella (huella
# no reversible para seguir enmascarando ese secreto en digest/informe) y AuditorProveedor (bool, AUD-SEC). Si el
# post-proceso falla, el reporte se borra y esa ejecución queda en error (fail-closed: nunca un crudo sin enmascarar).
# Ronda 6 (grupo secretos, verificación real 2026-11-20):
#  (a) el escaneo del árbol excluye SIEMPRE entornos virtuales y cachés de herramientas (arbol.toml: .venv, venv,
#      .nox, .tox, site-packages, .pytest_cache, .mypy_cache, .ruff_cache, .cache, supabase/.temp, __pycache__) y,
#      además, cada carpeta con pyvenv.cfg (entorno con nombre libre, p. ej. .venv312). meta.excluidas_venv las lista.
#      Las carpetas de bundle siguen el paso 3 aunque estén ignoradas (se publican); la búsqueda de bundles no
#      entra en entornos virtuales ni cachés (pip deja carpetas build/ dentro de .venv).
#  (b) en un repo git, las carpetas IGNORADAS por git y sin ningún archivo versionado (git ls-files -o -i
#      --directory, verificado con ls-files) no entran en el escaneo principal: se escanean aparte con presupuesto
#      propio (AUDITOR_GITLEAKS_IGNORADAS_S, 60 s por defecto, con con_timeout.py) y --max-target-megabytes
#      (AUDITOR_GITLEAKS_IGNORADAS_MAX_MB, 10), y sus hallazgos se unen a gitleaks.json. Así un tasks/ de 10 GB
#      ignorado ya no agota el timeout de la tarea. Si ese escaneo se corta o falla, queda en
#      meta.ignoradas.estado (timeout/error) sin bajar el estado global: lo ignorado y nunca versionado no cuenta
#      para SEG-SECRETO-REPO, así que no abre un pase falso.
#      gitleaks_redactar.py --estado-git marca cada hallazgo del árbol con AuditorGit (versionado | no_versionado |
#      ignorado | ignorado_con_historial | desconocido | sin_git) consultando git ls-files / check-ignore / log;
#      normalizar/gitleaks.py trata solo "ignorado" (ignorado y sin rastro en el historial) como secreto local de
#      baja prioridad. Fuera de git (sin .git) todo cuenta como hasta ahora, salvo (a).
set -u
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
adaptador_iniciar gitleaks AUDITOR_BIN_GITLEAKS gitleaks "$@"

VERSION="$(version_de "$BIN" version)"
CONF_ARBOL="$RAIZ/reglas/gitleaks/arbol.toml"
CONF_BASE="$RAIZ/reglas/gitleaks/base.toml"
CONFIDENCIAL_PY="$RAIZ/scripts/checks/datos_confidenciales.py"
if "$PY" "$CONFIDENCIAL_PY" --config-gitleaks "$CONF_ARBOL" "$LOGS/arbol_confidencial.toml" \
   && "$PY" "$CONFIDENCIAL_PY" --config-gitleaks "$CONF_BASE" "$LOGS/base_confidencial.toml" \
   && PATRONES_CONF="$("$PY" "$CONFIDENCIAL_PY" --patrones)"; then
  CONF_ARBOL="$LOGS/arbol_confidencial.toml"; CONF_BASE="$LOGS/base_confidencial.toml"
else
  escribir_meta error "" "" "" "no se pudo generar la configuración con rutas confidenciales (config/confidencial.toml): no se escanea (fail-closed)"
  limpiar_tmp
  exit 0
fi
COMUNES=(--report-format json --no-banner --exit-code 10 --ignore-gitleaks-allow --redact=100 -i "$LOGS" -l warn)
REDACTAR_PY="$ADAPT_DIR/gitleaks_redactar.py"
ESTADO_GLOBAL=ok; ERROR_GLOBAL=""; SALIDAS=""; CODIGO_DIR=""; DIR_OK=0; HIST_OK=0; N_BUNDLES_OK=0

# redactar SALIDA [--git-raiz DIR] → enmascara el reporte en crudo/ (0) o lo borra (1, fail-closed).
redactar() {
  local salida="$1"; shift
  if "$PY" "$REDACTAR_PY" "$CRUDO/$salida" --base "$PROYECTO" "$@" 2>"$LOGS/redactar.log"; then return 0; fi
  rm -f "$CRUDO/$salida"
  return 1
}

evaluar() { # MODO SALIDA [ARGS DE redactar]
  local modo="$1" salida="$2"; shift 2
  if { [ "$ULTIMO_CODIGO" -eq 0 ] || [ "$ULTIMO_CODIGO" -eq 10 ]; } && json_valido "$CRUDO/$salida"; then
    if ! redactar "$salida" "$@"; then
      local errr="no se pudo enmascarar el reporte (gitleaks_redactar.py): se descarta (fail-closed): $(cola_log "$LOGS/redactar.log")"
      registrar_ejecucion "$modo" "$salida" error "$errr"
      ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }$modo: $errr"
      return 1
    fi
    registrar_ejecucion "$modo" "$salida" ok
    SALIDAS+="${SALIDAS:+,}$salida"
    return 0
  fi
  local err; err="$(cola_log "$ULTIMO_LOG")"
  registrar_ejecucion "$modo" "$salida" error "exit $ULTIMO_CODIGO: $err"
  ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }$modo: exit $ULTIMO_CODIGO: $err"
  rm -f "$CRUDO/$salida"
  return 1
}

# --- 0. exclusiones dinámicas (ronda 6) ---------------------------------------------------------
rm -f "$CRUDO/gitleaks.json" "$CRUDO/gitleaks-git.json" "$CRUDO/gitleaks-bundle.json"
cd "$PROYECTO" || exit 1
# Nombres que nunca se recorren buscando entornos ni bundles (mismos que arbol.toml, sección ronda 6).
PODA=( \( -name node_modules -o -name .git -o -name .auditoria -o -name .venv -o -name venv -o -name .nox
       -o -name .tox -o -name site-packages -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache
       -o -name .cache -o -name __pycache__ -o -path ./supabase/.temp -o -path '*/supabase/.temp' \) -prune )
VENVS=()
while IFS= read -r f; do VENVS+=("$(dirname "${f#./}")"); done < <(
  find . "${PODA[@]}" -o -type f -name pyvenv.cfg -print 2>/dev/null | sort)
EN_REPO=0
[ "$(git -C "$PROYECTO" --no-optional-locks rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ] && EN_REPO=1
IGNORADAS=()
if [ "$EN_REPO" -eq 1 ]; then
  # Carpetas completas ignoradas por git (-o -i --directory). Se descartan las de build (paso 3), las que ya
  # excluye arbol.toml, las que están dentro de un entorno virtual y las que tienen algún archivo versionado.
  while IFS= read -r -d '' d; do
    case "$d" in */) ;; *) continue ;; esac
    d="${d%/}"
    case "/$d/" in
      */node_modules/*|*/.git/*|*/.auditoria/*|*/dist/*|*/build/*|*/.next/*|*/out/*|*/.venv/*|*/venv/*|*/.nox/*|\
      */.tox/*|*/site-packages/*|*/.pytest_cache/*|*/.mypy_cache/*|*/.ruff_cache/*|*/.cache/*|*/__pycache__/*|\
      */supabase/.temp/*) continue ;;
    esac
    dentro=0
    for v in "${VENVS[@]+"${VENVS[@]}"}"; do
      case "$d/" in "$v"/*) dentro=1 ;; esac
    done
    [ "$dentro" -eq 1 ] && continue
    # Si git falla, la carpeta se queda en el escaneo principal (fail-closed: cuenta como repo).
    versionados="$(git -C "$PROYECTO" --no-optional-locks ls-files -- ":(literal)$d" 2>/dev/null)" || continue
    [ -n "$versionados" ] && continue
    IGNORADAS+=("$d")
  done < <(git -C "$PROYECTO" --no-optional-locks ls-files -z -o -i --exclude-standard --directory 2>/dev/null)
fi
# Configuraciones derivadas: _ign (para escanear las carpetas ignoradas) = árbol + entornos; principal = además
# sin las carpetas ignoradas. Rutas como expresiones regulares ancladas, en cadenas TOML básicas (json.dumps).
agregar_allowlist() { # DESTINO DESCRIPCION RUTAS...
  local destino="$1" desc="$2"; shift 2
  [ $# -gt 0 ] || return 0
  "${PYI[@]}" - "$destino" "$desc" "$@" <<'PYEOF'
import json, re, sys
destino, desc, rutas = sys.argv[1], sys.argv[2], sys.argv[3:]
lineas = ["", "[[allowlists]]", "description = " + json.dumps(desc), "paths = ["]
lineas += ["  " + json.dumps("^(\\./)?" + re.escape(r) + "/") + "," for r in rutas]
lineas.append("]")
with open(destino, "a", encoding="utf-8") as f:
    f.write("\n".join(lineas) + "\n")
PYEOF
}
CONF_ARBOL_IGN="$LOGS/arbol_ignoradas.toml"
if cp "$CONF_ARBOL" "$CONF_ARBOL_IGN" \
   && agregar_allowlist "$CONF_ARBOL_IGN" "Entornos virtuales de Python (pyvenv.cfg): código de terceros" "${VENVS[@]+"${VENVS[@]}"}" \
   && cp "$CONF_ARBOL_IGN" "$LOGS/arbol_principal.toml" \
   && agregar_allowlist "$LOGS/arbol_principal.toml" "Carpetas ignoradas por git sin archivos versionados (se escanean aparte)" \
        "${IGNORADAS[@]+"${IGNORADAS[@]}"}"; then
  CONF_ARBOL="$LOGS/arbol_principal.toml"
else
  escribir_meta error "" "" "" "no se pudo generar la configuración con las exclusiones de entornos y carpetas ignoradas: no se escanea (fail-closed)"
  limpiar_tmp
  exit 0
fi

# --- 1. working tree -------------------------------------------------------------------------
ejecutar dir gitleaks.json -- "$BIN" dir . -c "$CONF_ARBOL" "${COMUNES[@]}" --report-path "$CRUDO/gitleaks.json"
CODIGO_DIR="$ULTIMO_CODIGO"; CMD_DIR="$ULTIMO_CMD"; DUR_DIR="$ULTIMO_DUR"; LOG_DIR="$ULTIMO_LOG"
# 1b. carpetas ignoradas por git (ronda 6): presupuesto propio; sus hallazgos se unen a gitleaks.json.
IGN_ESTADO=""; IGN_MOTIVO=""; IGN_OK=0
if [ "${#IGNORADAS[@]}" -gt 0 ] && { [ "$CODIGO_DIR" -eq 0 ] || [ "$CODIGO_DIR" -eq 10 ]; } \
   && json_valido "$CRUDO/gitleaks.json"; then
  PRESUPUESTO="${AUDITOR_GITLEAKS_IGNORADAS_S:-60}"
  case "$PRESUPUESTO" in ''|*[!0-9]*|0) PRESUPUESTO=60 ;; esac
  MAX_MB="${AUDITOR_GITLEAKS_IGNORADAS_MAX_MB:-10}"
  case "$MAX_MB" in ''|*[!0-9]*|0) MAX_MB=10 ;; esac
  T0_IGN="$(ahora)"; PARTES_IGN=("$CRUDO/gitleaks.json"); IGN_ESTADO=ok
  for d in "${IGNORADAS[@]}"; do
    resto="$("${PYI[@]}" -c 'import sys; print(max(0, int(float(sys.argv[1]) - float(sys.argv[2]))))' "$PRESUPUESTO" "$(transcurrido "$T0_IGN")")"
    if [ "$resto" -lt 1 ]; then
      IGN_ESTADO=timeout; IGN_MOTIVO="presupuesto de ${PRESUPUESTO} s agotado antes de escanear todas las carpetas ignoradas"
      break
    fi
    parcial="$LOGS/ignorada_$IGN_OK.json"
    ejecutar "ignorada_$IGN_OK" "" -- "$PY" "$CON_TIMEOUT" "$resto" "$BIN" dir "./$d" -c "$CONF_ARBOL_IGN" \
      "${COMUNES[@]}" --max-target-megabytes "$MAX_MB" --report-path "$parcial"
    if [ "$ULTIMO_CODIGO" -eq 124 ]; then
      IGN_ESTADO=timeout; IGN_MOTIVO="presupuesto de ${PRESUPUESTO} s agotado en la carpeta ignorada '$d'"
      break
    elif { [ "$ULTIMO_CODIGO" -eq 0 ] || [ "$ULTIMO_CODIGO" -eq 10 ]; } && json_valido "$parcial"; then
      PARTES_IGN+=("$parcial"); IGN_OK=$((IGN_OK + 1))
    else
      IGN_ESTADO=error; IGN_MOTIVO="carpeta ignorada '$d': exit $ULTIMO_CODIGO: $(cola_log "$ULTIMO_LOG")"
    fi
  done
  if [ "${#PARTES_IGN[@]}" -gt 1 ]; then
    "${PYI[@]}" - "$CRUDO/gitleaks.json" "${PARTES_IGN[@]}" <<'PYEOF'
import json, sys
todo = []
for p in sys.argv[2:]:
    todo.extend(json.load(open(p, encoding="utf-8")) or [])
json.dump(todo, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
  fi
  ULTIMO_DUR="$(transcurrido "$T0_IGN")"; ULTIMO_CODIGO=0
  [ "$IGN_ESTADO" = timeout ] && ULTIMO_CODIGO=124
  ULTIMO_CMD="$(comando_texto "$BIN" dir "<${#IGNORADAS[@]} carpetas ignoradas por git>" -c "$CONF_ARBOL_IGN" --max-target-megabytes "$MAX_MB")"
  registrar_ejecucion ignoradas "" "$IGN_ESTADO" "$IGN_MOTIVO"
fi
ULTIMO_CODIGO="$CODIGO_DIR"; ULTIMO_CMD="$CMD_DIR"; ULTIMO_DUR="$DUR_DIR"; ULTIMO_LOG="$LOG_DIR"
if evaluar dir gitleaks.json --estado-git; then DIR_OK=1; else ESTADO_GLOBAL=error; fi
[ "$CODIGO_DIR" -eq 10 ] && CODIGO_DIR=0   # 10 = hubo hallazgos: no es un error

# --- 2. historial git ------------------------------------------------------------------------
EXTRA='{}'
COMMITS=""   # vacío = sin registrar (fail-closed en estado.py)
HAY_DOTGIT=0
d="$PROYECTO"
while :; do   # busca un .git hacia arriba como git: sin subir a una carpeta de GIT_CEILING_DIRECTORIES
  if [ -e "$d/.git" ]; then HAY_DOTGIT=1; break; fi
  [ "$d" = "/" ] && break
  padre="$(dirname "$d")"
  techo=0
  IFS=: read -r -a TECHOS <<<"${GIT_CEILING_DIRECTORIES:-}"
  for c in "${TECHOS[@]+"${TECHOS[@]}"}"; do
    [ -n "$c" ] && [ "${c%/}" = "$padre" ] && techo=1
  done
  [ "$techo" -eq 1 ] && break
  d="$padre"
done
if [ "$EN_REPO" -eq 0 ]; then
  if [ "$HAY_DOTGIT" -eq 1 ]; then
    [ "$ESTADO_GLOBAL" = ok ] && ESTADO_GLOBAL=parcial
    ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }hay un .git, pero git no pudo leer el repositorio: no se sabe si el historial debía escanearse"
  else
    COMMITS=0
  fi
elif ! git -C "$PROYECTO" --no-optional-locks rev-parse --verify -q HEAD >/dev/null 2>&1; then
  COMMITS=0   # repo sin commits: no hay historial
fi
if [ "$EN_REPO" -eq 1 ] \
   && git -C "$PROYECTO" --no-optional-locks rev-parse --verify -q HEAD >/dev/null 2>&1; then
  TOP="$(git -C "$PROYECTO" --no-optional-locks rev-parse --show-toplevel)"
  PREFIJO="$(git -C "$PROYECTO" --no-optional-locks rev-parse --show-prefix)"; PREFIJO="${PREFIJO%/}"
  LOG_OPTS="--all --no-ext-diff --no-textconv"
  FILTRO=ninguno
  if [ -n "$PREFIJO" ]; then
    case "$PREFIJO" in
      -*|*[!A-Za-z0-9._/@+-]*) FILTRO=posterior ;;   # gitleaks partiría la ruta por espacios
      *) FILTRO=pathspec; LOG_OPTS="$LOG_OPTS -- $PREFIJO" ;;
    esac
  fi
  ejecutar git gitleaks-git.json -- "$BIN" git "$TOP" --log-opts="$LOG_OPTS" -c "$CONF_BASE" "${COMUNES[@]}" \
    --report-path "$CRUDO/gitleaks-git.json"
  if evaluar git gitleaks-git.json --git-raiz "$TOP"; then
    HIST_OK=1
    if [ "$FILTRO" = posterior ]; then
      "${PYI[@]}" - "$CRUDO/gitleaks-git.json" "$PREFIJO" <<'PYEOF'
import json, sys
ruta, prefijo = sys.argv[1], sys.argv[2].rstrip("/") + "/"
datos = json.load(open(ruta, encoding="utf-8")) or []
datos = [d for d in datos if str(d.get("File") or "").startswith(prefijo)]
json.dump(datos, open(ruta, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
    fi
  elif [ "$ESTADO_GLOBAL" = ok ]; then ESTADO_GLOBAL=parcial; fi
  EXTRA="$("${PYI[@]}" -c 'import json,sys; print(json.dumps({"raiz_git": sys.argv[1], "prefijo_git": sys.argv[2], "filtro_prefijo": sys.argv[3]}))' "$TOP" "$PREFIJO" "$FILTRO")"
  if [ -n "$PREFIJO" ]; then
    COMMITS="$(git -C "$TOP" --no-optional-locks rev-list --all --count -- ":(literal)$PREFIJO" 2>/dev/null)" || COMMITS=""
  else
    COMMITS="$(git -C "$TOP" --no-optional-locks rev-list --all --count 2>/dev/null)" || COMMITS=""
  fi
  case "$COMMITS" in ''|*[!0-9]*) COMMITS=""; [ "$ESTADO_GLOBAL" = ok ] && ESTADO_GLOBAL=parcial
    ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }no se pudo contar los commits del repositorio" ;; esac
fi

# --- 3. bundles de build (aunque estén en .gitignore) ------------------------------------------
# Ronda 4 (PV-R3-03): a CUALQUIER profundidad (antes -maxdepth 4). arbol.toml excluye (dist|build|.next|out)/ en
# cualquier nivel, así que una carpeta de build en un monorepo (apps/*/packages/*/build) solo la cubre este paso.
BUNDLES=()
while IFS= read -r d; do BUNDLES+=("${d#./}"); done < <(
  find . "${PODA[@]}" -o \
       -type d \( -name dist -o -name build -o -name .next -o -name out \) -print -prune 2>/dev/null | sort)
# Ronda 6: tampoco dentro de un entorno virtual con nombre libre (pyvenv.cfg).
if [ "${#VENVS[@]}" -gt 0 ] && [ "${#BUNDLES[@]}" -gt 0 ]; then
  FILTRADOS=()
  for b in "${BUNDLES[@]}"; do
    dentro=0
    for v in "${VENVS[@]}"; do case "$b/" in "$v"/*) dentro=1 ;; esac; done
    [ "$dentro" -eq 0 ] && FILTRADOS+=("$b")
  done
  BUNDLES=("${FILTRADOS[@]+"${FILTRADOS[@]}"}")
fi
if [ "${#BUNDLES[@]}" -gt 0 ]; then
  PARTES=(); FALLO=0
  for d in "${BUNDLES[@]}"; do
    parcial="$LOGS/bundle_$(printf '%s' "$d" | tr '/ ' '__').json"
    ejecutar "bundle_$(printf '%s' "$d" | tr '/ ' '__')" "" -- "$BIN" dir "./$d" -c "$CONF_BASE" "${COMUNES[@]}" --report-path "$parcial"
    if { [ "$ULTIMO_CODIGO" -eq 0 ] || [ "$ULTIMO_CODIGO" -eq 10 ]; } && json_valido "$parcial"; then
      PARTES+=("$parcial"); N_BUNDLES_OK=$((N_BUNDLES_OK + 1))
    else
      FALLO=1; ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }bundle $d: exit $ULTIMO_CODIGO: $(cola_log "$ULTIMO_LOG")"
    fi
  done
  # Une los reportes por carpeta en uno solo (gitleaks no acepta varias rutas en 'dir').
  "${PYI[@]}" - "$CRUDO/gitleaks-bundle.json" "${PARTES[@]+"${PARTES[@]}"}" <<'PYEOF'
import json, sys
todo = []
for p in sys.argv[2:]:
    todo.extend(json.load(open(p, encoding="utf-8")) or [])
json.dump(todo, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PYEOF
  ULTIMO_CMD="$(comando_texto "$BIN" dir "<${BUNDLES[*]}>" -c "$CONF_BASE" "${COMUNES[@]}")"
  if ! redactar gitleaks-bundle.json; then
    N_BUNDLES_OK=0
    errr="no se pudo enmascarar el reporte (gitleaks_redactar.py): se descarta (fail-closed): $(cola_log "$LOGS/redactar.log")"
    registrar_ejecucion bundle gitleaks-bundle.json error "$errr"
    ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }bundle: $errr"
    [ "$ESTADO_GLOBAL" = ok ] && ESTADO_GLOBAL=parcial
  elif [ "$FALLO" -eq 0 ]; then
    registrar_ejecucion bundle gitleaks-bundle.json ok
    SALIDAS+="${SALIDAS:+,}gitleaks-bundle.json"
  else
    registrar_ejecucion bundle gitleaks-bundle.json error "falló al menos una carpeta"
    [ "$ESTADO_GLOBAL" = ok ] && ESTADO_GLOBAL=parcial
    SALIDAS+="${SALIDAS:+,}gitleaks-bundle.json"
  fi
  EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["carpetas_bundle"]=sys.argv[2:]; print(json.dumps(d))' "$EXTRA" "${BUNDLES[@]}")"
fi

# .gitleaksignore que gitleaks aplicó: proyecto, raíz git (si es otra carpeta) y cada bundle.
IGNORES=()
[ -f "$PROYECTO/.gitleaksignore" ] && IGNORES+=(".gitleaksignore=$PROYECTO/.gitleaksignore")
if [ -n "${TOP:-}" ] && [ "$TOP" != "$PROYECTO" ] && [ -f "$TOP/.gitleaksignore" ]; then
  IGNORES+=("<raiz_git>/.gitleaksignore=$TOP/.gitleaksignore")
fi
for d in "${BUNDLES[@]+"${BUNDLES[@]}"}"; do
  [ -f "$d/.gitleaksignore" ] && IGNORES+=("$d/.gitleaksignore=$PROYECTO/$d/.gitleaksignore")
done
if [ "${#IGNORES[@]}" -gt 0 ]; then
  EXTRA="$("${PYI[@]}" - "$EXTRA" "${IGNORES[@]}" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
lista = []
for par in sys.argv[2:]:
    nombre, ruta = par.split("=", 1)
    lineas = [l for l in open(ruta, encoding="utf-8", errors="replace").read().splitlines()
              if l.strip() and not l.lstrip().startswith("#")]
    lista.append({"archivo": nombre, "entradas": len(lineas)})
    if nombre == ".gitleaksignore":
        d["gitleaksignore_proyecto"] = {"archivo": ".gitleaksignore", "entradas": len(lineas)}
d["gitleaksignore"] = sorted(lista, key=lambda x: x["archivo"])
print(json.dumps(d))
PYEOF
)"
  if "${PYI[@]}" -c 'import json,sys; sys.exit(0 if any(x["entradas"] for x in json.loads(sys.argv[1])["gitleaksignore"]) else 1)' "$EXTRA"; then
    [ "$ESTADO_GLOBAL" = ok ] && ESTADO_GLOBAL=parcial
    ERROR_GLOBAL+="${ERROR_GLOBAL:+ | }hay .gitleaksignore con entradas: gitleaks pudo silenciar secretos (no basta para declarar pass)"
  fi
fi

EXTRA="$("${PYI[@]}" - "$EXTRA" "$IGN_ESTADO" "$IGN_MOTIVO" "$IGN_OK" "${#IGNORADAS[@]}" "${#VENVS[@]}" \
  "${VENVS[@]+"${VENVS[@]}"}" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
estado, motivo, ok, n_ign, n_venv = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
d["excluidas_venv"] = sys.argv[7:7 + n_venv]
d["ignoradas"] = {"carpetas": n_ign, "escaneadas": ok, "estado": estado or ("no_aplica" if n_ign == 0 else "no_evaluado"),
                  "motivo": motivo or None}
print(json.dumps(d))
PYEOF
)"
EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); d["exclusiones_confidenciales"]=[x for x in sys.argv[2].splitlines() if x]; print(json.dumps(d))' \
  "$EXTRA" "$PATRONES_CONF")"
# Alcance: si alcance.py falla, el meta queda sin `alcance` y ningún control de ausencia puede pasar (fail-closed).
# Ronda 6 (integración, DECISIONES.md #12): alcance.ignoradas_pendientes = carpetas ignoradas sin escanear (timeout o
# error del escaneo aparte; 1 si el estado es desconocido). SEG-SECRETO-LOCAL no pasa si es > 0 (alcance_excluyente).
if ALC="$("${PYI[@]}" "$ADAPT_DIR/alcance.py" "$PROYECTO")"; then
  EXTRA="$("${PYI[@]}" -c 'import json,sys; d=json.loads(sys.argv[1]); a=json.loads(sys.argv[2]); d["alcance"]={"arbol": a["arbol"] if sys.argv[3]=="1" else 0, "historial": int(sys.argv[4]), "bundles": int(sys.argv[5]), "codigo_confidencial": a["codigo_confidencial"]}; d["alcance"].update({"commits": int(sys.argv[6])} if sys.argv[6] else {}); ig=d.get("ignoradas") or {}; d["alcance"]["ignoradas_pendientes"]=max(0, int(ig.get("carpetas") or 0)-int(ig.get("escaneadas") or 0)) if ig.get("estado") in ("ok","no_aplica","timeout","error") else 1; print(json.dumps(d))' \
    "$EXTRA" "$ALC" "$DIR_OK" "$HIST_OK" "$N_BUNDLES_OK" "$COMMITS")"
fi
escribir_meta "$ESTADO_GLOBAL" "$CODIGO_DIR" "$CMD_DIR" "$SALIDAS" "$ERROR_GLOBAL" "$EXTRA"
limpiar_tmp
exit 0
