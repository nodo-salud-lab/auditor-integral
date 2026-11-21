#!/usr/bin/env python3
"""rls_estatico — fallback de splinter (DECISIONES #6; investigacion/13 §4.15). Cobertura parcial.

splinter es un conjunto de vistas SQL que se ejecuta contra la base viva (o vía MCP Supabase
get_advisors). Sin conexión, este fallback reconstruye un ESTADO ACUMULADO a partir de
supabase/migrations/*.sql en orden lexicográfico (orden de aplicación). supabase/seed.sql no se lee.
Limitación crítica: los cambios hechos desde el dashboard o no versionados no se ven; por eso este
fallback puede dar fail, pero su pase (ok_rls_migraciones) NO debe dejar en pass DAT-RLS-ON ni
DAT-RLS-PERMISIVA (ver investigacion/propuestas/fallbacks_integracion.md).

Subregla                  sev      lint splinter   → control
  rls_deshabilitado        critica  0013            → DAT-RLS-ON
  vista_security_definer   alta     0010            → DAT-RLS-ON
  rls_sin_politicas        info     0008            → DAT-RLS-DENY-ALL (ronda 7). RLS activo sin políticas niega todo
                                                     acceso a anon/authenticated (deny-all); no es permisivo, así que
                                                     no va a DAT-RLS-PERMISIVA (la antigua rls_sin_politica, ronda 6,
                                                     solo quedaba en `informativos` y no llegaba al informe). Control
                                                     de severidad info, gate N4, sin bloqueo y sin pase; bloquea el
                                                     pase ok_rls_migraciones. `informativos` se sigue escribiendo.
  politica_siempre_true    critica  0024            → DAT-RLS-PERMISIVA
  politica_user_metadata   alta     0015            → DAT-RLS-METADATA
  secdef_sin_search_path   alta     0011            → DAT-SECDEF
  secdef_ejecutable_anon   alta     0028/0029       → DAT-SECDEF
  auth_users_expuesto      critica  0002            → DAT-GRANTS
  grant_anon_amplio        alta     —               → DAT-GRANTS
  sin_pk                   media    0004            → DAT-PK-FK
  fk_sin_indice            media    0001            → DAT-FK-INDICE
  bucket_publico           media    0025 (parcial)  → DAT-BUCKETS
Ronda 6 (stack): RLS activado en un bloque DO $$ … EXECUTE format('ALTER TABLE …%I ENABLE ROW LEVEL SECURITY', t)
… $$ también cuenta. Si el bucle recorre las tablas de un esquema (pg_class/pg_namespace, pg_tables o
information_schema.tables con solo filtros de esquema y tipo de tabla) o un ARRAY literal de nombres, se marcan esas
tablas (las existentes en ese punto de las migraciones). Si no se puede resolver qué tablas toca, ninguna tabla
creada antes del bloque recibe rls_deshabilitado: quedan en `rls_dinamico_no_resuelto` con el motivo, sin pase
(el control queda no_evaluado, nunca fail por esa causa).
Uso: rls_estatico.py PROYECTO DIR_CRUDO
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402
from migraciones_sql import IDENT, clausulas, norm_tabla, sentencias  # noqa: E402

NOMBRE = "rls_estatico"
REEMPLAZA = "splinter"
HERRAMIENTAS_REALES = ("splinter",)
I = re.I | re.S
ESQUEMAS_EXPUESTOS = ("public",)


def _cols(texto):
    return [c.strip().strip('"').lower() for c in texto.split(",") if c.strip()]


def _indice_implicito(cl):
    """Primera columna del índice que Postgres crea para un PRIMARY KEY o UNIQUE de la cláusula, o None.
    De tabla: «[CONSTRAINT n] PRIMARY KEY|UNIQUE (a, b)» → a. De columna: «a tipo ... PRIMARY KEY|UNIQUE» → a."""
    mt = re.match(r"(?:ADD\s+)?(?:CONSTRAINT\s+\S+\s+)?(?:PRIMARY\s+KEY|UNIQUE)\s*(?:NULLS\s+(?:NOT\s+)?DISTINCT\s*)?"
                  r"\(([^)]*)\)", cl, I)
    if mt:
        cols = _cols(mt.group(1))
        return cols[0] if cols else None
    if re.search(r"\b(PRIMARY\s+KEY|UNIQUE)\b", cl, I) and not re.match(r"(CONSTRAINT|CHECK|FOREIGN|EXCLUDE)\b", cl, I):
        col = re.sub(r"^ADD\s+(COLUMN\s+)?(IF\s+NOT\s+EXISTS\s+)?", "", cl.strip(), flags=I)
        return col.split()[0].strip('"').lower() if col.split() else None
    return None


PH = r"%(?:\d+\$)?[IsL]"  # marcador de format(): %I, %s, %1$I…
RE_EXECUTE_RLS = re.compile(r"EXECUTE\s+format\s*\(\s*'\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"
                            r"(?:(\"?\w+\"?)\s*\.\s*)?(" + PH + r"|\"?\w+\"?)\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY", I)
RE_EXECUTE_POLICY = re.compile(r"EXECUTE\s+format\s*\(\s*'\s*CREATE\s+POLICY\s+(\S+)\s+ON\s+(?:(\"?\w+\"?)\s*\.\s*)?(" + PH +
                               r"|\"?\w+\"?)((?:[^']|'')*)'", I)
RE_EXECUTE_RLS_CONCAT = re.compile(r"EXECUTE\s+'\s*ALTER\s+TABLE[^;]*?'\s*\|\|[^;]*ROW\s+LEVEL\s+SECURITY", I)
RE_ESQUEMA_FILTRO = re.compile(r"\b(?:n\.)?(?:nspname|schemaname|table_schema)\s*=\s*'(\w+)'", I)


def _tablas_del_bucle(cuerpo, variable_tabla):
    """Resuelve sobre qué tablas itera el bucle del bloque DO. Devuelve ('esquema', nombre), ('lista', [tablas]) o
    (None, motivo)."""
    m = re.search(r"\bFOREACH\s+(\w+)\s+IN\s+ARRAY\s+ARRAY\s*\[([^\]]*)\]", cuerpo, I)
    if m and (variable_tabla is None or m.group(1).lower() == variable_tabla.lower()):
        nombres = re.findall(r"'([^']+)'", m.group(2))
        return ("lista", nombres) if nombres else (None, "ARRAY sin nombres literales")
    m = re.search(r"\bFOR\s+(\w+)\s+IN\s+(?:SELECT\s+(?:\w+\s*\.\s*)?\w+\s+FROM\s+)?(?:unnest\s*\(\s*)?"
                  r"(?:ARRAY\s*\[([^\]]*)\])", cuerpo, I)
    if m:
        nombres = re.findall(r"'([^']+)'", m.group(2))
        return ("lista", nombres) if nombres else (None, "ARRAY sin nombres literales")
    m = re.search(r"\bFOR\s+(\w+)\s+IN\s+(SELECT\b.*?)\bLOOP\b", cuerpo, I)
    if not m:
        return None, "no se reconoce el bucle que recorre las tablas"
    consulta = m.group(2)
    if not re.search(r"\b(pg_class|pg_tables|information_schema\s*\.\s*tables)\b", consulta, I):
        return None, "el bucle no recorre el catálogo (pg_class, pg_tables o information_schema.tables)"
    esquemas = set(RE_ESQUEMA_FILTRO.findall(consulta))
    where = re.split(r"\bWHERE\b", consulta, maxsplit=1, flags=I)
    if len(esquemas) != 1 or len(where) != 2:
        return None, "el bucle no filtra por un único esquema"
    resto = re.sub(r"\bORDER\s+BY\b.*$", "", where[1], flags=I | re.S)
    condiciones = [c.strip() for c in re.split(r"\bAND\b", resto, flags=I) if c.strip()]
    for c in condiciones:
        if RE_ESQUEMA_FILTRO.fullmatch(c) or re.fullmatch(r"(?:\w+\.)?relkind\s*(?:=\s*'[rp]'|IN\s*\(\s*'[rp]'(?:\s*,\s*'[rp]')?\s*\))",
                                                         c, I) \
                or re.fullmatch(r"(?:\w+\.)?table_type\s*=\s*'BASE TABLE'", c, I):
            continue
        return None, f"el bucle filtra las tablas con condiciones que no se pueden resolver en estático ({c[:60]})"
    return "esquema", esquemas.pop().lower()


class Estado:
    def __init__(self):
        self.tablas = {}     # nombre → {archivo, linea, pk, fks: [(col, archivo, linea)], rls}
        self.politicas = {}  # (tabla, nombre) → {cmd, using, check, archivo, linea}
        self.indices = {}    # tabla → [primera columna]
        self.funciones = {}  # nombre → {secdef, search_path, archivo, linea, revocada}
        self.vistas = {}     # nombre → {auth_users, invoker, archivo, linea, texto}
        self.otros = []      # hallazgos directos (grant_anon_amplio, bucket_publico)
        self.no_resuelto = {}  # tabla → motivo (RLS dinámico que no se pudo resolver; ronda 6)
        self.politicas_no_resueltas = set()  # tablas con CREATE POLICY dinámico sin resolver (ronda 6)
        self.dinamicos = []    # bloques DO con RLS dinámico resueltos: {archivo, linea, tablas}

    def aplicar_do(self, arch, linea, cuerpos):
        """Ronda 6: ENABLE/DISABLE ROW LEVEL SECURITY y CREATE POLICY dentro de EXECUTE format(…) en un bloque DO."""
        for cuerpo in cuerpos:
            for mp in RE_EXECUTE_POLICY.finditer(cuerpo):
                esquema = (mp.group(2) or "public").strip('"').lower()
                if re.fullmatch(PH, mp.group(3)):
                    tipo, valor = _tablas_del_bucle(cuerpo, None)
                    if tipo == "lista":
                        tablas = [norm_tabla(n if "." in n else f"{esquema}.{n}") for n in valor]
                    elif tipo == "esquema" and valor == esquema:
                        tablas = [t for t in self.tablas if t.split(".", 1)[0] == esquema]
                    else:
                        for t in self.tablas:
                            if t.split(".", 1)[0] == esquema:
                                self.politicas_no_resueltas.add(t)
                        continue
                else:
                    tablas = [norm_tabla(f"{esquema}.{mp.group(3)}")]
                texto = mp.group(4).replace("''", "'")
                cmd = re.search(r"\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b", texto, I)
                for t in tablas:
                    nombre = re.sub(PH, t.split(".", 1)[-1], mp.group(1)).strip('"')
                    self.politicas[(t, nombre)] = {"cmd": (cmd.group(1).upper() if cmd else "ALL"), "texto": texto,
                                                   "archivo": arch, "linea": linea}
            m = RE_EXECUTE_RLS.search(cuerpo)
            concat = RE_EXECUTE_RLS_CONCAT.search(cuerpo)
            if not m and not concat:
                continue
            activa = bool(m) and m.group(3).upper() == "ENABLE"
            if m and not re.fullmatch(PH, m.group(2)):
                t = norm_tabla(f"{m.group(1)}.{m.group(2)}" if m.group(1) else m.group(2))
                if t in self.tablas:
                    self.tablas[t]["rls"] = activa
                    self.no_resuelto.pop(t, None)
                continue
            esquema_fijo = (m.group(1) or "").strip('"').lower() if m else ""
            tipo, valor = _tablas_del_bucle(cuerpo, None)
            if tipo == "esquema" and (not esquema_fijo or esquema_fijo == valor):
                tablas = [t for t in self.tablas if t.split(".", 1)[0] == valor]
            elif tipo == "lista":
                tablas = [norm_tabla(n if "." in n or not esquema_fijo else f"{esquema_fijo}.{n}") for n in valor]
                tablas = [t for t in tablas if t in self.tablas]
            else:
                motivo = (valor if tipo is None else "el esquema del bucle no coincide con el del ALTER TABLE")
                for t in self.tablas:
                    if not self.tablas[t]["rls"]:
                        self.no_resuelto[t] = f"{arch}:{linea}: RLS dinámico en un bloque DO sin resolver: {motivo}"
                continue
            for t in tablas:
                self.tablas[t]["rls"] = activa
                self.no_resuelto.pop(t, None)
            self.dinamicos.append({"archivo": arch, "linea": linea, "accion": "ENABLE" if activa else "DISABLE",
                                   "tablas": len(tablas)})

    def aplicar(self, arch, linea, s):
        m = re.match(rf"CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})\s*\((.*)\)", s, I)
        if m:
            t = norm_tabla(m.group(1))
            if t in self.tablas and re.search(r"IF\s+NOT\s+EXISTS", s, I):
                return
            info = {"archivo": arch, "linea": linea, "pk": False, "fks": [], "rls": False}
            implicitos = []
            for cl in clausulas(m.group(2)):
                idx = _indice_implicito(cl)
                if idx:
                    implicitos.append(idx)
                if re.search(r"PRIMARY\s+KEY", cl, I):
                    info["pk"] = True
                mf = re.match(r"(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(([^)]*)\)", cl, I)
                if mf:
                    info["fks"].append((_cols(mf.group(1))[0], arch, linea))
                elif re.search(r"\bREFERENCES\b", cl, I) and not re.match(r"(CONSTRAINT|CHECK|UNIQUE)\b", cl, I):
                    info["fks"].append((cl.split()[0].strip('"').lower(), arch, linea))
            self.tablas[t] = info
            self.indices[t] = implicitos
            return
        m = re.match(rf"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(.*)$", s, I)
        if m:
            for nombre in re.findall(IDENT, re.sub(r"\b(CASCADE|RESTRICT)\b", "", m.group(1), flags=I)):
                t = norm_tabla(nombre)
                self.tablas.pop(t, None)
                self.no_resuelto.pop(t, None)
                self.indices.pop(t, None)
                for k in [k for k in self.politicas if k[0] == t]:
                    self.politicas.pop(k)
            return
        m = re.match(rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({IDENT})\s+(.*)$", s, I)
        if m:
            t = norm_tabla(m.group(1))
            info = self.tablas.get(t)
            for cl in clausulas(m.group(2)):
                if info is None:
                    break
                idx = _indice_implicito(cl)
                if idx:
                    self.indices.setdefault(t, []).append(idx)
                if re.match(r"ENABLE\s+ROW\s+LEVEL\s+SECURITY", cl, I):
                    info["rls"] = True
                elif re.match(r"DISABLE\s+ROW\s+LEVEL\s+SECURITY", cl, I):
                    info["rls"] = False
                elif re.match(r"ADD\s+(CONSTRAINT\s+\S+\s+)?PRIMARY\s+KEY", cl, I):
                    info["pk"] = True
                else:
                    mf = re.match(r"ADD\s+(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(([^)]*)\)", cl, I)
                    if mf:
                        info["fks"].append((_cols(mf.group(1))[0], arch, linea))
                    elif re.match(r"ADD\s+(COLUMN\s+)?", cl, I):
                        col = re.sub(r"^ADD\s+(COLUMN\s+)?(IF\s+NOT\s+EXISTS\s+)?", "", cl, flags=I)
                        if re.search(r"PRIMARY\s+KEY", col, I):
                            info["pk"] = True
                        if re.search(r"\bREFERENCES\b", col, I):
                            info["fks"].append((col.split()[0].strip('"').lower(), arch, linea))
            return
        m = re.match(rf"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(?:\S+\s+)?ON\s+"
                     rf"(?:ONLY\s+)?({IDENT})\s*(?:USING\s+\w+\s*)?\(([^)]*)\)", s, I)
        if m:
            cols = _cols(m.group(2))
            if cols:
                self.indices.setdefault(norm_tabla(m.group(1)), []).append(cols[0])
            return
        m = re.match(rf"CREATE\s+POLICY\s+(\"[^\"]+\"|\S+)\s+ON\s+({IDENT})(.*)$", s, I)
        if m:
            resto = m.group(3)
            cmd = re.search(r"\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b", resto, I)
            self.politicas[(norm_tabla(m.group(2)), m.group(1).strip('"'))] = {
                "cmd": (cmd.group(1).upper() if cmd else "ALL"), "texto": resto, "archivo": arch, "linea": linea}
            return
        m = re.match(rf"DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?(\"[^\"]+\"|\S+)\s+ON\s+({IDENT})", s, I)
        if m:
            self.politicas.pop((norm_tabla(m.group(2)), m.group(1).strip('"')), None)
            return
        m = re.match(rf"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+({IDENT})\s*\(", s, I)
        if m:
            f = norm_tabla(m.group(1))
            previa = self.funciones.get(f, {})
            self.funciones[f] = {"secdef": bool(re.search(r"SECURITY\s+DEFINER", s, I)),
                                 "search_path": bool(re.search(r"\bSET\s+search_path\b", s, I)),
                                 "revocada": previa.get("revocada", False), "archivo": arch, "linea": linea}
            return
        m = re.match(rf"ALTER\s+FUNCTION\s+({IDENT})", s, I)
        if m and norm_tabla(m.group(1)) in self.funciones:
            f = self.funciones[norm_tabla(m.group(1))]
            if re.search(r"\bSET\s+search_path\b", s, I):
                f["search_path"] = True
            if re.search(r"SECURITY\s+INVOKER", s, I):
                f["secdef"] = False
            return
        m = re.match(rf"REVOKE\s+(?:ALL|EXECUTE)\b.*?\bON\s+FUNCTION\s+({IDENT}).*?\bFROM\s+(.*)$", s, I)
        if m and norm_tabla(m.group(1)) in self.funciones and re.search(r"\b(public|anon)\b", m.group(2), I):
            self.funciones[norm_tabla(m.group(1))]["revocada"] = True
            return
        m = re.match(rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})(.*)$", s, I)
        if m:
            v = norm_tabla(m.group(1))
            self.vistas[v] = {"auth_users": bool(re.search(r"\bauth\s*\.\s*users\b", m.group(2), I)),
                              "invoker": bool(re.search(r"security_invoker\s*=\s*(true|on|1)", m.group(2), I)),
                              "archivo": arch, "linea": linea}
            return
        m = re.match(rf"ALTER\s+VIEW\s+({IDENT})\s+SET\s*\((.*)\)", s, I)
        if m and norm_tabla(m.group(1)) in self.vistas:
            if re.search(r"security_invoker\s*=\s*(true|on|1)", m.group(2), I):
                self.vistas[norm_tabla(m.group(1))]["invoker"] = True
            return
        m = re.match(r"GRANT\s+(.*?)\s+ON\s+(.*?)\s+TO\s+(.*)$", s, I)
        if m and re.search(r"\banon\b", m.group(3), I) and re.search(r"\b(ALL|INSERT|UPDATE|DELETE|TRUNCATE)\b", m.group(1), I) \
                and not re.search(r"\bFUNCTION\b|\bSEQUENCE\b", m.group(2), I):
            self.otros.append(("grant_anon_amplio", arch, linea, "GRANT de escritura/ALL al rol anon: con RLS débil, "
                               "cualquiera sin sesión puede modificar datos.", s, "alta"))
            return
        if re.match(r"INSERT\s+INTO\s+storage\s*\.\s*buckets\b", s, I):
            cols = re.match(r"INSERT\s+INTO\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*VALUES\s*\((.*)\)", s, I)
            publico = False
            if cols:
                nombres, valores = _cols(cols.group(1)), clausulas(cols.group(2))
                if "public" in nombres and len(valores) > nombres.index("public"):
                    publico = valores[nombres.index("public")].strip().lower() in ("true", "'t'", "'true'")
            else:
                publico = bool(re.search(r"\btrue\b", s, I))
            if publico:
                self.otros.append(("bucket_publico", arch, linea, "Bucket de storage creado como público: sus archivos se "
                                   "leen sin autenticación por URL.", s, "media"))


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    base = proyecto / "supabase" / "migrations"
    archivos = sorted((p for p in fb.recorrer(proyecto, {".sql"}, desde="supabase/migrations")
                       if p.parent == base), key=lambda p: p.name)
    if not archivos:
        return fb.resultado(REEMPLAZA, estado="no_evaluado", motivo="no hay supabase/migrations/*.sql: el estado real de "
                            "RLS solo se verifica con splinter (psql) o el MCP de Supabase get_advisors")
    est = Estado()
    for p in archivos:
        texto = comun.leer(p)
        if texto is None:
            continue
        arch = fb.rel(proyecto, p)
        for linea, s, cuerpos in sentencias(texto, con_cuerpos=True):
            if cuerpos and re.match(r"DO\b", s, I):
                est.aplicar_do(arch, linea, cuerpos)
                continue
            est.aplicar(arch, linea, fb.RE_ESPACIOS.sub(" ", s))
    hallazgos, informativos, no_evaluadas = [], [], []

    def h(sub, archivo, linea, mensaje, evidencia, sev):
        hallazgos.append(comun.hallazgo(NOMBRE, sub, archivo, linea, mensaje, evidencia, sev))

    for t, info in sorted(est.tablas.items()):
        esquema = t.split(".", 1)[0]
        if esquema in ESQUEMAS_EXPUESTOS:
            pols = {k: v for k, v in est.politicas.items() if k[0] == t}
            if not info["rls"] and t in est.no_resuelto:
                no_evaluadas.append({"tabla": t, "motivo": est.no_resuelto[t]})
            elif not info["rls"]:
                h("rls_deshabilitado", info["archivo"], info["linea"], "Tabla expuesta por la API sin ENABLE ROW LEVEL "
                  "SECURITY en las migraciones (splinter 0013).", t, "critica")
            elif not pols and t not in est.politicas_no_resueltas:
                # Ronda 6: RLS activo sin políticas = deny-all para anon/authenticated (solo service_role entra). No es
                # una política permisiva: no es hallazgo de DAT-RLS-PERMISIVA; queda como informativo (nivel info).
                # Ronda 7 (DECISIONES #12, adenda 2): además es hallazgo de severidad info con regla propia
                # (rls_sin_politicas → DAT-RLS-DENY-ALL, gate N4, sin bloqueo ni pase) para que llegue a hallazgos.jsonl
                # e informe.md; `informativos` se conserva por compatibilidad del crudo.
                mensaje = ("RLS habilitado sin políticas: niega todo acceso vía API a anon y authenticated "
                           "(splinter 0008, deny-all); revisar que sea intencional.")
                informativos.append({"regla": f"check:{NOMBRE}.rls_sin_politica", "severidad": "info", "tabla": t,
                                     "archivo": info["archivo"], "linea": info["linea"], "mensaje": mensaje})
                h("rls_sin_politicas", info["archivo"], info["linea"], mensaje, t, "info")
        if not info["pk"]:
            h("sin_pk", info["archivo"], info["linea"], "Tabla sin PRIMARY KEY (splinter 0004).", t, "media")
        indices = set(est.indices.get(t, []))
        for col, archivo, linea in info["fks"]:
            if col not in indices:
                h("fk_sin_indice", archivo, linea, f"Clave foránea {t}.{col} sin índice cuya primera columna sea {col} "
                  "(splinter 0001).", f"{t}({col})", "media")
    for (t, nombre), pol in sorted(est.politicas.items()):
        texto = pol["texto"]
        if pol["cmd"] in ("ALL", "INSERT", "UPDATE", "DELETE") and re.search(
                r"\b(USING|WITH\s+CHECK)\s*\(\s*\(?\s*true\s*\)?\s*\)", texto, I):
            h("politica_siempre_true", pol["archivo"], pol["linea"], f"Política «{nombre}» ({pol['cmd']}) con USING/WITH "
              "CHECK (true): cualquiera puede escribir (splinter 0024).", f"{t}: {nombre}", "critica")
        if re.search(r"user_metadata|raw_user_meta_data", texto, I):
            h("politica_user_metadata", pol["archivo"], pol["linea"], f"Política «{nombre}» depende de user_metadata, "
              "editable por el propio usuario (splinter 0015).", f"{t}: {nombre}", "alta")
    for f, info in sorted(est.funciones.items()):
        if not info["secdef"]:
            continue
        if not info["search_path"]:
            h("secdef_sin_search_path", info["archivo"], info["linea"], "Función SECURITY DEFINER sin SET search_path "
              "fijo (splinter 0011).", f, "alta")
        if not info["revocada"] and f.split(".", 1)[0] in ESQUEMAS_EXPUESTOS:
            h("secdef_ejecutable_anon", info["archivo"], info["linea"], "Función SECURITY DEFINER en esquema expuesto sin "
              "REVOKE EXECUTE a public/anon (splinter 0028/0029).", f, "alta")
    for v, info in sorted(est.vistas.items()):
        if v.split(".", 1)[0] not in ESQUEMAS_EXPUESTOS:
            continue
        if info["auth_users"]:
            h("auth_users_expuesto", info["archivo"], info["linea"], "Vista en esquema expuesto que lee auth.users "
              "(splinter 0002).", v, "critica")
        if not info["invoker"]:
            h("vista_security_definer", info["archivo"], info["linea"], "Vista sin security_invoker = true: ignora el RLS "
              "de quien consulta (splinter 0010).", v, "alta")
    for sub, archivo, linea, mensaje, s, sev in est.otros:
        h(sub, archivo, linea, mensaje, s[:200], sev)
    pases = []
    if not hallazgos and not no_evaluadas and not informativos:
        pases.append(fb.pase(NOMBRE, "rls_migraciones", f"{len(est.tablas)} tablas verificadas contra {len(archivos)} "
                             "migraciones (no contra la base viva)"))
    res = fb.resultado(REEMPLAZA, hallazgos, pases)
    if informativos:
        res["informativos"] = informativos
    if no_evaluadas:
        res["rls_dinamico_no_resuelto"] = no_evaluadas
        res["motivo"] = ((res.get("motivo") + "; ") if res.get("motivo") else "") + (
            f"RLS de {len(no_evaluadas)} tabla(s) no evaluado: se activa con SQL dinámico (bloque DO) que no se pudo "
            "resolver en estático")
    if est.dinamicos:
        res["rls_dinamico"] = est.dinamicos
    return res


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))
