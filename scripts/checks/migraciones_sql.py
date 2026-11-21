#!/usr/bin/env python3
"""migraciones_sql — fallback de squawk (DECISIONES #6; investigacion/13 §4.4). Cobertura parcial.

Analiza migraciones SQL versionadas (supabase/migrations, prisma/migrations/**/migration.sql,
migrations/, drizzle/, db/migrate/, database/migrations/) sentencia por sentencia, sin parser real de
Postgres (falla con SQL dinámico). Los cuerpos $$…$$ / $tag$…$tag$ y los comentarios se ignoran.

Subregla                       sev    squawk equivalente                         → control
  index_sin_concurrently        alta   require-concurrent-index-creation          → DAT-MIGRACIONES-SEGURAS
  drop_index_sin_concurrently   media  require-concurrent-index-deletion
  concurrently_en_transaccion   alta   ban-concurrent-index-creation-in-transaction
  not_null_sin_default          alta   adding-required-field
  set_not_null                  media  adding-not-nullable-field
  drop_column                   alta   ban-drop-column
  drop_table                    alta   ban-drop-table
  rename                        media  renaming-column / renaming-table
  cambio_tipo                   media  changing-column-type
  fk_sin_not_valid              media  adding-foreign-key-constraint
  check_sin_not_valid           media  constraint-missing-not-valid
  sin_lock_timeout              baja   require-lock-timeout
  tipo_timestamp                baja   prefer-timestamptz                         → DAT-TIPOS
  tipo_serial_int               baja   prefer-identity / prefer-bigint-over-int
  tipo_varchar                  baja   prefer-text-field
  reconstruccion_sqlite         info   (sin equivalente: reconstrucción SQLite sin hijas) → DAT-MIGRACION-RECONSTRUCCION
Pase ok_migraciones: ≥ 1 archivo analizado y 0 hallazgos de severidad ≥ media.
Supuesto declarado: las reglas de lock no aplican a tablas creadas en la misma migración (vacías).
Ronda 6 (stack) — dialecto: las reglas propias de PostgreSQL (CONCURRENTLY, locks de ALTER/SET NOT NULL/cambio de tipo,
NOT VALID, lock_timeout y los tipos timestamptz/identity/text) NO se aplican a migraciones SQLite. El dialecto se decide
por archivo: supabase/ → PostgreSQL; sintaxis propia (AUTOINCREMENT, PRAGMA, WITHOUT ROWID, INSERT OR REPLACE →
SQLite; timestamptz, jsonb, serial, CREATE EXTENSION/POLICY, $$, ::tipo → PostgreSQL); si no, el manifiesto más cercano
(better-sqlite3, sqlite3, @libsql/client, aiosqlite, Prisma provider "sqlite", drizzle dialect sqlite frente a pg,
postgres, psycopg, asyncpg…) y, por último, señales del proyecto (import sqlite3, archivos .db/.sqlite). Con señales de
ambos o sin señales se aplican las reglas de PostgreSQL (fail-closed). En SQLite siguen: drop_table, drop_column,
rename y not_null_sin_default (SQLite lo rechaza); la reconstrucción estándar de tabla de SQLite (CREATE nueva →
INSERT … SELECT FROM vieja → DROP vieja → ALTER nueva RENAME TO vieja) no se informa como destrucción: queda en
`omitidos` del resultado con su motivo y, si hay alguna, no hay pase (no se demostró nada que no sea esa omisión).
Ronda 7 (DECISIONES #12, adenda 2) — reconstrucción con tablas hijas: antes de declarar inocua una reconstrucción se
buscan, en TODAS las migraciones del proyecto, tablas hijas con REFERENCES <vieja> … ON DELETE CASCADE / SET NULL /
SET DEFAULT (en la columna, en FOREIGN KEY de tabla o en ALTER TABLE … ADD). Con foreign_keys=ON, SQLite hace un
DELETE implícito al ejecutar DROP TABLE: borra (CASCADE) o altera (SET NULL/DEFAULT) las filas de las hijas. Si hay
alguna, el DROP sale como drop_table (alta) con la cascada y las hijas en el mensaje. Si el pragma no puede saberse se
asume ON (fail-closed); un PRAGMA foreign_keys = OFF en el archivo no lo descarta (dentro de una transacción no surte
efecto), solo se menciona. Las reconstrucciones sin hijas siguen omitidas, pero ya no solo en el crudo: cada una
emite reconstruccion_sqlite (info) → DAT-MIGRACION-RECONSTRUCCION, visible en hallazgos.jsonl e informe.md.
Uso: migraciones_sql.py PROYECTO DIR_CRUDO
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "migraciones_sql"
REEMPLAZA = "squawk"
HERRAMIENTAS_REALES = ("squawk",)
CARPETAS = ("supabase/migrations", "prisma/migrations", "migrations", "drizzle", "db/migrate", "database/migrations")
I = re.I | re.S
IDENT = r'(?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?'


def sentencias(texto, con_cuerpos=False):
    """[(linea_inicio, sentencia)] separando por ';' fuera de cadenas, identificadores entre comillas,
    comentarios y bloques $tag$. Comentarios y cuerpos $…$ se reemplazan por espacio/'$$'.
    con_cuerpos=True (ronda 6): [(linea_inicio, sentencia, [cuerpos $…$ de la sentencia])], para quien necesita leer
    un bloque DO $$ … $$ (rls_estatico: ENABLE ROW LEVEL SECURITY dentro de EXECUTE format(…))."""
    salida, buf, cuerpos = [], [], []
    i, n, linea, inicio = 0, len(texto), 1, None
    while i < n:
        c = texto[i]
        if c == "-" and texto.startswith("--", i):
            j = texto.find("\n", i)
            j = n if j < 0 else j
            i = j
            continue
        if c == "/" and texto.startswith("/*", i):
            j = texto.find("*/", i + 2)
            j = n if j < 0 else j + 2
            linea += texto.count("\n", i, j)
            buf.append(" ")
            i = j
            continue
        if c == "$":
            m = re.match(r"\$([A-Za-z_]\w*)?\$", texto[i:])
            if m:
                tag = m.group(0)
                j = texto.find(tag, i + len(tag))
                j = n if j < 0 else j + len(tag)
                if inicio is None:
                    inicio = linea
                linea += texto.count("\n", i, j)
                buf.append("$$")
                cuerpos.append(texto[i + len(tag):max(i + len(tag), j - len(tag))])
                i = j
                continue
        if c in ("'", '"'):
            j = i + 1
            while j < n:
                if texto[j] == c:
                    if j + 1 < n and texto[j + 1] == c:
                        j += 2
                        continue
                    break
                j += 1
            j = min(j + 1, n)
            if inicio is None:
                inicio = linea
            linea += texto.count("\n", i, j)
            buf.append(texto[i:j])
            i = j
            continue
        if c == ";":
            s = "".join(buf).strip()
            if s:
                salida.append((inicio or linea, s, cuerpos) if con_cuerpos else (inicio or linea, s))
            buf, inicio, cuerpos = [], None, []
            i += 1
            continue
        if c == "\n":
            linea += 1
        elif not c.isspace() and inicio is None:
            inicio = linea
        buf.append(c)
        i += 1
    s = "".join(buf).strip()
    if s:
        salida.append((inicio or linea, s, cuerpos) if con_cuerpos else (inicio or linea, s))
    return salida


def norm_tabla(nombre):
    n = nombre.replace('"', "").lower()
    return n if "." in n else f"public.{n}"


def clausulas(cuerpo):
    """Divide por comas de nivel superior (fuera de paréntesis y cadenas)."""
    partes, buf, prof, q = [], [], 0, None
    for c in cuerpo:
        if q:
            buf.append(c)
            if c == q:
                q = None
            continue
        if c in "'\"":
            q = c
        elif c == "(":
            prof += 1
        elif c == ")":
            prof -= 1
        elif c == "," and prof == 0:
            partes.append("".join(buf).strip())
            buf = []
            continue
        buf.append(c)
    if "".join(buf).strip():
        partes.append("".join(buf).strip())
    return partes


# --------------------------------------------------------------------------------------------- dialecto (ronda 6)
RE_SQLITE_SINTAXIS = re.compile(r"\bAUTOINCREMENT\b|^\s*PRAGMA\b|\bWITHOUT\s+ROWID\b|\bINSERT\s+OR\s+(?:REPLACE|IGNORE)\b|"
                                r"\)\s*STRICT\s*(?:,|;|$)", re.I | re.M)
RE_PG_SINTAXIS = re.compile(r"\btimestamptz\b|\bjsonb\b|\b(?:big|small)?serial\b|\bCREATE\s+EXTENSION\b|\bCREATE\s+POLICY\b|"
                            r"\bROW\s+LEVEL\s+SECURITY\b|\bplpgsql\b|\bgen_random_uuid\b|\buuid_generate_v4\b|\bCONCURRENTLY\b|"
                            r"\$\$|::\s*[a-z_]+|\bauth\.uid\s*\(|\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b|\bCREATE\s+SCHEMA\b",
                            re.I)
DEPS_SQLITE = {"better-sqlite3", "sqlite3", "sqlite", "@libsql/client", "libsql", "aiosqlite", "sqlite-utils",
               "expo-sqlite", "sql.js", "@sqlite.org/sqlite-wasm", "@databases/sqlite", "sqlean", "libsql-client"}
DEPS_PG = {"pg", "postgres", "pg-promise", "@neondatabase/serverless", "@vercel/postgres", "@supabase/supabase-js",
           "psycopg", "psycopg2", "psycopg2-binary", "asyncpg", "slonik", "@electric-sql/pglite", "pgx",
           "mysql", "mysql2", "pymysql", "mysqlclient"}  # MySQL tampoco es SQLite: fail-closed hacia las reglas generales
MANIFIESTOS_BD = ("package.json", "requirements.txt", "requirements.in", "pyproject.toml", "Pipfile", "schema.prisma",
                  "drizzle.config.ts", "drizzle.config.js", "drizzle.config.mjs")


def _senales_manifiesto(texto, nombre):
    """{'sqlite', 'postgres'} según las dependencias o la configuración que declara un manifiesto."""
    senales = set()
    bajo = texto.lower()
    if nombre == "schema.prisma":
        m = re.search(r"datasource\s+\w+\s*\{[^}]*provider\s*=\s*['\"](\w+)['\"]", texto, re.S)
        if m:
            senales.add("sqlite" if m.group(1).lower() == "sqlite" else "postgres")
        return senales
    if nombre.startswith("drizzle.config"):
        m = re.search(r"(?:dialect|driver)\s*:\s*['\"]([\w-]+)['\"]", texto)
        if m:
            senales.add("sqlite" if re.search(r"sqlite|turso|libsql|d1", m.group(1), re.I) else "postgres")
        return senales
    for deps, senal in ((DEPS_SQLITE, "sqlite"), (DEPS_PG, "postgres")):
        for d in deps:
            if nombre == "package.json":
                hay = re.search(r"""['"]""" + re.escape(d) + r"""['"]\s*:""", bajo)  # clave de dependencies
            else:  # requirements / pyproject / Pipfile: el nombre al inicio de una línea o de un elemento de lista
                hay = re.search(r"""(?m)(?:^|['"])\s*""" + re.escape(d) + r"""(?![\w.-])\s*(?:[<>=!~;\[,'"]|$)""", bajo)
            if hay:
                senales.add(senal)
    return senales


class Dialecto:
    """Decide el dialecto (sqlite | postgres | desconocido) de cada migración. Solo 'sqlite' desactiva reglas."""

    def __init__(self, proyecto):
        self.proyecto = Path(proyecto)
        self._cache = {}
        self.proyecto_senales = None

    def _carpeta(self, carpeta):
        if carpeta in self._cache:
            return self._cache[carpeta]
        senales, fuente = set(), None
        for nombre in MANIFIESTOS_BD:
            q = carpeta / nombre
            if q.is_file() and not q.is_symlink():
                nuevas = _senales_manifiesto(comun.leer(q) or "", nombre)
                if nuevas:
                    senales |= nuevas
                    fuente = fuente or fb.rel(self.proyecto, q)
        prisma = carpeta / "prisma" / "schema.prisma"
        if prisma.is_file() and not prisma.is_symlink():
            nuevas = _senales_manifiesto(comun.leer(prisma) or "", "schema.prisma")
            if nuevas:
                senales |= nuevas
                fuente = fuente or fb.rel(self.proyecto, prisma)
        self._cache[carpeta] = (senales, fuente)
        return self._cache[carpeta]

    def _del_proyecto(self):
        if self.proyecto_senales is None:
            senales, fuente = set(), None
            for q in fb.recorrer(self.proyecto, {".db", ".sqlite", ".sqlite3", ".py", ".js", ".mjs", ".cjs", ".ts"}):
                suf = q.suffix.lower()
                if suf in (".db", ".sqlite", ".sqlite3"):
                    senales.add("sqlite")
                    fuente = fuente or fb.rel(self.proyecto, q)
                    continue
                texto = comun.leer(q) or ""
                if re.search(r"^\s*import\s+sqlite3\b|^\s*from\s+sqlite3\b|['\"]bun:sqlite['\"]|['\"]node:sqlite['\"]",
                             texto, re.M):
                    senales.add("sqlite")
                    fuente = fuente or fb.rel(self.proyecto, q)
                if re.search(r"^\s*import\s+(?:psycopg2?|asyncpg)\b|require\(\s*['\"]pg['\"]\s*\)|from\s+['\"]pg['\"]",
                             texto, re.M):
                    senales.add("postgres")
            self.proyecto_senales = (senales, fuente)
        return self.proyecto_senales

    def de(self, rel, texto):
        """(dialecto, motivo)."""
        if rel.startswith("supabase/") or "/supabase/" in rel:
            return "postgres", "migración de Supabase (PostgreSQL)"
        sq, pg = bool(RE_SQLITE_SINTAXIS.search(texto)), bool(RE_PG_SINTAXIS.search(texto))
        if sq and not pg:
            return "sqlite", "sintaxis propia de SQLite en el archivo (AUTOINCREMENT, PRAGMA, WITHOUT ROWID…)"
        if pg and not sq:
            return "postgres", "sintaxis propia de PostgreSQL en el archivo"
        if sq and pg:
            return "desconocido", "sintaxis de SQLite y de PostgreSQL en el mismo archivo"
        carpeta = (self.proyecto / rel).parent
        raiz = self.proyecto.resolve()
        while True:
            senales, fuente = self._carpeta(carpeta)
            if senales:
                if senales == {"sqlite"}:
                    return "sqlite", f"el manifiesto más cercano declara SQLite ({fuente})"
                if "sqlite" not in senales:
                    return "postgres", f"el manifiesto más cercano declara otro motor ({fuente})"
                return "desconocido", f"el manifiesto más cercano declara SQLite y otro motor ({fuente})"
            if carpeta.resolve() == raiz or carpeta == carpeta.parent:
                break
            carpeta = carpeta.parent
        senales, fuente = self._del_proyecto()
        if senales == {"sqlite"}:
            return "sqlite", f"el proyecto solo usa SQLite ({fuente})"
        return "desconocido", "sin señales de dialecto: se aplican las reglas de PostgreSQL (fail-closed)"


def archivos_migracion(proyecto):
    vistos = []
    for p in fb.recorrer(proyecto, {".sql"}):
        r = fb.rel(proyecto, p)
        if any(r.startswith(c + "/") or f"/{c}/" in r for c in CARPETAS):
            vistos.append(p)
    return vistos


def _reconstrucciones_sqlite(sents):
    """Tablas viejas reemplazadas con el patrón de reconstrucción de SQLite en la misma migración:
    CREATE TABLE nueva … ; INSERT INTO nueva … SELECT … FROM vieja ; DROP TABLE vieja ; ALTER TABLE nueva RENAME TO vieja.
    Devuelve {vieja: nueva}."""
    creadas, copias, renombres = set(), {}, {}
    for _, s in sents:
        m = re.match(rf"CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})", s, I)
        if m:
            creadas.add(norm_tabla(m.group(1)))
            continue
        m = re.match(rf"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+({IDENT}).*?\bSELECT\b.*?\bFROM\s+({IDENT})", s, I)
        if m:
            copias.setdefault(norm_tabla(m.group(1)), set()).add(norm_tabla(m.group(2)))
            continue
        m = re.match(rf"ALTER\s+TABLE\s+({IDENT})\s+RENAME\s+TO\s+({IDENT})\s*$", s, I)
        if m:
            renombres[norm_tabla(m.group(2))] = norm_tabla(m.group(1))
    return {vieja: nueva for vieja, nueva in renombres.items()
            if nueva in creadas and vieja in copias.get(nueva, set())}


RE_FK_ACCION = re.compile(rf"\bREFERENCES\s+({IDENT})(?:\s*\([^)]*\))?((?:(?!\bREFERENCES\b).)*)", I)
RE_ON_DELETE = re.compile(r"\bON\s+DELETE\s+(CASCADE|SET\s+NULL|SET\s+DEFAULT)\b", I)


def fk_con_accion(sents, arch):
    """FK que alteran datos al borrar el padre: {padre: [{hija, accion, archivo, linea}]}. Lee REFERENCES … ON DELETE
    CASCADE | SET NULL | SET DEFAULT en CREATE TABLE (columna o FOREIGN KEY de tabla) y en ALTER TABLE … ADD."""
    hijas = {}
    for linea, s in sents:
        m = re.match(rf"CREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})\s*\((.*)\)",
                     s, I)
        if m:
            hija, partes = norm_tabla(m.group(1)), clausulas(m.group(2))
        else:
            m = re.match(rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({IDENT})\s+(.*)$", s, I)
            if not m:
                continue
            hija, partes = norm_tabla(m.group(1)), [c for c in clausulas(m.group(2)) if re.match(r"ADD\b", c, I)]
        for cl in partes:
            for r in RE_FK_ACCION.finditer(cl):
                a = RE_ON_DELETE.search(r.group(2))
                if a:
                    pos = s.find(cl)  # línea de la cláusula (aproximada si hubo comentarios /* */ multilínea)
                    hijas.setdefault(norm_tabla(r.group(1)), []).append(
                        {"hija": hija, "accion": re.sub(r"\s+", " ", a.group(1).upper()), "archivo": arch,
                         "linea": linea + (s.count("\n", 0, pos) if pos >= 0 else 0)})
    return hijas


def _sin_public(t):
    return t[len("public."):] if t.startswith("public.") else t


REGLAS_SOLO_PG = {"index_sin_concurrently", "drop_index_sin_concurrently", "concurrently_en_transaccion", "set_not_null",
                  "cambio_tipo", "fk_sin_not_valid", "check_sin_not_valid", "sin_lock_timeout", "tipo_timestamp",
                  "tipo_serial_int", "tipo_varchar"}


def analizar_archivo(arch, texto, hallazgos, dialecto="desconocido", omitidos=None, hijas=None):
    """dialecto 'sqlite' (ronda 6): sin reglas propias de PostgreSQL; la reconstrucción de tabla no se informa como
    destrucción y se anota en `omitidos` [{archivo, linea, regla, motivo}] y como hallazgo info reconstruccion_sqlite.
    hijas (ronda 7): {padre: [{hija, accion, archivo, linea}]} de TODAS las migraciones (fk_con_accion); si falta,
    se leen las de este archivo. Una reconstrucción cuya tabla vieja tiene hijas con ON DELETE CASCADE / SET NULL /
    SET DEFAULT no es inocua: su DROP sale como drop_table (alta)."""
    omitidos = omitidos if omitidos is not None else []
    sents = sentencias(texto)
    if hijas is None:
        hijas = fk_con_accion(sents, arch)
    fk_off = bool(re.search(r"^\s*PRAGMA\s+(?:main\.)?foreign_keys\s*=\s*['\"]?(?:OFF|0|FALSE|NO)\b", texto, re.I | re.M))
    rebuild = _reconstrucciones_sqlite(sents) if dialecto == "sqlite" else {}
    creadas = set()
    for _, s in sents:
        m = re.match(rf"CREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENT})", s, I)
        if m:
            creadas.add(norm_tabla(m.group(1)))
    en_tx = False
    hay_lock_timeout = any(re.match(r"SET\s+(LOCAL\s+)?lock_timeout\b", s, I) for _, s in sents)
    alter_preexistente = None

    def h(sub, linea, mensaje, s, sev):
        if dialecto == "sqlite" and sub in REGLAS_SOLO_PG:
            return  # regla de PostgreSQL: en SQLite no hay CONCURRENTLY, NOT VALID, lock_timeout ni timestamptz
        hallazgos.append(comun.hallazgo(NOMBRE, sub, arch, linea, mensaje, fb.RE_ESPACIOS.sub(" ", s)[:200], sev))

    def reconstruccion(sub, linea, tabla, s=None):
        con_hijas = bool(hijas_de(tabla))
        tabla = _sin_public(tabla)
        motivo = (f"reconstrucción estándar de tabla en SQLite ({tabla}): se copian los datos a una tabla nueva y se la "
                  "renombra con el nombre anterior en la misma migración; " + (
                      "el RENAME no pierde datos, pero el DROP de esta reconstrucción se informó como drop_table (alta) "
                      "porque hay tablas hijas con ON DELETE CASCADE/SET NULL/SET DEFAULT" if con_hijas else
                      "ninguna migración declara tablas hijas con ON DELETE CASCADE/SET NULL/SET DEFAULT hacia ella, "
                      "así que el DROP no borra ni altera otras filas"))
        omitidos.append({"archivo": arch, "linea": linea, "regla": f"check:{NOMBRE}.{sub}", "motivo": motivo})
        if s is not None:  # ronda 7: visible como info (un hallazgo por reconstrucción, en la línea del DROP)
            hallazgos.append(comun.hallazgo(NOMBRE, "reconstruccion_sqlite", arch, linea, (
                f"Reconstrucción de tabla en SQLite ({tabla}; CREATE nueva → INSERT … SELECT → DROP → RENAME) no "
                "informada como destrucción: ninguna migración declara tablas hijas con ON DELETE CASCADE/SET NULL/"
                "SET DEFAULT hacia ella. Revisar que los índices, triggers y vistas de la tabla anterior se recreen "
                "(DROP TABLE los elimina)."),
                fb.RE_ESPACIOS.sub(" ", s)[:200], "info"))

    def hijas_de(tabla):
        return [x for x in hijas.get(tabla, []) if x["hija"] != tabla]

    for linea, s in sents:
        if re.match(r"(BEGIN|START\s+TRANSACTION)\b", s, I):
            en_tx = True
            continue
        if re.match(r"(COMMIT|END|ROLLBACK)\b", s, I):
            en_tx = False
            continue
        m = re.match(rf"CREATE\s+(UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?.*?\bON\s+(?:ONLY\s+)?({IDENT})", s, I)
        if m:
            if m.group(2) and en_tx:
                h("concurrently_en_transaccion", linea, "CREATE INDEX CONCURRENTLY dentro de una transacción: Postgres lo rechaza.",
                  s, "alta")
            elif not m.group(2) and norm_tabla(m.group(3)) not in creadas:
                h("index_sin_concurrently", linea, "CREATE INDEX sin CONCURRENTLY sobre tabla existente: bloquea escrituras "
                  "mientras se construye.", s, "alta")
            continue
        if re.match(r"DROP\s+INDEX\s+(?!CONCURRENTLY)", s, I):
            h("drop_index_sin_concurrently", linea, "DROP INDEX sin CONCURRENTLY: toma un lock exclusivo.", s, "media")
            continue
        if re.match(r"DROP\s+TABLE\b", s, I):
            md = re.match(rf"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?({IDENT})\s*$", s, I)
            if md and norm_tabla(md.group(1)) in rebuild:
                vieja = norm_tabla(md.group(1))
                afectadas = hijas_de(vieja)
                if not afectadas:
                    reconstruccion("drop_table", linea, vieja, s)
                    continue
                lista = "; ".join(f"{_sin_public(x['hija'])} (ON DELETE {x['accion']}, {x['archivo']}:{x['linea']})"
                                  for x in afectadas[:6]) + (f"; y {len(afectadas) - 6} más" if len(afectadas) > 6 else "")
                pragma = (" El archivo trae PRAGMA foreign_keys = OFF, pero dentro de una transacción (lo habitual en un "
                          "runner de migraciones) no surte efecto: se asume ON (fail-closed)." if fk_off else
                          " No se puede saber si foreign_keys está activo al migrar: se asume ON (fail-closed).")
                h("drop_table", linea, (
                    f"DROP TABLE {_sin_public(vieja)} borra o altera filas de tablas hijas: {lista}. Es una "
                    "reconstrucción de tabla de SQLite, pero con foreign_keys=ON el DROP hace un DELETE implícito y la "
                    "acción ON DELETE borra (CASCADE) o altera (SET NULL/SET DEFAULT) esas filas antes del RENAME."
                    f"{pragma} Guarda: desactivar foreign_keys fuera de la transacción, o copiar y restaurar las filas "
                    "hijas; respaldar antes."),
                  s, "alta")
                continue
            h("drop_table", linea, "DROP TABLE: operación destructiva; exige guarda (backup, despliegue en dos pasos).", s, "alta")
            continue
        m = re.match(rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({IDENT})\s+(.*)$", s, I)
        if not m:
            continue
        tabla, cuerpo = norm_tabla(m.group(1)), m.group(2)
        nueva = tabla in creadas
        if not nueva and alter_preexistente is None:
            alter_preexistente = (linea, s)
        if re.match(r"RENAME\s+TO\b", cuerpo, I):
            mr = re.match(rf"RENAME\s+TO\s+({IDENT})\s*$", cuerpo, I)
            if mr and rebuild.get(norm_tabla(mr.group(1))) == tabla:
                reconstruccion("rename", linea, norm_tabla(mr.group(1)))
                continue
            h("rename", linea, "Renombrar una tabla rompe a los clientes que aún usan el nombre anterior.", s, "media")
            continue
        for cl in clausulas(cuerpo):
            if re.match(r"ADD\s+(COLUMN\s+)?(?!CONSTRAINT\b|PRIMARY\b|UNIQUE\b|FOREIGN\b|CHECK\b)", cl, I):
                if re.search(r"\bNOT\s+NULL\b", cl, I) and not re.search(r"\bDEFAULT\b|\bGENERATED\b", cl, I) and not nueva:
                    h("not_null_sin_default", linea, "ADD COLUMN NOT NULL sin DEFAULT en tabla existente: falla si hay filas "
                      "o reescribe la tabla.", s, "alta")
            elif re.match(r"ALTER\s+(COLUMN\s+)?\S+\s+SET\s+NOT\s+NULL", cl, I) and not nueva:
                h("set_not_null", linea, "SET NOT NULL recorre la tabla con lock exclusivo (usar CHECK NOT VALID + VALIDATE).",
                  s, "media")
            elif re.match(r"ALTER\s+(COLUMN\s+)?\S+\s+(SET\s+DATA\s+)?TYPE\b", cl, I) and not nueva:
                h("cambio_tipo", linea, "Cambio de tipo de columna: puede reescribir la tabla con lock exclusivo.", s, "media")
            elif re.match(r"DROP\s+(COLUMN\s+)?(?!CONSTRAINT\b)(IF\s+EXISTS\s+)?\S+", cl, I) and not re.match(
                    r"DROP\s+(DEFAULT|NOT\s+NULL|IDENTITY|EXPRESSION)\b", cl, I):
                h("drop_column", linea, "DROP COLUMN: operación destructiva; el código desplegado puede seguir usándola.",
                  s, "alta")
            elif re.match(r"RENAME\s+(COLUMN\s+)?\S+\s+TO\b", cl, I):
                h("rename", linea, "Renombrar una columna rompe a los clientes que aún usan el nombre anterior.", s, "media")
            elif re.match(r"ADD\s+(CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\b", cl, I) and not nueva and not re.search(
                    r"NOT\s+VALID", cl, I):
                h("fk_sin_not_valid", linea, "FOREIGN KEY sin NOT VALID en tabla existente: valida todas las filas con lock.",
                  s, "media")
            elif re.match(r"ADD\s+(CONSTRAINT\s+\S+\s+)?CHECK\b", cl, I) and not nueva and not re.search(r"NOT\s+VALID", cl, I):
                h("check_sin_not_valid", linea, "CHECK sin NOT VALID en tabla existente: valida todas las filas con lock.",
                  s, "media")
    if alter_preexistente and not hay_lock_timeout:
        h("sin_lock_timeout", alter_preexistente[0], "ALTER TABLE sobre tabla existente sin SET lock_timeout: puede "
          "encolar todo el tráfico detrás del lock.", alter_preexistente[1], "baja")
    # Tipos (DAT-TIPOS): en definiciones de columnas nuevas
    for linea, s in sents:
        defin = None
        m = re.match(rf"CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{IDENT}\s*\((.*)\)", s, I)
        if m:
            defin = clausulas(m.group(1))
        else:
            m = re.match(rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{IDENT}\s+(.*)$", s, I)
            if m:
                defin = [re.sub(r"^ADD\s+(COLUMN\s+)?", "", c, flags=I) for c in clausulas(m.group(1))
                         if re.match(r"ADD\s+(COLUMN\s+)?(?!CONSTRAINT\b)", c, I)]
        for cl in defin or []:
            if re.search(r"\btimestamp\b(?!\s*(\(\d+\)\s*)?with\s+time\s+zone)", cl, I):
                h("tipo_timestamp", linea, "timestamp sin zona horaria: preferir timestamptz.", cl, "baja")
            if re.search(r"\b(serial|serial4|int4|int|integer)\b", cl, I) and re.search(r"PRIMARY\s+KEY", cl, I):
                h("tipo_serial_int", linea, "PK serial/integer: preferir bigint GENERATED ... AS IDENTITY.", cl, "baja")
            if re.search(r"\b(varchar|character\s+varying|char)\s*\(\s*\d+\s*\)", cl, I):
                h("tipo_varchar", linea, "varchar(n)/char(n): preferir text con CHECK de largo (cambiar n bloquea la tabla).",
                  cl, "baja")


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    archivos = archivos_migracion(proyecto)
    if not archivos:
        return fb.resultado(REEMPLAZA, estado="no_aplica", motivo="no hay migraciones SQL versionadas")
    hallazgos, omitidos, dialectos = [], [], {}
    detector = Dialecto(proyecto)
    textos, hijas = [], {}
    for p in archivos:
        texto = comun.leer(p)
        if texto is not None:
            rel = fb.rel(proyecto, p)
            textos.append((rel, texto))
            for padre, lista in fk_con_accion(sentencias(texto), rel).items():  # ronda 7: FK de TODAS las migraciones
                hijas.setdefault(padre, []).extend(lista)
    for rel, texto in textos:
        dialecto, motivo = detector.de(rel, texto)
        dialectos[rel] = {"dialecto": dialecto, "motivo": motivo}
        analizar_archivo(rel, texto, hallazgos, dialecto, omitidos, hijas)
    pases = []
    if not omitidos and not any(h["severidad_sugerida"] in ("critica", "alta", "media") for h in hallazgos):
        pases.append(fb.pase(NOMBRE, "migraciones", f"{len(archivos)} migraciones sin operaciones de riesgo ≥ media"))
    res = fb.resultado(REEMPLAZA, hallazgos, pases)
    res["dialectos"] = dialectos
    if omitidos:
        res["omitidos"] = omitidos
    return res


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))
