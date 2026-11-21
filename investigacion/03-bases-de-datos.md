# 03 — Dominio: Bases de datos y SQL

**Proyecto:** auditor-integral · **Fecha:** 2026-11-17 · **Sello:** SÍNTESIS (evidencia verificada) + GUÍA (procedimiento) + ESTIMACIÓN (donde se indica)

> Regla del informe: toda cifra lleva URL. Las cifras de proveedores de escáneres (muestras no aleatorias, conflicto de interés comercial) se marcan como **INDICATIVO**. Lo que no se pudo verificar se marca **NO VERIFICADO**.

---

## 1. Resumen ejecutivo

1. **La falla número uno en proyectos vibe-coded con BaaS (Supabase/Firebase) no es el SQL mal escrito, sino el control de acceso a nivel de fila (RLS) ausente o permisivo.** El caso de referencia es CVE-2025-48757 (Lovable, CVSS 9.3, disputado por el proveedor): al menos 170 apps exponían tablas de Supabase en 303 endpoints (Superblocks); el denominador de 1.645 apps escaneadas proviene de fuentes secundarias y no figura en el registro CVE ni en Superblocks (**PARCIALMENTE VERIFICADO**) ([Superblocks](https://www.superblocks.com/blog/lovable-rls-breach), [cvefeed](https://cvefeed.io/vuln/detail/CVE-2025-48757)). La causa: la `anon key` es pública por diseño y la seguridad depende 100 % de RLS bien escrita; las políticas tipo `USING (true)` equivalen a no tener RLS.
2. **La inyección SQL clásica es, paradójicamente, de lo que menos falla la IA**: Veracode 2025 midió ~20 % de fallos en CWE-89 (≈80 % de aprobación), y la actualización de primavera 2026 reporta 82 % de aprobación ([SC World](https://www.scworld.com/news/llms-make-insecure-coding-choices-for-45-of-tasks-study-finds), [Veracode Spring 2026](https://veracode.com/blog/spring-2026-genai-code-security)). Sigue siendo 1 de cada 5 casos: no se omite, pero se detecta barato con SAST (Semgrep/CodeQL, ver dominio de seguridad).
3. **Lo que la IA casi nunca hace sola**: índices sobre claves foráneas, migraciones sin locks largos (`CONCURRENTLY`, `NOT VALID`, `lock_timeout`), pooling de conexiones en serverless, backups con restauración *probada*, y separación de roles con mínimo privilegio. Todo esto es **detectable de forma determinista** con lints de catálogo y de migraciones.
4. **Estrategia de tokens**: el 80 % de este dominio se audita con (a) `squawk` sobre archivos de migración, (b) `supabase db advisors` / splinter sobre la base viva, (c) ~10 consultas SQL al catálogo de Postgres (`pg_catalog`, `pg_stat_*`) que devuelven JSON compacto. El LLM solo interpreta el JSON y juzga lo que no es mecanizable (modelo de autorización, normalización, semántica de negocio).

---

## 2. Top de fallas (priorizadas para proyectos hechos con IA)

| # | Falla | Severidad | Por qué ocurre con IA / vibe coding | Detección | Fuente |
|---|---|---|---|---|---|
| F1 | **RLS deshabilitado en tablas expuestas por la API** (`public` en Supabase) | Crítica | El agente crea tablas con SQL o desde el editor y no activa RLS; el frontend funciona igual, así que el usuario no nota nada | Determinista: lint splinter `0013_rls_disabled_in_public` (ERROR) | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F2 | **Políticas RLS permisivas** (`USING (true)`, `WITH CHECK (true)`, o solo para `SELECT` pero no `UPDATE/DELETE`) | Crítica | La IA "arregla" el error 401/permiso denegado relajando la política hasta que funcione | Determinista: `0024_permissive_rls_policy`; LLM para juzgar si la política refleja la regla de negocio | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors), [CVE-2025-48757](https://cvefeed.io/vuln/detail/CVE-2025-48757) |
| F3 | **`service_role` key (o credencial de BD con superusuario) en el bundle del cliente o en variables `NEXT_PUBLIC_`/`VITE_`** | Crítica | Para "saltarse" errores de RLS la IA sugiere usar la service key en el frontend | Determinista: gitleaks/regex sobre `dist/` y código; búsqueda de `service_role` en JWT decodificado | INDICATIVO: ~1 de cada 5 apps Lovable escaneadas ([dev.to](https://dev.to/solobillions/i-scanned-30-lovable-apps-this-month-here-are-the-5-security-issues-i-found-in-almost-every-one-4k6j)); 1 de 40 apps ([dev.to](https://dev.to/birol_dev/we-scanned-40-ai-built-production-apps-30-criticals-8-leaking-apps-and-the-three-patterns-we-51ai)) |
| F4 | **RLS que confía en `user_metadata`** (editable por el propio usuario) para roles/tenant | Crítica | La IA guarda `role: 'admin'` en `raw_user_meta_data` porque es el atajo más corto | Determinista: `0015_rls_references_user_metadata` (ERROR) | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F5 | **Funciones `SECURITY DEFINER` ejecutables por `anon`/`authenticated`**, con `search_path` mutable o SQL dinámico | Crítica/Alta | La IA usa `SECURITY DEFINER` para que una RPC "funcione" ignorando RLS | Determinista: `0028`, `0029`, `0031`, `0011_function_search_path_mutable`; vistas `0010_security_definer_view` | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F6 | **Inyección SQL** por concatenación (`$queryRawUnsafe`, `sql.raw`, template strings, `format()` sin `%I/%L` en PL/pgSQL) | Crítica | Consultas "dinámicas" para filtros/ordenamiento; ~20 % de tareas fallan CWE-89 | Determinista: Semgrep/CodeQL (reglas SQLi), grep de APIs inseguras de ORM | [SC World/Veracode](https://www.scworld.com/news/llms-make-insecure-coding-choices-for-45-of-tasks-study-finds) |
| F7 | **Sin backups o backups nunca restaurados** (RPO/RTO no definidos; plan gratuito sin PITR) | Crítica | El vibe coder asume que "la nube hace backup"; nadie prueba un restore | Manual + determinista parcial (existe script de `pg_dump`/restore en CI, PITR habilitado) | GUÍA (sin cifra) |
| F8 | **Migraciones que toman locks largos**: índice sin `CONCURRENTLY`, FK/CHECK sin `NOT VALID`, cambio de tipo de columna, `ADD COLUMN ... NOT NULL` sin default, sin `lock_timeout` | Alta | El ORM genera el DDL "ingenuo"; funciona en dev con 10 filas y bloquea prod con 10 M | Determinista: `squawk` (reglas `require-concurrent-index-creation`, `constraint-missing-not-valid`, `changing-column-type`, `require-lock-timeout`, etc.) | [Squawk rules](https://squawkhq.com/docs/rules) |
| F9 | **Claves foráneas sin índice** | Alta | Ni Postgres ni la mayoría de ORMs crean el índice del lado hijo automáticamente | Determinista: `0001_unindexed_foreign_keys` o consulta al catálogo (§5) | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F10 | **N+1 queries** (bucle con `await` dentro de `map`/`for`, resolvers GraphQL, `include` anidados sin estrategia) | Alta | La IA escribe el código más legible por función, no por request | Mixto: determinista con regex/AST (`await` + llamada ORM dentro de bucle) + `pg_stat_statements` (`calls` altas con `mean` baja); LLM confirma | [Prisma query optimization](https://prisma.io/docs/orm/prisma-client/queries/query-optimization-performance) |
| F11 | **Agotamiento de conexiones en serverless** (Vercel/Netlify/Edge abriendo conexión directa por invocación, sin pooler) | Alta | El tutorial usa la connection string directa (puerto 5432) | Determinista: inspección de `DATABASE_URL` (puerto/host de pooler, `pgbouncer=true`, `connection_limit`); `supabase inspect db role-stats`/`db-stats` | GUÍA |
| F12 | **Llamadas a `auth.uid()` en RLS re-evaluadas por fila** (sin envolver en `(select auth.uid())`) | Media/Alta (rendimiento a escala) | Copia literal de ejemplos | Determinista: `0003_auth_rls_initplan` | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F13 | **Tablas sin clave primaria, sin `NOT NULL`, sin FKs** (integridad referencial delegada a la app) | Media/Alta | Esquemas "JSON en todas partes"; columnas `text` para todo; IDs como string sin FK | Determinista: `0004_no_primary_key` + catálogo; LLM para normalización | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F14 | **Operaciones multi-paso sin transacción** (crear pedido + descontar stock + pago) y sin idempotencia | Alta | Cada `await` aislado; el cliente Supabase JS no ofrece transacciones multi-statement desde el navegador | LLM (revisión de flujos críticos) + determinista parcial (buscar múltiples `insert/update` consecutivos en un handler sin `$transaction`/`db.transaction`/RPC) | GUÍA |
| F15 | **Datos personales/sensibles sin protección** (columnas sensibles expuestas por la API, RUT/diagnósticos en texto plano, buckets públicos listables) | Crítica (en salud/datos personales) | El modelo no distingue PII; expone todo vía `select('*')` | Determinista: `0023_sensitive_columns_exposed`, `0025_public_bucket_allows_listing`; LLM para clasificar columnas | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F16 | **Permisos excesivos**: app conectada como `postgres`/owner; `GRANT ALL` a `anon`; `auth.users` expuesta | Alta/Crítica | Atajo para "que funcione" | Determinista: `0002_auth_users_exposed`; consulta `information_schema.role_table_grants` | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) |
| F17 | **Deriva de esquema** (cambios hechos a mano en el dashboard que no están en migraciones; `prisma db push` en prod) | Alta | El vibe coder edita desde la UI de Supabase; no hay fuente de verdad versionada | Determinista: `supabase db diff` / `atlas schema diff` / `prisma migrate diff` contra la base viva (diff vacío = OK) | GUÍA |
| F18 | **Índices duplicados/no usados, bloat, autovacuum deshabilitado** | Media | Índices "por si acaso" agregados por la IA | Determinista: `0005`, `0009`, `0020`, `0030`; `supabase inspect db index-stats`, `bloat` | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors), [supabase inspect db](https://supabase.com/docs/reference/cli/supabase-inspect-db) |
| F19 | **Consultas sin paginación / `select *` sin límite** | Media/Alta (saturación) | El listado funciona con datos de prueba | Mixto: regex/AST (`findMany()` sin `take`, `.select('*')` sin `.range/.limit`) + `pg_stat_statements` (filas por llamada) | GUÍA |
| F20 | **Tipos inadecuados**: `int` para PK (overflow), `timestamp` sin zona, `varchar(n)` arbitrario, `serial` en vez de `identity`, dinero en `float` | Media | Valores por defecto de tutoriales antiguos | Determinista: squawk (`prefer-bigint-over-int`, `prefer-timestamptz`, `prefer-identity`, `prefer-text-field`) | [Squawk rules](https://squawkhq.com/docs/rules) |

---

## 3. Fallas típicas de IA por stack (ORM / BaaS)

### 3.1 Supabase
- RLS desactivado o `USING (true)` (F1, F2); políticas solo para `SELECT` y no para `INSERT/UPDATE/DELETE` con `WITH CHECK`.
- `service_role` en el cliente (F3); uso de `supabase.auth.admin` desde el navegador.
- Roles en `user_metadata` (F4) en vez de `app_metadata` o tabla de roles con RLS.
- RPC `SECURITY DEFINER` sin `set search_path = ''` y sin `REVOKE EXECUTE ... FROM anon` (F5).
- Buckets de Storage públicos con listado (F15) — ver caso de buckets públicos en Lovable ([vibegraveyard](https://vibegraveyard.ai/story/lovable-public-buckets/), INDICATIVO).
- Uso de `pg_graphql` exponiendo tablas a `anon` sin intención (`0026`, `0027`).
- Edge Functions que crean un cliente con service key y no verifican el JWT del llamador.
- Cambios por dashboard sin migraciones (F17).

### 3.2 Prisma
- `$queryRawUnsafe` / `$executeRawUnsafe` con interpolación (F6). El seguro es `$queryRaw` con tagged template o `Prisma.sql`.
- N+1 por bucles con `findUnique` (F10); Prisma ejecuta exactamente lo que se escribe, no previene N+1 ([Prisma relation queries](https://www.prisma.io/docs/orm/v7/prisma-client/queries/relation-queries)). Mitigación: `include`/`select` con `relationLoadStrategy: "join"` o batching.
- `prisma db push` en producción (sin historial de migraciones) → deriva (F17).
- `@relation` sin `@@index` en el campo FK en MySQL/PlanetScale con `relationMode = "prisma"` (no hay FK real ni índice).
- Instanciar `new PrismaClient()` por request en serverless → agotamiento de conexiones (F11).
- `findMany()` sin `take` (F19); campos `Float` para dinero (usar `Decimal`).
- Herramienta de lint: `prisma-lint` (reglas configurables de convención; 143 estrellas, MIT, activo oct-2026) — útil pero poco maduro.

### 3.3 Drizzle / Kysely / SQL crudo
- `sql.raw()` con input de usuario (Drizzle), `sql.lit`/`sql.raw` (Kysely) → SQLi.
- `drizzle-kit push` en prod (mismo problema que `db push`).
- Migraciones generadas sin revisar: `ALTER COLUMN TYPE`, `DROP COLUMN` inmediatos → lint con squawk sobre el `.sql` generado.

### 3.4 Firebase / NoSQL (mención breve; fuera del foco SQL)
- Reglas `allow read, write: if true;`. Detección determinista por regex sobre `firestore.rules`. Se recomienda que el auditor tenga un submódulo análogo.

---

## 4. Herramientas y repositorios (verificados con `gh api`, 2026-11-17)

Criterio de selección: salida legible por máquina (JSON/SARIF/TSV), ejecución local o vía CLI, bajo costo de tokens.

| Herramienta | URL | Para qué | Estrellas · Licencia · Último push | Salida | Costo tokens |
|---|---|---|---|---|---|
| **squawk** | https://github.com/sbdchd/squawk | Lint de migraciones Postgres (locks, cambios peligrosos, timeouts) — 70+ reglas | 1.267 · Apache-2.0 · 2026-11-18 | `--reporter json` (también tty, gcc, gitlab; **SARIF no soportado** según [docs CLI](https://squawkhq.com/docs/cli)) | Bajo |
| **splinter** (Supabase lints) | https://github.com/supabase/splinter | Lints de seguridad/rendimiento sobre la base viva (consultas SQL puras; corre en cualquier Postgres con esquema tipo Supabase) | 292 · PostgreSQL · 2026-11-17 | Filas SQL (→ JSON) | Bajo |
| **Supabase CLI** | https://github.com/supabase/cli | `supabase db advisors`, `supabase inspect db *` (outliers, calls, locks, blocking, bloat, index-stats, table-stats, long-running-queries, role-stats, vacuum-stats, xid-age…), `supabase db diff` | 2.468 · MIT · 2026-11-17 | Texto; flag global `--output-format json` documentado, **NO VERIFICADO** en `inspect db` ([docs](https://supabase.com/docs/reference/cli/supabase-inspect-db)) | Bajo |
| **Supabase MCP `get_advisors`** | https://supabase.com/docs/guides/database/database-advisors | Igual que advisors, invocable por el agente | — | JSON | Bajo |
| **supabase/agent-skills** | https://github.com/supabase/agent-skills | Skills oficiales de Supabase para agentes (buenas prácticas de seguridad/desarrollo) — reutilizable como referencia del skill de BD | 3.101 · MIT · 2026-11-12 | Markdown | Medio (cargar solo secciones) |
| **sqlfluff** | https://github.com/sqlfluff/sqlfluff | Lint/estilo SQL multi-dialecto (ambigüedades, `select *`, aliases) | 10.028 · MIT · 2026-11-17 | `--format json` / `github-annotation` | Bajo-medio (ruidoso en estilo; usar solo reglas de corrección) |
| **Atlas** (`migrate lint`, `schema diff`) | https://github.com/ariga/atlas | Lint de migraciones (destructivas, data-dependent, backward-incompatible, naming) y diff de esquema | 8.829 · Apache-2.0 · 2026-11-17 | JSON/plantillas (**NO VERIFICADO** formato exacto); `concurrent_index` y 100+ checks requieren **Atlas Pro** ([docs](https://atlasgo.io/lint/analyzers)) | Bajo |
| **pgroll** | https://github.com/xataio/pgroll | Ejecuta migraciones expand/contract sin downtime (remediación, no auditoría) | 6.630 · Apache-2.0 · 2026-11-14 | — | — |
| **reshape** | https://github.com/fabianlindfors/reshape | Alternativa expand/contract | 1.858 · MIT · 2026-09-26 | — | — |
| **strong_migrations** | https://github.com/ankane/strong_migrations | Equivalente a squawk para Rails (referencia de catálogo de operaciones peligrosas) | 4.462 · MIT · 2026-11-02 | — | — |
| **pgTAP** | https://github.com/theory/pgtap | Tests unitarios dentro de Postgres (probar políticas RLS: "usuario A no ve filas de B") | 1.177 · licencia tipo PostgreSQL (texto en README; la API de GitHub no la detecta) · 2026-09-27 | TAP | Bajo |
| **PgHero** | https://github.com/ankane/pghero | Dashboard: consultas lentas, índices faltantes/duplicados, conexiones | 8.956 · MIT · 2026-10-22 | Web/Ruby | Medio |
| **Dexter** | https://github.com/ankane/dexter | Sugerencia automática de índices desde `pg_stat_statements` + HypoPG | 2.095 · MIT · 2026-11-01 | Texto | Bajo |
| **HypoPG** | https://github.com/HypoPG/hypopg | Índices hipotéticos para validar sugerencias sin crearlos | 1.752 · (PostgreSQL-like) · 2026-11-08 | SQL | Bajo |
| **pgBadger** | https://github.com/darold/pgbadger | Análisis de logs de Postgres (lentitud, locks, errores) | 4.075 · PostgreSQL · 2026-11-03 | HTML/JSON | Bajo (resumir JSON) |
| **SchemaSpy** | https://github.com/schemaspy/schemaspy | Documentación/diagrama ER y anomalías (tablas sin PK, FKs implícitas) | 3.741 · LGPL-3.0 · 2026-03-05 | HTML + XML | Medio (Java) |
| **schemalint** | https://github.com/kristiandupont/schemalint | Lint del esquema vivo con reglas configurables (nombres, tipos, `prefer-timestamptz`, etc.) | 445 · MIT · 2026-11-15 | Texto/JSON | Bajo |
| **pgtune** | https://github.com/le0pard/pgtune | Parámetros base de `postgresql.conf` según hardware (self-hosted) | 2.762 · MIT · 2026-11-13 | Texto | Bajo |
| **pgBackRest** | https://github.com/pgbackrest/pgbackrest | Backups/PITR self-hosted; `info --output=json` para verificar backups | 4.501 · MIT-like (NOASSERTION en GitHub) · 2026-11-17 | JSON | Bajo |
| **WAL-G** | https://github.com/wal-g/wal-g | Backups/PITR a almacenamiento de objetos | 4.340 · Apache-2.0 (NOASSERTION en GitHub) · 2026-11-17 | JSON | Bajo |
| **sqlc** | https://github.com/sqlc-dev/sqlc | Genera código tipado desde SQL (remediación anti-SQLi; `sqlc vet` con reglas) | 18.464 · MIT · 2026-11-14 | — | — |
| **libpg_query** | https://github.com/pganalyze/libpg_query | Parser real de Postgres (base de squawk) para checks AST propios | 1.494 · BSD-3 · 2026-11-10 | JSON AST | Bajo |
| **sqlmap** | https://github.com/sqlmapproject/sqlmap | Prueba dinámica de SQLi (solo en entorno propio/staging autorizado) | 38.976 · GPL (NOASSERTION) · 2026-11-12 | Texto/CSV | Medio |
| **gitleaks** | https://github.com/gitleaks/gitleaks | Secretos (connection strings, service keys) en repo y bundle | 31.145 · MIT · 2026-10-28 | JSON/SARIF | Bajo |
| **nplusone** (Python) | https://github.com/jmcarp/nplusone | Detección de N+1 en Django/SQLAlchemy en tiempo de test | 1.070 · MIT · **sin push desde 2022** | Excepción/log | Bajo — riesgo de abandono |
| **sqlcheck** | https://github.com/jarulraj/sqlcheck | Anti-patrones SQL | 2.520 · Apache-2.0 · **último push 2024-02** | Texto | Bajo — poco mantenido |
| **supa_audit** | https://github.com/supabase/supa_audit | Auditoría de cambios por tabla | 670 · **archivado** | — | Descartar; usar `pgaudit` |

**Descartados o con advertencia:** `postgresqltuner` (último push 2024-01), `supa_audit` (archivado), `nplusone`/`sqlcheck` (sin mantenimiento reciente). Atlas: la parte gratuita sirve; la regla de índice concurrente está detrás de Pro → cubrir con squawk.

---

## 5. Consultas deterministas de catálogo (núcleo del skill, bajo costo de tokens)

Diseñadas para devolver JSON compacto con `json_agg`. Ejecutar con un rol de solo lectura. **GUÍA** — validar en el proyecto de prueba antes de fijar umbrales.

```sql
-- DB-01: tablas en esquemas expuestos sin RLS
select json_agg(json_build_object('t', n.nspname||'.'||c.relname))
from pg_class c join pg_namespace n on n.oid=c.relnamespace
where c.relkind in ('r','p') and n.nspname in ('public')  -- ajustar a esquemas expuestos
  and not c.relrowsecurity;

-- DB-02: políticas permisivas (qual o with_check = true)
select json_agg(json_build_object('t',schemaname||'.'||tablename,'p',policyname,'cmd',cmd,'roles',roles,'using',qual,'check',with_check))
from pg_policies
where coalesce(qual,'')='true' or coalesce(with_check,'')='true';

-- DB-03: FKs sin índice que empiece por las columnas de la FK
select json_agg(json_build_object('t',conrelid::regclass::text,'fk',conname))
from pg_constraint c
where contype='f' and not exists (
  select 1 from pg_index i
  where i.indrelid=c.conrelid
    and (i.indkey::int2[])[0:array_length(c.conkey,1)-1] @> c.conkey);

-- DB-04: tablas sin PK
select json_agg(c.oid::regclass::text) from pg_class c join pg_namespace n on n.oid=c.relnamespace
where c.relkind='r' and n.nspname not in ('pg_catalog','information_schema')
  and not exists (select 1 from pg_constraint where conrelid=c.oid and contype='p');

-- DB-05: top 10 consultas por tiempo total (requiere pg_stat_statements)
select json_agg(q) from (
  select left(query,200) q_text, calls, round(mean_exec_time::numeric,1) mean_ms,
         round(total_exec_time::numeric) total_ms, rows/greatest(calls,1) rows_per_call
  from pg_stat_statements order by total_exec_time desc limit 10) q;
-- Firma N+1: calls muy altas, mean_ms muy baja, rows_per_call≈1 con el mismo patrón WHERE id=$1

-- DB-06: grants peligrosos a anon/authenticated/PUBLIC
select json_agg(json_build_object('grantee',grantee,'t',table_schema||'.'||table_name,'priv',privilege_type))
from information_schema.role_table_grants
where grantee in ('anon','PUBLIC') and privilege_type in ('INSERT','UPDATE','DELETE','TRUNCATE');

-- DB-07: funciones SECURITY DEFINER sin search_path fijo
select json_agg(p.oid::regprocedure::text) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog','information_schema')
  and not exists (select 1 from unnest(coalesce(p.proconfig,'{}')) c where c like 'search_path=%');

-- DB-08: saturación de conexiones
select json_build_object('used',(select count(*) from pg_stat_activity),
  'max',current_setting('max_connections')::int,
  'idle_in_tx',(select count(*) from pg_stat_activity where state='idle in transaction'));

-- DB-09: rol de la app es superusuario / bypassrls
select json_agg(rolname) from pg_roles where (rolsuper or rolbypassrls) and rolname=current_user;

-- DB-10: columnas con nombre sugerente de PII (heurística; LLM confirma)
select json_agg(table_schema||'.'||table_name||'.'||column_name) from information_schema.columns
where table_schema='public' and column_name ~* '(rut|dni|ssn|passport|diagn|phone|telefono|email|address|direccion|birth|nacimiento|salary|card|token|password)';
```

**Checks sobre código (sin BD viva), por grep/AST — costo casi nulo:**
- `rg -n '\$queryRawUnsafe|\$executeRawUnsafe|sql\.raw\(|\.raw\(`\$\{|format\(.*%s'` → candidatos SQLi.
- `rg -n 'service_role|SUPABASE_SERVICE_ROLE' -g '!*.env*'` en código cliente y en `dist/`/`.next/static`.
- `rg -n 'NEXT_PUBLIC_.*(DATABASE|SERVICE|SECRET)|VITE_.*(SERVICE|SECRET)'`.
- `rg -n 'db push'` en scripts de CI/deploy.
- Patrón N+1: `for|forEach|map` cuyo cuerpo contiene `await (prisma|db|supabase)\.` (AST con ast-grep/semgrep para precisión).
- `rg -n 'new PrismaClient\(' ` fuera de un singleton.
- `DATABASE_URL` con puerto 5432 en entorno serverless sin `pgbouncer=true`/pooler (Supabase pooler: puerto 6543 en modo transaction — **verificar en docs del proveedor del proyecto**).

---

## 6. Catálogo de chequeos (con nivel de madurez)

Niveles: **N1** prototipo · **N2** MVP con usuarios reales · **N3** beta · **N4** producción · **N5** escala.

| ID | Chequeo | Método | Herramienta | Nivel exigido |
|---|---|---|---|---|
| DB-01 | Todas las tablas expuestas por API tienen RLS activado | determinista | splinter `0013` / SQL DB-01 | N1 (si hay datos reales) / N2 obligatorio |
| DB-02 | No hay políticas `true` ni tablas con RLS sin políticas en tablas sensibles | determinista + llm | splinter `0024`, `0008` / SQL DB-02 | N2 |
| DB-03 | Las políticas RLS implementan la regla de negocio (propietario, tenant, rol) para SELECT/INSERT/UPDATE/DELETE | llm | Lectura de `pg_policies` (JSON) + modelo de dominio | N2 |
| DB-04 | Tests de RLS: usuario A no lee/modifica datos de B; `anon` no lee nada privado | determinista | pgTAP o test de integración con dos JWT | N3 |
| DB-05 | Ninguna credencial privilegiada (service_role, URL con `postgres`) en cliente/bundle/repo | determinista | gitleaks + grep sobre build | N1 |
| DB-06 | RLS no depende de `user_metadata` | determinista | splinter `0015` | N2 |
| DB-07 | Funciones SECURITY DEFINER con `search_path` fijo y EXECUTE revocado a anon | determinista | splinter `0011`, `0028`, `0029`, `0031` / SQL DB-07 | N2 |
| DB-08 | Sin SQL concatenado con input de usuario | determinista + llm (falsos positivos) | Semgrep/CodeQL + grep §5 | N1 |
| DB-09 | Esquema versionado: migraciones en repo y diff vacío contra prod | determinista | `supabase db diff` / `atlas schema diff` / `prisma migrate diff` | N2 |
| DB-10 | Migraciones seguras (CONCURRENTLY, NOT VALID + VALIDATE, lock/statement timeout, sin renames/drops directos) | determinista | squawk `--reporter json` | N3 |
| DB-11 | Cambios incompatibles con patrón expand/contract documentado | llm + manual | Revisión de PR; pgroll/reshape como remediación | N4 |
| DB-12 | Todas las tablas tienen PK; FKs declaradas donde hay relaciones | determinista | splinter `0004` / SQL DB-04, SchemaSpy | N2 |
| DB-13 | FKs indexadas | determinista | splinter `0001` / SQL DB-03 | N3 |
| DB-14 | Normalización adecuada (sin listas en texto, sin duplicación de entidades, JSONB justificado) | llm | SchemaSpy XML / dump `--schema-only` resumido | N3 |
| DB-15 | Tipos correctos (bigint/identity, timestamptz, numeric para dinero, text) y constraints (`NOT NULL`, `CHECK`, `UNIQUE`) | determinista | squawk `prefer-*`, schemalint | N3 |
| DB-16 | Operaciones multi-paso en transacción (o RPC atómica) e idempotentes | llm | Revisión de handlers críticos | N3 |
| DB-17 | Sin N+1 en endpoints principales | mixto | AST + `pg_stat_statements` (SQL DB-05) | N3 |
| DB-18 | Paginación/límites en listados | mixto | grep/AST + rows_per_call | N3 |
| DB-19 | Top consultas lentas revisadas con `EXPLAIN (ANALYZE, BUFFERS)`; índices propuestos validados | determinista + llm | `pg_stat_statements`, `supabase inspect db outliers`, Dexter + HypoPG | N4 |
| DB-20 | Pooling de conexiones correcto para el runtime (serverless → pooler en modo transacción; cliente ORM singleton) | determinista | Inspección de env + SQL DB-08 | N3 (serverless) / N4 |
| DB-21 | Timeouts configurados (`statement_timeout`, `idle_in_transaction_session_timeout`) por rol de app | determinista | `select rolname, rolconfig from pg_roles` | N4 |
| DB-22 | Rol de aplicación con mínimo privilegio (no superusuario, no owner, no BYPASSRLS); grants a `anon` mínimos | determinista | SQL DB-06, DB-09, splinter `0002` | N2 |
| DB-23 | Backups automáticos activos y PITR según RPO definido | manual + determinista | Dashboard proveedor / `pgbackrest info --output=json` / `wal-g backup-list --json` | N2 (backup diario) / N4 (PITR) |
| DB-24 | Restauración probada periódicamente con RTO medido | manual (con script) | Script `pg_dump` → restore en BD efímera + conteo de filas/checksums | N4 |
| DB-25 | PII identificada, minimizada y protegida (no expuesta por API, cifrado de columnas o de aplicación cuando corresponda, retención definida) | llm + determinista | SQL DB-10, splinter `0023`, `0025`; marco normativo | N2 (salud/PII) |
| DB-26 | Auditoría de accesos/cambios en datos sensibles | determinista | `pgaudit` habilitado / triggers de auditoría | N4 |
| DB-27 | Higiene: índices duplicados/no usados, bloat, autovacuum activo, edad de XID | determinista | splinter `0005`, `0009`, `0020`, `0030`; `supabase inspect db bloat`, `vacuum-stats`, `xid-age` | N4 |
| DB-28 | Monitoreo y alertas (conexiones, CPU, lentitud, almacenamiento) | manual | PgHero / pgBadger / observabilidad del proveedor | N4 |
| DB-29 | Plan de escalado: réplicas de lectura, particionamiento de tablas que crecen sin límite, caché | llm | Volumen (`table-stats`) + patrón de acceso | N5 |
| DB-30 | Prueba de carga con datos de volumen realista (seed escalado) | manual (script) | pgbench / k6 contra staging | N4 |

---

## 7. Señales de madurez (cómo el auditor distingue niveles)

- **N1 Prototipo:** hay base de datos; sin datos reales o con datos de prueba; ninguna clave privilegiada en el cliente; SQL sin concatenación. RLS puede faltar *solo* si no hay datos reales (debe advertirse en rojo).
- **N2 MVP:** RLS activo en 100 % de tablas expuestas, sin políticas `true`; migraciones en el repo (no solo dashboard); PKs en todas las tablas; backup diario del proveedor activo; rol de app sin superusuario; PII identificada.
- **N3 Beta:** tests de RLS automatizados (pgTAP o integración); squawk en CI sin errores; FKs indexadas; transacciones en flujos críticos; sin N+1 en endpoints top; pooling correcto; paginación.
- **N4 Producción:** PITR con RPO/RTO definidos *y* restauración probada con registro; `pg_stat_statements` revisado periódicamente; timeouts por rol; auditoría de datos sensibles; monitoreo con alertas; expand/contract para cambios incompatibles; prueba de carga con volumen realista.
- **N5 Escala:** réplicas de lectura o caché con estrategia de invalidación; particionamiento o archivado de tablas grandes; capacity planning documentado (conexiones, almacenamiento, IOPS); migraciones sin downtime automatizadas (pgroll o similar); runbooks de incidente de BD.

---

## 8. Estándares de referencia

| Estándar | URL | Uso en el auditor |
|---|---|---|
| OWASP Top 10 2021 — A03 Injection, A01 Broken Access Control | https://owasp.org/Top10/ | Clasificar F1–F6, F16 |
| OWASP ASVS 4.0.3 (V5 validación/inyección, V4 control de acceso, V8 protección de datos) | https://owasp.org/www-project-application-security-verification-standard/ | Requisitos verificables por nivel (L1–L3) mapeables a N2–N4 |
| OWASP SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html | Criterio de remediación (consultas parametrizadas, allow-list para identificadores) |
| OWASP Database Security Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html | Mínimo privilegio, cifrado en tránsito, configuración |
| CWE-89 (SQLi), CWE-284/285 (control de acceso), CWE-798 (credenciales embebidas) | https://cwe.mitre.org/data/definitions/89.html | Etiquetado de hallazgos |
| Documentación oficial PostgreSQL — Row Security Policies, Explicit Locking, Routine Backup | https://www.postgresql.org/docs/current/ddl-rowsecurity.html · https://www.postgresql.org/docs/current/explicit-locking.html · https://www.postgresql.org/docs/current/backup.html | Base técnica de DB-01..04, DB-10, DB-23/24 |
| Supabase Database Advisors (lints) | https://supabase.com/docs/guides/database/database-advisors | Códigos de lint referenciados en checks |
| CIS PostgreSQL Benchmark | https://www.cisecurity.org/benchmark/postgresql | Endurecimiento de instancias self-hosted (N4–N5) |
| Ley 19.628 (Chile) y su reforma por Ley 21.719 (2024) | https://www.bcn.cl/leychile | Contexto PII para usuarios chilenos — **no se afirma cumplimiento**; el auditor solo señala riesgos y deriva a revisión legal |

---

## 9. Diseño propuesto del sub-skill `auditor-bd` (flujo eficiente en tokens)

1. **Detección de stack (determinista, <1 s):** presencia de `supabase/`, `prisma/schema.prisma`, `drizzle.config.*`, `migrations/*.sql`, `firestore.rules`, `DATABASE_URL`.
2. **Estático sin BD viva:** squawk (JSON) sobre migraciones; grep/AST de §5; gitleaks sobre repo y build. Salida normalizada a un JSON común `{id, severidad, archivo, línea, regla, evidencia≤200 car.}`.
3. **Con BD viva (solo si el usuario provee conexión de solo lectura o proyecto Supabase vinculado):** `supabase db advisors` o splinter; consultas DB-01..10; `supabase inspect db outliers/calls/locks/index-stats/bloat`.
4. **Juicio LLM (acotado):** solo recibe (a) el JSON agregado, (b) `pg_policies` + lista de tablas/columnas (no datos), (c) los 3–5 handlers con flujos multi-paso. Juzga DB-03, DB-11, DB-14, DB-16, DB-25, DB-29.
5. **Puntuación:** el nivel alcanzado es el máximo N tal que todos los chequeos exigidos hasta ese nivel pasan (modelo de "compuerta", no promedio). Una falla Crítica bloquea N2.
6. **Hoja de ruta:** lista ordenada de chequeos fallidos del siguiente nivel, con remediación concreta (p. ej. "crear índice CONCURRENTLY en `orders(user_id)`").

**Restricciones de seguridad del propio auditor:** nunca ejecutar DDL/DML; usar rol de solo lectura; nunca volcar filas de datos (solo metadatos de catálogo) — coherente con el tratamiento confidencial de datos de pacientes; sqlmap solo contra staging propio y con confirmación explícita.

---

## 10. Vacíos y advertencias

- **No se encontró un estudio revisado por pares** que cuantifique la prevalencia de RLS deshabilitado en apps vibe-coded; las cifras disponibles provienen de proveedores de escáneres (INDICATIVO). La única cifra con respaldo de CVE es 170/1.645 apps (CVE-2025-48757).
- Porcentajes como "RLS deshabilitado en 80 %+ de tablas" o "6 errores en 90 % de apps" circulan en blogs comerciales: **NO VERIFICADO**, no usar en el informe final al usuario.
- Formato JSON de `supabase inspect db` y de `atlas migrate lint`: **NO VERIFICADO**; confirmar en el proyecto piloto.
- La licencia de pgTAP no aparece declarada en la API de GitHub: **NO VERIFICADO**.
- Puerto/modo del pooler de Supabase (6543 transaction / 5432 session): basado en conocimiento previo, **verificar** en la documentación vigente antes de codificar la regla.

---

## Verificación

**Verificador escéptico · 2026-11-17.** Método: `gh api repos/OWNER/REPO` (estrellas, último push, licencia SPDX, archivado) para los 27 repos citados; WebFetch/WebSearch para las cifras clave.

### Repositorios

| Repo | Existe | Archivado | Estrellas (gh) | Licencia (gh / verificación) | Último push | Resultado |
|---|---|---|---|---|---|---|
| sbdchd/squawk | Sí | No | 1.267 | Apache-2.0 | 2026-11-18 | OK |
| supabase/splinter | Sí | No | 292 | PostgreSQL | 2026-11-17 | OK |
| supabase/cli | Sí | No | 2.468 | MIT | 2026-11-17 | OK |
| supabase/agent-skills | Sí | No | 3.101 | MIT | 2026-11-12 | OK |
| sqlfluff/sqlfluff | Sí | No | 10.028 | MIT | 2026-11-17 | OK |
| ariga/atlas | Sí | No | 8.829 | Apache-2.0 | 2026-11-17 | OK |
| theory/pgtap | Sí | No | 1.177 | null en API; README contiene texto de licencia tipo PostgreSQL | 2026-09-27 | CORREGIDO (licencia confirmada en README) |
| xataio/pgroll | Sí | No | 6.630 | Apache-2.0 | 2026-11-14 | OK |
| fabianlindfors/reshape | Sí | No | 1.858 | MIT | 2026-09-26 | OK |
| ankane/strong_migrations | Sí | No | 4.462 | MIT | 2026-11-02 | OK |
| ankane/pghero | Sí | No | 8.956 | MIT | 2026-10-22 | OK |
| ankane/dexter | Sí | No | 2.095 | MIT | 2026-11-01 | OK |
| HypoPG/hypopg | Sí | No | 1.752 | NOASSERTION | 2026-11-08 | OK |
| darold/pgbadger | Sí | No | 4.075 | PostgreSQL | 2026-11-03 | OK |
| schemaspy/schemaspy | Sí | No | 3.741 | LGPL-3.0 | 2026-03-05 | OK |
| kristiandupont/schemalint | Sí | No | 445 | MIT | 2026-11-15 | OK |
| le0pard/pgtune | Sí | No | 2.762 | MIT | 2026-11-13 | OK |
| pgbackrest/pgbackrest | Sí | No | 4.501 | NOASSERTION; archivo LICENSE = MIT | 2026-11-17 | OK (MIT confirmado) |
| wal-g/wal-g | Sí | No | 4.340 | NOASSERTION; archivo LICENSE = Apache-2.0 | 2026-11-17 | OK (Apache-2.0 confirmado) |
| sqlc-dev/sqlc | Sí | No | 18.464 | MIT | 2026-11-14 | OK |
| pganalyze/libpg_query | Sí | No | 1.494 | BSD-3-Clause | 2026-11-10 | OK |
| sqlmapproject/sqlmap | Sí | No | 38.976 | NOASSERTION (GPL según proyecto, no verificado aquí) | 2026-11-12 | OK |
| gitleaks/gitleaks | Sí | No | 31.145 | MIT | 2026-10-28 | OK |
| loop-payments/prisma-lint | Sí | No | 143 | MIT | 2026-10-23 | OK |
| jmcarp/nplusone | Sí | No | 1.070 | MIT | 2022-11-25 | OK (advertencia de abandono correcta) |
| jarulraj/sqlcheck | Sí | No | 2.520 | Apache-2.0 | 2024-02-21 | OK (advertencia correcta) |
| supabase/supa_audit | Sí | **Sí** | 670 | Apache-2.0 | 2024-01-03 | OK (descarte correcto) |

Ningún repo inexistente. Nota: el push de squawk (2026-11-18 UTC) es posterior a la fecha local del informe por zona horaria; no es error.

### Cifras y afirmaciones

| Afirmación | Fuente consultada | Resultado |
|---|---|---|
| CVE-2025-48757: 170 apps, 303 endpoints | [Superblocks](https://www.superblocks.com/blog/lovable-rls-breach) | **VERIFICADO** ("al menos 170" apps; 303 endpoints) |
| CVE-2025-48757: denominador 1.645 apps del showcase | [cvefeed](https://cvefeed.io/vuln/detail/CVE-2025-48757) no da cifras; Superblocks no da el total; aparece en resúmenes secundarios | **PARCIAL / NO VERIFICADO en fuente primaria**. El CVE confirma CVSS 9.3, CWE-863, y que Lovable lo disputa. Se cambió la `source_url` de F1 a Superblocks |
| Veracode 2025: ~80 % aprobación CWE-89 (~20 % fallo) | Veracode blog / búsqueda; SC World devolvió 403 | **VERIFICADO vía Veracode** (80 %); SC World no accesible |
| Veracode Spring 2026: 82 % aprobación CWE-89 | [Veracode Spring 2026](https://veracode.com/blog/spring-2026-genai-code-security) | **VERIFICADO** |
| 1 de 40 apps con `service_role` en bundle | [dev.to/birol_dev](https://dev.to/birol_dev/we-scanned-40-ai-built-production-apps-30-criticals-8-leaking-apps-and-the-three-patterns-we-51ai) | **VERIFICADO** (1 de 40; 30 hallazgos críticos). Sigue siendo INDICATIVO (escáner comercial) |
| "~1 de cada 5 apps Lovable" con service key (dev.to/solobillions) | No consultada | **NO VERIFICADO** |
| Squawk: reporters tty, gcc, json, gitlab; sin SARIF | [squawkhq.com/docs/cli](https://squawkhq.com/docs/cli) | **VERIFICADO** |
| Códigos de lint Supabase (0001–0031 citados, niveles ERROR/WARN/INFO) | [Supabase advisors](https://supabase.com/docs/guides/database/database-advisors) | **VERIFICADO**: todos los códigos citados existen con el nombre indicado. Precisión: 0024 `permissive_rls_policy` es WARN y 0001 es INFO (no ERROR) |

### Correcciones aplicadas
1. Resumen ejecutivo §1: 1.645 marcado como parcialmente verificado; añadido CVSS y disputa del proveedor.
2. pgTAP: licencia tipo PostgreSQL confirmada en README (ya no NO VERIFICADO).
3. Sin repos a eliminar; estrellas y licencias coinciden con `gh api`.
4. Permanecen **NO VERIFICADO**: formato JSON de `supabase inspect db` y `atlas migrate lint`; puerto del pooler de Supabase; cifra "1 de cada 5" de dev.to/solobillions; denominador 1.645.
