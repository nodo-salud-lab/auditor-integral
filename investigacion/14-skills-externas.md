# 14 — Skills y plugins externos para auditoría: ranking por evidencia (DECISIÓN 7)

**Proyecto:** auditor-integral · **Fecha:** 2026-11-18 · **Sellos:** SÍNTESIS (métricas de repos y fuentes leídas) + ESTIMACIÓN (costo en tokens, fórmula de puntaje) + GUÍA (integración)
**Amplía:** `investigacion/07-repos-skills-expertos.md` (no lo reemplaza). **Propuesta de configuración:** `investigacion/14-propuesta-skills_externas.toml` (archivo aparte; no se tocó `config/`, `catalogo/` ni `scripts/`).

> Regla aplicada: toda cifra viene de `gh api` (fecha 2026-11-18, UTC) o de una URL leída en esta sesión. Lo que no se pudo comprobar está marcado **NO VERIFICADO**. La fórmula de puntaje es una **ESTIMACIÓN de diseño**: la propongo yo y la decide el investigador. No existe un estándar publicado para puntuar skills de agentes.

---

## 1. Conclusiones (7 puntos)

1. **Ya está instalado lo esencial de seguridad.** Hay 8 plugins de Trail of Bits, 4 skills de Sentry/Supabase/Cloudflare copiadas con procedencia (`ORIGEN.txt`) y el plugin oficial `security-guidance` 2.0.20. Faltan **tres piezas de alto valor**: `claude-security` (Anthropic, oficial), `supabase-postgres-best-practices` (Supabase, oficial) y `security-review` de Sentry, que es la única de 5 skills de seguridad que una reseña independiente juzgó útil.
2. **Ranking de señal (sección 4):** primero `microsoft/playwright-mcp` (83,2), `anthropics/claude-plugins-official` (80,4), `supabase/mcp` (79,7), `ChromeDevTools/chrome-devtools-mcp` (77,7) y `supabase/agent-skills` (73,9). El puntaje mide **confiabilidad del origen**, no utilidad para el auditor. La recomendación (sección 6) cruza ambas cosas.
3. **Un caso a corregir en el plan: `semgrep/mcp` está archivado** (`archived: true`, último push 2025-10-28). No debe usarse. Semgrep publicó en su lugar `semgrep/skills` (beta, licencia propia "Semgrep Rules License v1.0", que no es OSI).
4. **`anthropics/claude-code-security-review` lleva 280 días sin push** (último 2026-02-11). En la práctica lo reemplazan `claude-security` y `security-guidance`, que viven en `claude-plugins-official` (push de hoy). Sigue siendo útil solo como **comparador "LLM pura"** en la validación (§11 del plan).
5. **Para no gastar tokens, ninguna skill externa se carga en el hilo principal.** Se invocan (a) solo si una condición determinista lo pide (bandera de stack, severidad ≥ alta, nivel objetivo ≥ N3), (b) dentro de un subagente con contrato de salida SARIF/JSON y tope de hallazgos, (c) con versión o commit fijado, y (d) preferentemente por CLI y no por MCP. Ver sección 7.
6. **Dos skills se descartan como dependencia por reproducibilidad o privacidad.** `vercel-labs/web-design-guidelines` descarga sus reglas de una URL en cada ejecución: no es reproducible y abre una superficie de inyección. `snyk/agent-scan` envía el contenido de las skills a la API de Snyk (el README dice que redacta los secretos antes de enviar, lo que no cambia el problema) y exige `SNYK_TOKEN`, lo que choca con la DECISIÓN 3 (nada de `kine us herramienta` sale a servicios externos). Snyk queda solo opt-in y con confirmación.
7. **Dato observado y no ejecutado (instrucción en contenido externo):** la página de documentación de Supabase (`/docs/guides/getting-started/ai-skills`) contenía una nota dirigida a agentes que pedía enviar un reporte de feedback. **No se ejecutó.** Se reporta aquí como dato. Implica que una skill que lee documentación remota en tiempo de ejecución puede recibir instrucciones de terceros, y es otro motivo para fijar versiones y no depender de fetch en vivo.

---

## 2. Método

| Criterio | Cómo se midió | Puntos máx. | Regla de puntuación (ESTIMACIÓN) |
|---|---|---|---|
| A. Autor u organización | `owner` del repo + coincidencia con la lista de la DECISIÓN 7 | 25 | 25 = Anthropic, Trail of Bits, Supabase, Vercel, Semgrep u OWASP (oficial); 20 = otra organización de ingeniería reconocida (Sentry, Cloudflare, Microsoft, Google/ChromeDevTools, HashiCorp, Snyk); 10 = individuo con trayectoria pública; 5 = otros |
| B. Estrellas | `stargazers_count` de `https://api.github.com/repos/OWNER/REPO` | 15 | 15 × min(1, log10(estrellas)/5) (100 000 ★ = tope) |
| C. Forks | `forks_count` (misma URL) | 5 | 5 × min(1, log10(forks)/4) |
| D. Mantenimiento | `pushed_at` vs. 2026-11-18 | 15 | ≤ 30 días = 15; ≤ 90 = 10; ≤ 180 = 5; > 180 = 0; archivado = excluido |
| E. Salud de issues | `https://api.github.com/search/issues?q=repo:OWNER/REPO+is:issue+is:open` y `is:closed` (excluye PR) | 10 | 10 × cerrados/(abiertos + cerrados); sin medir = 5 (neutro, marcado) |
| F. Licencia | `license.spdx_id` (y archivo LICENSE si es NOASSERTION) | 10 | MIT/Apache/ISC = 10; MPL-2.0/CC-BY-4.0 = 8; CC-BY-SA-4.0 = 6; licencia propia no OSI = 3; sin licencia = 0 |
| G. Menciones técnicas | Fuentes **leídas** en esta sesión | 10 | 10 = documentación oficial del proveedor o reseña independiente leída que la recomienda; 5 = aparece solo en buscadores o agregadores (contenido no leído); 0 = sin mención o reseña negativa |

**Limitaciones del método:** (i) las estrellas miden popularidad, no calidad; (ii) el criterio E se distorsiona con políticas de cierre automático (playwright-mcp: 0 abiertos y 948 cerrados) o con issues generados por feedback automático (supabase/agent-skills: 485 abiertos titulados "user-feedback: …"); (iii) la unidad evaluada es el **repo**, pero se adopta **una skill concreta** de él; (iv) la fórmula no está validada. Un análisis de sensibilidad, por ejemplo con pesos iguales, queda pendiente para el investigador.

**Fuentes de menciones leídas (G):**
- Reseña independiente que compara 5 skills de seguridad y elige `getsentry/skills@security-review` como la única que vale la pena (confianza por hallazgo, filtro de falsos positivos, trazado de flujo de datos), 2026-02-25: <https://timonweb.com/ai/i-checked-5-security-skills-for-claude-code-only-one-is-worth-installing/>. La misma reseña descarta `affaan-m/everything-claude-code@security-review` por ser un checklist estático.
- Redwerk, "7 Best Claude Code Plugins to Install in 2026", 2026-04-30: incluye `code-review`, `security-guidance`, `feature-dev`, `frontend-design` (Anthropic) y Playwright MCP. <https://redwerk.com/blog/best-claude-code-plugins/>. **Inconsistencia:** atribuye Playwright MCP al paquete `@anthropic-ai/playwright-mcp`, cuando el repo oficial es `microsoft/playwright-mcp`.
- SSOJet en Security Boulevard, 2026-06-07: incluye `/security-review`, `security-guidance`, `webapp-testing` (anthropics/skills) y superpowers. Declara que lo probó solo en parte. <https://securityboulevard.com/2026/06/20-claude-code-skills-every-developer-should-install-first/>
- Supabase, documentación oficial de AI skills (`supabase`, `supabase-postgres-best-practices`; instalación `npx skills add supabase/agent-skills`; plugin que incluye el MCP): <https://supabase.com/docs/guides/getting-started/ai-skills>
- README de `addyosmani/web-quality-skills` (WCAG 2.2; usa `lighthouse_audit` de Chrome DevTools MCP cuando existe): <https://github.com/addyosmani/web-quality-skills>
- README de `snyk/agent-scan` (envía contenido de skills a la API de Snyk; requiere `SNYK_TOKEN`; JSON experimental): <https://github.com/snyk/agent-scan>
- README de `claude-security` (salida `.md`, `.jsonl` y **SARIF 2.1.0** con ID de hallazgo estable entre corridas; severidad según la escala cualitativa CVSS v4.0): <https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security>
- OWASP Secure Agent Playbook (plugins `code-security-skills` y `ai-security-skills`; licencia CC-BY-4.0 según `LICENSE.md`): <https://github.com/OWASP/secure-agent-playbook>. Solo hay mención por buscador: **NO VERIFICADO** su uso o evaluación por terceros.

---

## 3. Inventario local (solo frontmatter, `installed_plugins.json` y `ORIGEN.txt`)

| Componente | Versión / origen | Procedencia verificada | Uso propuesto en el auditor |
|---|---|---|---|
| `static-analysis` (semgrep, codeql, sarif-parsing) | ToB 1.5.0 | `installed_plugins.json` | SAST y normalizador SARIF |
| `insecure-defaults` | ToB 2.0.3 | ídem | SEG configuración |
| `sharp-edges` | ToB 1.1.3 | ídem | Revisión de diseño de API (opcional) |
| `supply-chain-risk-auditor` | ToB 2.0.4 | ídem | SEG-DEPS (paquetes abandonados, install scripts) |
| `differential-review` | ToB 1.1.4 | ídem | OPS-REAUDITORIA (re-auditoría por diff) |
| `fp-check` | ToB 1.0.5 | ídem | SEG-SAST-TRIAGE |
| `audit-context-building` | ToB 2.0.2 | ídem | Solo módulos críticos (caro) |
| `variant-analysis` | ToB 2.0.4 | ídem | Después de un hallazgo crítico |
| `security-guidance` | Anthropic 2.0.20 (en caché también 2.0.17 a 2.0.19) | `plugin.json` (autor `dworken@anthropic.com`) | **No como dependencia del auditor.** Son hooks de desarrollo: avisos por patrón, revisión LLM del diff en cada Stop y revisor en `git commit`. Ojo: consume tokens en **cada** turno de cualquier sesión (README) |
| `code-review`, `feature-dev`, `frontend-design` | claude-code-plugins 1.0.1 / 1.0.1 / 1.1.1 | `installed_plugins.json` | Revisión de PR (fuera del flujo de auditoría) |
| `supabase` (skill) | supabase/agent-skills, commit `c9be0e9…` (instalada el 2026-10-19), MIT | `ORIGEN.txt` | DAT con Supabase |
| `gha-security-review`, `skill-scanner`, `secret-serialization` | getsentry/skills, commit `f57ada2…`, Apache-2.0 | `ORIGEN.txt` | SEG-CICD (complemento de zizmor), SEG-AGENTES-IA, OPS-LOGS / SEG-SECRETO |
| `workers-best-practices` | cloudflare/skills, commit `86505e4…`, Apache-2.0 | `ORIGEN.txt` | INF, solo si se detecta Cloudflare Workers |
| `security-audit` | **sin `ORIGEN.txt` ni LICENSE** | **NO VERIFICADO** (origen desconocido) | No usar como dependencia hasta registrar su procedencia. Tiene `validate-findings.cjs` y `report-schema.json` útiles, pero hay que auditarlos primero |
| `graphify` | local | sin `ORIGEN.txt` revisado | Mapa de arquitectura barato. El repo `safishamsi/graphify` redirige a `Graphify-Labs/graphify` (149 718 ★, Apache-2.0) |
| `superpowers` | 5.1.0 | `installed_plugins.json` | Proceso de construcción, no auditoría |
| `egm`, `ruflo-core`, `andrej-karpathy-skills` | 0.1.1 / 0.2.2 / 1.0.0 | `installed_plugins.json` | Sin uso en auditoría |

**No instalados y relevantes:** `claude-security`, `pr-review-toolkit` y LSPs (`typescript-lsp`, `pyright-lsp`) de `claude-plugins-official`; `supabase-postgres-best-practices`; `getsentry/skills@security-review` y `find-bugs`; de ToB: `spec-to-code-compliance`, `mutation-testing`, `semgrep-rule-creator`, `agentic-actions-auditor` y `property-based-testing`. Todos existen como directorios en sus repos (`gh api …/contents`, 2026-11-18).

---

## 4. Ranking con puntaje explícito por criterio

Datos: `gh api repos/OWNER/REPO` y búsqueda de issues, 2026-11-18. Días = días desde el último push.

| # | Repo | A autor (25) | B ★ (15) | C forks (5) | D push (15) | E issues (10) | F lic. (10) | G menc. (10) | **Total** |
|---|---|---|---|---|---|---|---|---|---|
| 1 | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | 20 | 13,8 (39 813 ★) | 4,4 (3 451) | 15 (1 d) | 10,0 (0 abiertos / 948 cerrados)¹ | 10 Apache-2.0 | 10 Redwerk | **83,2** |
| 2 | [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) | 25 | 14,0 (47 593) | 4,6 (4 945) | 15 (0 d) | 1,8 (1 098 / 249) | 10 Apache-2.0 | 10 Redwerk, SSOJet | **80,4** |
| 3 | [supabase/mcp](https://github.com/supabase/mcp) | 25 | 10,4 (3 018) | 3,3 (436) | 15 (1 d) | 6,0 (66 / 98) | 10 Apache-2.0 | 10 docs Supabase | **79,7** |
| 4 | [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) | 20 | 14,3 (58 070) | 4,6 (4 870) | 15 (1 d) | 8,8 (92 / 646) | 10 Apache-2.0 | 5 (citado en README de addyosmani) | **77,7** |
| 5 | [supabase/agent-skills](https://github.com/supabase/agent-skills) | 25 | 10,5 (3 102) | 3,0 (270) | 15 (6 d) | 0,4 (485 / 18)² | 10 MIT | 10 docs Supabase | **73,9** |
| 6 | [getsentry/skills](https://github.com/getsentry/skills) | 20 | 9,2 (1 175) | 2,3 (70) | 15 (4 d) | 4,7 (8 / 7) | 10 Apache-2.0 | 10 reseña timonweb | **71,2** |
| 7 | [anthropics/skills](https://github.com/anthropics/skills) | 25 | 15 (196 802) | 5 (23 069) | 15 (2 d) | 1,1 (457 / 57) | 0 (sin SPDX en el repo)³ | 10 SSOJet | **71,1** |
| 8 | [trailofbits/skills](https://github.com/trailofbits/skills) | 25 | 11,8 (8 260) | 3,6 (714) | 15 (6 d) | 4,6 (38 / 33) | 6 CC-BY-SA-4.0 | 5 (solo agregadores) | **71,0** |
| 9 | [obra/superpowers](https://github.com/obra/superpowers) | 10 | 15 (319 425) | 5 (28 486) | 15 (15 d) | 5 (no medido) | 10 MIT | 10 SSOJet | **70,0** |
| 10 | [snyk/agent-scan](https://github.com/snyk/agent-scan) | 20 | 10,5 (3 252) | 3,1 (298) | 15 (1 d) | 8,3 (14 / 70) | 10 Apache-2.0 | 0 | **66,9** |
| 11 | [OWASP/secure-agent-playbook](https://github.com/OWASP/secure-agent-playbook) | 25 | 7,1 (225) | 1,8 (29) | 10 (34 d) | 8,0 (2 / 8) | 8 CC-BY-4.0⁴ | 5 (buscador) | **64,9** |
| 12 | [cloudflare/skills](https://github.com/cloudflare/skills) | 20 | 10,6 (3 381) | 3,2 (351) | 15 (1 d) | 4,8 (34 / 32) | 10 Apache-2.0 | 0 | **63,6** |
| 13 | [semgrep/skills](https://github.com/semgrep/skills) | 25 | 7,6 (348) | 1,9 (36) | 15 (7 d) | 5,0 (1 / 1) | 3 Semgrep Rules License v1.0⁵ | 5 (agregadores) | **62,5** |
| 14 | [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | 25 | 13,6 (34 400) | 4,3 (2 989) | 15 (6 d) | 3,0 (76 / 32) | 0 (sin SPDX) | 0 | **60,9** |
| 15 | [affaan-m/ECC](https://github.com/affaan-m/ECC) (antes everything-claude-code) | 5 | 15 (305 627) | 5 (44 985) | 15 (1 d) | 9,1 (91 / 882) | 10 MIT | 0 (reseña negativa de su security-review) | **59,1** |
| 16 | [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | 25 | 11,5 (6 982) | 3,6 (797) | **0 (280 d)** | 2,2 (54 / 15) | 10 MIT | 5 (SSOJet solo la cita como origen de `/security-review`; no la recomienda)⁶ | **57,3** |
| 17 | [hashicorp/agent-skills](https://github.com/hashicorp/agent-skills) | 20 | 8,9 (931) | 2,7 (136) | 15 (14 d) | 2,7 (11 / 4) | 8 MPL-2.0 | 0 | **57,3** |
| 18 | [agamm/claude-code-owasp](https://github.com/agamm/claude-code-owasp) | 5 | 8,0 (453) | 2,0 (40) | 15 (15 d) | 10,0 (0 / 2) | 10 MIT | 5 (buscador) | **55,0** |
| 19 | [addyosmani/web-quality-skills](https://github.com/addyosmani/web-quality-skills) | 10 | 10,5 (3 104) | 3,0 (270) | 10 (86 d) | 5,0 (4 / 4) | 10 MIT | 0 | **48,5** |
| 20 | [trailofbits/skills-curated](https://github.com/trailofbits/skills-curated) | 25 | 8,2 (537) | 1,9 (36) | 5 (127 d) | 0,0 (13 / 0) | 6 CC-BY-SA-4.0 | 0 | **46,1** |
| — | [semgrep/mcp](https://github.com/semgrep/mcp) | — | 689 | 57 | 2025-10-28 | — | MIT | — | **EXCLUIDO: archivado** |

Notas: ¹ 0 issues abiertos con 948 cerrados sugiere una política de cierre o traslado, así que el criterio E sobreestima (NO VERIFICADO el motivo). ² Los issues abiertos más recientes se titulan "user-feedback: …": parecen feedback automatizado, no bugs, así que E subestima. ³ `anthropics/skills` declara licencia por skill: `skills/webapp-testing/LICENSE.txt` es Apache-2.0 (verificado con `gh api`, 2026-11-18). El 0 en F aplica al repo, no a esa skill. ⁴ Según `LICENSE.md`; la API devuelve NOASSERTION. ⁵ El `LICENSE` remite a <https://semgrep.dev/legal/rules-license>; restricciones de uso no leídas, NO VERIFICADO. ⁶ Corregido en la verificación (2026-11-18): el puntaje original era 62,3 con G = 10.

**Lectura:** el puntaje separa con claridad los orígenes oficiales y mantenidos (≥ 70) de los comunitarios o poco mantenidos (< 60). Dentro del grupo alto, las diferencias de 1 a 3 puntos **no son significativas**: dependen de la fórmula.

---

## 5. Cobertura por dominio: qué aporta cada skill y qué no

| Dominio | Herramienta determinista (primaria, ya en el plan §8.1) | Skill/plugin externo que complementa | Lo que la skill **no** debe decidir |
|---|---|---|---|
| SEG código | semgrep, gitleaks, osv-scanner | `claude-security` (juicio + verificación + SARIF), `getsentry security-review` (ligero), `fp-check` | El nivel N: lo decide `gates.py` con umbrales fijos |
| SEG CI/CD | zizmor, actionlint | `gha-security-review` (instalada); ToB `agentic-actions-auditor` si hay agentes IA en Actions | — |
| SEG agentes IA | `config_agentes` (propio) | `skill-scanner` (instalada, local); `snyk/agent-scan` solo opt-in (envía datos fuera) | — |
| SEG LLM | semgrep | `semgrep/skills@llm-security` (referencia OWASP LLM Top 10, beta) | — |
| DAT Supabase | splinter (SQL) / `get_advisors` de `supabase/mcp` | `supabase-postgres-best-practices` como **remediación** | Semántica de RLS: va al `revisor-autorizacion` |
| UX/a11y | axe-core + Playwright CLI, Lighthouse CI | `addyosmani/web-quality-skills` como **referencia de remediación** (WCAG 2.2, CWV) | IUA: 100 % determinista (§5.1); ninguna skill LLM entra en el IUA |
| INF IaC | checkov, trivy, hadolint | `hashicorp/agent-skills` (terraform) como referencia; `workers-best-practices` si hay Workers | — |
| COD | eslint/tsc/knip/jscpd/lizard | ToB `mutation-testing` (COD-MUTACION), `spec-to-code-compliance` (COD-FLUJOGRAMA/CRITERIOS), LSPs oficiales para diagnósticos | — |

---

## 6. Recomendación: dependencias opcionales del auditor (BORRADOR para decisión)

Cada fila indica control, condición de disparo y modo de invocación. Ninguna es obligatoria: si falta, el control usa su herramienta determinista o el fallback (DECISIÓN 6) y declara `cobertura: parcial`.

### 6.1 Integrar (prioridad alta)

| Skill / plugin | Repo (puntaje) | Controles | Disparo | Invocación barata |
|---|---|---|---|---|
| `fp-check` (instalada) | trailofbits/skills (71,0) | SEG-SAST-TRIAGE | Solo hallazgos crítico/alto de semgrep/gitleaks/osv | Subagente; entrada: hallazgo + 20 líneas de contexto; salida: `{fingerprint, veredicto, razón≤40 palabras}` |
| `claude-security` (instalar) | anthropics/claude-plugins-official (80,4) | SEG-IDOR, SEG-BFLA, SEG-AUTH-CLIENTE, SEG-MASIVA, SEG-SSRF (juicio), OPS-REAUDITORIA (modo "scan changes") | Nivel objetivo ≥ N2 y banderas `auth` o `datos_reales`; alcance limitado a rutas de auth y API (`rutas_inventario`) | Ejecutarla **fuera** del hilo; el auditor solo ingiere `CLAUDE-SECURITY-RESULTS.sarif` con el normalizador SARIF existente. Usar el ID estable para deduplicar entre corridas. Esfuerzo `low/medium` salvo pedido explícito. **Costo alto (ESTIMACIÓN): el propio plugin pide confirmar tiempo y tokens antes de escanear** |
| `supabase-postgres-best-practices` (instalar) | supabase/agent-skills (73,9) | DAT-RLS-ON, DAT-RLS-PERMISIVA, DAT-GRANTS, DAT-FK-INDICE, DAT-PK-FK, DAT-POOLER y otros 5 DAT (remediación; lista completa y mapa en la propuesta TOML). **No cubre DAT-SECDEF:** ningún archivo de `references/` trata `SECURITY DEFINER` por nombre | Proyecto con `supabase/` o dependencia `@supabase/*` y al menos un hallazgo DAT | **No cargar el SKILL.md completo:** leer solo el archivo de regla que corresponde al hallazgo (mapa regla→archivo en la propuesta TOML) |
| `get_advisors` vía `supabase/mcp` | supabase/mcp (79,7) | DAT-RLS-ON, DAT-RLS-METADATA, DAT-SECDEF, DAT-GRANTS, DAT-HIGIENE | Proyecto Supabase remoto **con permiso del dueño**; si no, splinter local | Salida JSON → normalizador; el LLM ve solo conteos y top-N |
| `gha-security-review` (instalada) | getsentry/skills (71,2) | SEG-CICD | Hay `.github/workflows/` **y** (zizmor reporta alto **o** hay `pull_request_target`/`workflow_run`) | Subagente con la lista de workflows marcados por zizmor, no todos |
| `skill-scanner` (instalada) | getsentry/skills (71,2) | SEG-AGENTES-IA | Existe `.claude/`, `.cursor/`, `AGENTS.md` o `.mcp.json` en el proyecto auditado | Subagente; solo archivos de config de agentes |
| `secret-serialization` (instalada) | getsentry/skills (71,2) | SEG-SECRETO-REPO (complemento), OPS-LOGS-ESTRUCTURADOS | Semgrep/gitleaks detectan modelos con campos `password/token/secret` | Grep previo determinista; la skill solo revisa los archivos que coinciden |

### 6.2 Integrar como opcional condicional (prioridad media)

| Skill | Repo (puntaje) | Control | Disparo |
|---|---|---|---|
| `security-review` (instalar) | getsentry/skills (71,2) | Alternativa **ligera** a `claude-security` para SEG-* de juicio | Nivel objetivo N2, o cuando el usuario no acepta el costo de `claude-security` |
| `spec-to-code-compliance` | trailofbits/skills (71,0) | COD-FLUJOGRAMA, COD-CRITERIOS | Existe flujograma o criterios declarados en la entrevista |
| `mutation-testing` | trailofbits/skills (71,0) | COD-MUTACION (N4) | Nivel objetivo ≥ N4 y módulos críticos identificados |
| `semgrep-rule-creator` | trailofbits/skills (71,0) | Construcción de reglas propias vibe coding (`reglas/`) | **En tiempo de construcción del auditor**, no en cada auditoría |
| `agentic-actions-auditor` | trailofbits/skills (71,0) | SEG-CICD | Workflows que invocan agentes IA (claude-code-action, etc.) |
| `typescript-lsp` / `pyright-lsp` | anthropics/claude-plugins-official (80,4) | COD-TIPOS (fallback si no hay `tsc`/`pyright` configurado) | Falta configuración de tipos en el proyecto |
| `web-quality-skills` (accessibility, core-web-vitals) | addyosmani (48,5) | UX-AXE-*, UX-LCP-LAB, UX-CWV-CAMPO (**solo texto de remediación**) | Hay hallazgos UX; leer el archivo de referencia puntual |
| `terraform` | hashicorp/agent-skills (57,3) | INF-IAC (remediación) | Hay `*.tf` |
| `workers-best-practices` (instalada) | cloudflare/skills (63,6) | INF-PLATAFORMA, INF-TAREAS-LARGAS | `wrangler.toml`/`wrangler.jsonc` presente |
| `llm-security` | semgrep/skills (62,5) | SEG-LLM-SALIDA, SEG-LLM-AGENCIA, SEG-REDTEAM-LLM (checklist) | Dependencias `openai`, `@anthropic-ai/sdk`, `langchain`, etc. Revisar antes la licencia (NO VERIFICADO) |

### 6.3 No integrar como dependencia (motivo)

| Skill / repo | Motivo |
|---|---|
| `security-guidance` (instalada) | Es un hook de desarrollo que corre LLM en cada Stop y commit. Dentro de una auditoría duplica costo y no produce SARIF. Mantenerla para desarrollo, no para auditar |
| `anthropics/claude-code-security-review` | 280 días sin push; excluye DoS y rate limit por diseño (informe 07). Solo como **comparador** en la validación |
| `semgrep/mcp` | Archivado |
| `vercel-labs/web-design-guidelines` | Descarga reglas remotas en cada corrida (SKILL.md: "Fetch fresh guidelines before each review"); no es reproducible, abre superficie de inyección y el repo no declara licencia |
| `snyk/agent-scan` | Envía contenido de skills y configuraciones MCP a la API de Snyk y requiere token. Prohibido para `kine us herramienta` (DECISIÓN 3); en otros proyectos, solo opt-in con confirmación |
| `affaan-m/ECC`, `wshobson/agents`, `VoltAgent/...` | Colecciones masivas; una reseña independiente descarta el security-review de ECC por ser un checklist estático; inflan el contexto |
| `agamm/claude-code-owasp`, `toshipon/...` | Autor individual con baja adopción; útiles como fuente de ideas, no como dependencia |
| `OWASP/secure-agent-playbook` | Origen óptimo (OWASP, CC-BY-4.0), pero 225 ★ y sin evaluación de terceros. **Usarlo como referencia de checklists (ASVS 5.0, `iac-security-review`, `secrets-scan`)** citando y reescribiendo; reevaluar en 6 meses |
| `security-audit` (local) | Origen no registrado; primero registrar procedencia |

---

## 7. Cómo invocarlas sin gastar muchos tokens (GUÍA; cifras = ESTIMACIÓN cualitativa)

1. **Descubrimiento sin carga.** `doctor` lee solo `~/.claude/plugins/installed_plugins.json` y la primera línea `name:` de `~/.claude/skills/*/SKILL.md`. Nunca abre el cuerpo de la skill. Reporta qué falta y cómo instalarlo, sin instalar nada (DECISIÓN 6).
2. **Disparo determinista.** Cada skill tiene una condición sobre `perfil.json` o sobre hallazgos ya normalizados (ver la propuesta TOML). Si la condición es falsa, el control usa la herramienta determinista y la skill no se toca.
3. **Aislamiento en subagente.** La skill se carga dentro de un subagente cuyo contexto se descarta. El hilo principal solo recibe el contrato de salida.
4. **Contrato de salida estrecho.** SARIF 2.1.0 o JSONL con `{fingerprint, regla, archivo, linea, severidad, confianza, resumen≤40 palabras}` y un **tope de hallazgos** (p. ej. 20 por skill, propuesta). Así lo hace `claude-security` (SARIF + ID estable) y es compatible con `sarif-parsing` de ToB.
5. **Entrada mínima.** Se pasan rutas y fragmentos (hallazgo + N líneas), no el repo. Para auditar la arquitectura se usa el grafo de `graphify` en lugar de leer todo.
6. **CLI antes que MCP.** Los MCP de navegador (playwright-mcp, chrome-devtools-mcp) devuelven snapshots de accesibilidad y trazas voluminosas; para el IUA se usan Playwright, axe y LHCI por CLI con salida JSON filtrada (jq). El MCP queda solo para exploración manual del `revisor-ux`.
7. **Referencias por archivo, no por skill.** Para remediación (Supabase, web-quality, OWASP) se mapea `regla → archivo de referencia` y se lee solo ese archivo cuando hay hallazgo.
8. **Versiones fijadas y procedencia.** Cada dependencia registra repo, commit o versión y licencia (como los `ORIGEN.txt` existentes). El informe de auditoría imprime esas versiones para que sea reproducible (§4.2 punto 7 del plan).
9. **Presupuesto explícito.** Las skills de costo alto (`claude-security`, `audit-context-building`) requieren confirmación y cuentan contra `config/presupuesto_tokens.toml`. Si se agota el presupuesto, el control sale `no_evaluado` y no se degrada en silencio.
10. **Datos confidenciales.** Ninguna skill recibe contenido de `datos-reales/` ni `datos-abiertos/` (DECISIÓN 3). La exclusión se aplica antes de construir la entrada del subagente.

---

## 8. Cambios sugeridos a documentos existentes (no aplicados: los decide el investigador u otro proceso)

| Documento | Cambio sugerido |
|---|---|
| `PLAN_MAESTRO.md` §8.2 | Agregar `claude-security`, `supabase-postgres-best-practices`, `getsentry/skills@security-review`, `OWASP/secure-agent-playbook` (referencia) y la tabla de exclusiones; anotar que `semgrep/mcp` está archivado |
| `catalogo/controles.toml` | Agregar como herramientas opcionales: `claude-security` en SEG-IDOR/BFLA/AUTH-CLIENTE/MASIVA; `gha-security-review` en SEG-CICD; `spec-to-code-compliance` en COD-FLUJOGRAMA/CRITERIOS; `mutation-testing` en COD-MUTACION; `llm-security` en SEG-LLM-*; `secret-serialization` en OPS-LOGS-ESTRUCTURADOS. Hoy SEG-CICD lista solo zizmor y actionlint |
| `config/` | Nuevo archivo de dependencias opcionales según `investigacion/14-propuesta-skills_externas.toml` |
| `investigacion/07` | Precisar: `security-guidance` **ya está instalado** (2.0.20), pero el inventario de la sección 3 del informe 07 no lo registra |

---

## 9. Pendientes NO VERIFICADO

- Licencia por skill dentro de `vercel-labs/agent-skills` (sin SPDX a nivel de repo). En `anthropics/skills`, `webapp-testing` quedó verificada como Apache-2.0.
- Términos de la "Semgrep Rules License v1.0" aplicados a `semgrep/skills`.
- Motivo de 0 issues abiertos en `microsoft/playwright-mcp` y naturaleza de los 485 "user-feedback" en `supabase/agent-skills`.
- Calidad real de `OWASP/secure-agent-playbook` (no hay evaluación de terceros leída).
- Afiliación actual de Addy Osmani (el README dice "unofficial"; no se verificó afiliación).
- Costo real en tokens de cada skill: **medir en el piloto** (brazo C, `kine us herramienta`) con el contador de `presupuesto_tokens.toml`.
- Issues de `obra/superpowers`, `wshobson/agents` y `awslabs/mcp`: no medidos (límite de la API de búsqueda).

---

## Verificación

Revisión escéptica independiente, 2026-11-18. Métodos: `gh api` (metadatos, búsqueda de issues, contenidos y commits) y WebFetch de las fuentes citadas. Se recalcularon los 20 puntajes de la §4 con la fórmula de la §2: todos coinciden salvo el caso corregido abajo.

| # | Afirmación | Fuente | Resultado |
|---|---|---|---|
| 1 | Estrellas, forks, `pushed_at` y licencia de los 20 repos del ranking | `gh api repos/OWNER/REPO` (p. ej. <https://api.github.com/repos/microsoft/playwright-mcp>) | **Confirmado.** Diferencias de ±1 a 12 ★ por el paso del tiempo (playwright-mcp 39 814; superpowers 319 437); no cambian ningún puntaje |
| 2 | `semgrep/mcp` archivado, último push 2025-10-28 | <https://api.github.com/repos/semgrep/mcp> | **Confirmado** (`archived: true`, `pushed_at` 2025-10-28T22:32:31Z) |
| 3 | `claude-code-security-review`: 280 días sin push | <https://api.github.com/repos/anthropics/claude-code-security-review> | **Confirmado** (2026-02-11 → 2026-11-18 = 280 d) |
| 4 | Conteos de issues (playwright-mcp 0/948; claude-plugins-official 1 098/249; supabase/mcp 66/98; agent-skills 485/18; getsentry 8/7; skills-curated 13/0; ccsr 54/15) | `https://api.github.com/search/issues?q=repo:OWNER/REPO+is:issue+is:open` / `is:closed` | **Confirmado** exacto en los 7 repos medidos. En playwright-mcp `has_issues = true`; el motivo de 0 abiertos sigue NO VERIFICADO |
| 5 | Commits `e6143c9…`, `a582c51…`, `149d7b2…`, `c9be0e9…` en main | `gh api repos/OWNER/REPO/commits/main` | **Confirmado** (los cuatro) |
| 6 | Existencia de `claude-security`, `pr-review-toolkit`, `typescript-lsp`, `pyright-lsp`; ToB `fp-check`, `spec-to-code-compliance`, `mutation-testing`, `semgrep-rule-creator`, `agentic-actions-auditor`, `property-based-testing`; Sentry `security-review`, `find-bugs`; `hashicorp/agent-skills/plugins/terraform`; `semgrep/skills/skills/llm-security`; addyosmani `accessibility`, `core-web-vitals` | `gh api repos/…/contents/…` | **Confirmado** |
| 7 | 11 archivos de `references/` del mapa TOML de `supabase-postgres-best-practices` | <https://github.com/supabase/agent-skills/tree/main/skills/supabase-postgres-best-practices/references> | **Confirmado.** **Corregido:** la §6.1 atribuía DAT-SECDEF a esta skill; no hay archivo que lo cubra |
| 8 | Licencias: OWASP CC-BY-4.0 en `LICENSE.md`; semgrep/skills "Semgrep Rules License v1.0" | `gh api …/contents/LICENSE.md` y `…/LICENSE` | **Confirmado.** Términos de la licencia de Semgrep: siguen NO VERIFICADO |
| 9 | `anthropics/skills` sin licencia verificable para `webapp-testing` | <https://github.com/anthropics/skills/blob/main/skills/webapp-testing/LICENSE.txt> | **Corregido:** la skill tiene `LICENSE.txt` Apache-2.0 |
| 10 | Reseña timonweb (2026-02-25) elige `getsentry/skills@security-review` y descarta la de ECC por ser checklist estático | <https://timonweb.com/ai/i-checked-5-security-skills-for-claude-code-only-one-is-worth-installing/> | **Confirmado** (5 skills comparadas) |
| 11 | Redwerk (2026-04-30) incluye code-review, security-guidance, feature-dev, frontend-design y Playwright con el paquete `@anthropic-ai/playwright-mcp` | <https://redwerk.com/blog/best-claude-code-plugins/> | **Confirmado** (las otras dos son Context7 y ast-grep) |
| 12 | SSOJet/Security Boulevard (2026-06-07) recomienda `claude-code-security-review` (G = 10 en la fila #14 original) | <https://securityboulevard.com/2026/06/20-claude-code-skills-every-developer-should-install-first/> | **Corregido:** el artículo recomienda `/security-review` (skill incluida) y solo cita el repo como origen de su análisis; no es una entrada numerada. G pasa a 5 y el total de 62,3 a **57,3** (puesto 16). La prueba práctica parcial del autor queda confirmada |
| 13 | Docs de Supabase: skills `supabase` y `supabase-postgres-best-practices`; `npx skills add supabase/agent-skills`; nota dirigida a agentes | <https://supabase.com/docs/guides/getting-started/ai-skills> | **Confirmado**, incluida la nota a agentes, que tampoco se ejecutó en esta verificación |
| 14 | `claude-security` produce SARIF 2.1.0 + JSONL con `claudeSecurityPluginFindingId` estable; escala cualitativa CVSS v4.0; pide confirmar tiempo y tokens | README del plugin, <https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security> | **Confirmado** |
| 15 | `vercel-labs/web-design-guidelines`: "Fetch fresh guidelines before each review" | `skills/web-design-guidelines/SKILL.md` en <https://github.com/vercel-labs/agent-skills> | **Confirmado** literal |
| 16 | `snyk/agent-scan` envía contenido de skills a su API y requiere `SNYK_TOKEN`; salida experimental | <https://github.com/snyk/agent-scan> (README) | **Confirmado.** **Precisión agregada:** el README dice que redacta los secretos antes de transmitir; la exclusión por DECISIÓN 3 se mantiene porque el contenido de las skills igual sale |
| 17 | addyosmani/web-quality-skills: "unofficial", WCAG 2.2, `lighthouse_audit` | README del repo | **Confirmado** |
| 18 | `SEG-CICD` hoy lista solo zizmor y actionlint; los IDs de control citados existen | `catalogo/controles.toml` | **Confirmado** (los 40 IDs usados en §6 y en el TOML existen) |

**No se verificaron en esta revisión:** el inventario local de la §3 (versiones de plugins instalados y `ORIGEN.txt`), el número de 52k ★ de ECC que cita la reseña (cifra histórica de la reseña) y los costos en tokens (ESTIMACIÓN).
