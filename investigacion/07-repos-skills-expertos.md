# 07 — Ecosistema de repositorios expertos, skills y plugins para auditoría (eficientes en tokens)

**Proyecto:** auditor-integral · **Fecha:** 2026-11-17 · **Sello:** SÍNTESIS (datos de repos) + ESTIMACIÓN (costos en tokens) + GUÍA (stack recomendado)

> Método: las cifras de estrellas, fecha de último push y licencia se obtuvieron con `gh api repos/OWNER/REPO` el 2026-11-17 (hora UTC; algunos push aparecen fechados 2026-11-18 UTC). Los contenidos de repos se revisaron con `gh api .../contents` o WebFetch del README. Los costos en tokens son **ESTIMACIÓN cualitativa** (bajo / medio / alto) según el tipo de salida (JSON/SARIF filtrable vs. lectura LLM de código), no mediciones.

---

## 1. Conclusión ejecutiva

1. **No hace falta construir desde cero.** El usuario ya tiene instalados 8 plugins de Trail of Bits (static-analysis con semgrep/codeql/sarif-parsing, insecure-defaults, sharp-edges, supply-chain-risk-auditor, differential-review, fp-check, variant-analysis, audit-context-building), además de `security-audit`, `gha-security-review`, `secret-serialization`, `skill-scanner`, `supabase`, `workers-best-practices`, y skills de `engineering:*` y `design:*`. Eso cubre ~60–70 % de los dominios de seguridad y revisión de código (ESTIMACIÓN).
2. **El hueco real no es seguridad de código, sino:** (a) orquestación por fases "idea → producción" con puntuación de madurez; (b) dominios no-seguridad deterministas: BD/migraciones (squawk, sqlfluff), carga/saturación (k6), frontend/UX/a11y (Lighthouse CI, axe-core), infraestructura como código (checkov, hadolint, trivy config); (c) checklists específicos de vibe coding (Supabase RLS, claves en `NEXT_PUBLIC_*`, rate limiting, endpoints de LLM).
3. **Patrón de eficiencia de tokens recomendado:** herramientas CLI → SARIF/JSON → un normalizador determinista (script) que deduplica y agrega por severidad → el LLM solo lee el resumen agregado + top-N hallazgos, y aplica `fp-check` únicamente a hallazgos críticos/altos. Es el mismo patrón que ya usan `static-analysis:sarif-parsing` (Trail of Bits) y el plugin oficial `claude-security` ("verification tally computed in code").
4. **Advertencia relevante:** el `security-review` oficial de Anthropic **excluye por defecto** DoS, rate limiting y agotamiento de memoria/CPU como "falsos positivos" ([README](https://github.com/anthropics/claude-code-security-review)). En apps vibe-coded la falta de rate limiting es justamente un fallo frecuente (ítem 16 del checklist de [boxed-dev/vibe-coding-security](https://github.com/boxed-dev/vibe-coding-security)). El auditor-integral debe cubrirlo en su dominio de saturación, no delegarlo a ese plugin.

---

## 2. Contexto cuantitativo (por qué auditar código generado por IA)

| Dato | Fuente | Estado |
|---|---|---|
| Código generado por IA introdujo vulnerabilidades en 45 % de 80 tareas, >100 LLM (2025); XSS (CWE-80) falló en 86 % y log injection (CWE-117) en 88 % | [Veracode, nota de prensa 2025](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/) | Verificado vía buscador; no se leyó el PDF completo |
| Informe 2026: tasa media de aprobación de seguridad 56 %, prácticamente plana vs. año anterior; Java 30 %, Python 63 % | [SD Times sobre Veracode 2026](https://sdtimes.com/agentic-security/veracode-finds-ai-generated-code-security-has-barely-improved-since-last-year/) | Resumen de buscador; NO VERIFICADO contra el informe original |
| OWASP Top 10:2025: Broken Access Control #1; Security Misconfiguration sube a #2; nuevas A03 Software Supply Chain Failures y A10 Mishandling of Exceptional Conditions | [owasp.org Top10 2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/), [Semgrep blog](https://semgrep.dev/blog/2026/owasp-top-10-2025-whats-new) | Verificado parcialmente |

Implicancia de diseño: las categorías que más fallan en código IA (control de acceso, misconfiguración, cadena de suministro, manejo de errores) son en buena parte **detectables de forma determinista** (semgrep, checkov, osv-scanner, gitleaks) — salvo control de acceso/IDOR y lógica de negocio, que requieren juicio LLM.

---

## 3. Inventario: skills y plugins ya instalados (reutilizables)

Fuente: `~/.claude/skills/*/SKILL.md` y `~/.claude/plugins/cache/*` (solo frontmatter). Marketplaces en caché: `trailofbits`, `superpowers-marketplace`, `claude-code-plugins`, `karpathy-skills`, `ruflo`, `egm`.

| Skill / plugin instalado | Qué hace (frontmatter) | Dominio auditor-integral | Determinista vs LLM | Reutilizar como |
|---|---|---|---|---|
| `static-analysis:semgrep` / `semgrep-scan` (ToB 1.5.0) | Ejecuta Semgrep y gestiona resultados | Código, seguridad | Determinista + triage LLM | **Núcleo SAST** |
| `static-analysis:codeql` / `codeql-build` | CodeQL con build de base de datos | Seguridad profunda | Determinista (costoso en tiempo) | SAST profundo nivel N3+ |
| `static-analysis:sarif-parsing` | Parseo/agregación de SARIF | Transversal | Determinista | **Normalizador de hallazgos** |
| `insecure-defaults:audit` / `audit-pipeline` | Defaults "fail-open" con verificadores por archivo | Seguridad config | Mixto | Fase configuración |
| `sharp-edges` | APIs propensas a error, configs peligrosas | Seguridad/diseño | LLM | Revisión de diseño de API |
| `supply-chain-risk-auditor` (2.0.4) | Advisories por versión, lockfile completo, paquetes abandonados, install scripts | Dependencias | Mixto (consulta advisories) | **Fase dependencias** |
| `differential-review:diff-review` | Revisión de seguridad de cambios con git blame | Seguridad incremental | LLM | Modo "re-auditoría" |
| `fp-check` | Veredicto TRUE/FALSE POSITIVE documentado | Transversal | LLM | **Filtro de falsos positivos solo para crítico/alto** |
| `variant-analysis:variants` | Busca variantes de un bug ya hallado | Seguridad | Mixto | Después de un hallazgo crítico |
| `audit-context-building:audit-context` | Contexto por función (supuestos/garantías) | Arquitectura | LLM (caro) | Solo en módulos críticos (auth, pagos) |
| `security-audit` (local) | Revisión de seguridad completa / pentest de código | Seguridad | LLM | Fase de juicio de seguridad |
| `gha-security-review` (local) | Explotación de workflows de GitHub Actions | CI/CD | LLM | Fase despliegue |
| `secret-serialization` (local) | Secretos filtrados por repr/asdict/JSON.stringify | Seguridad datos | Mixto | Complemento a gitleaks |
| `skill-scanner` (local) | Escaneo de skills | Cadena de suministro de IA | Mixto | Auditar `.claude/` del proyecto auditado |
| `supabase` (local) + MCP Supabase `get_advisors` | Advisors de seguridad/rendimiento de Supabase | BD | Determinista (API) | **Fase BD si el proyecto usa Supabase** |
| `workers-best-practices` | Buenas prácticas Cloudflare Workers | Infra | LLM | Condicional |
| `engineering:deploy-checklist`, `engineering:testing-strategy`, `engineering:tech-debt`, `engineering:system-design`, `engineering:architecture`, `engineering:incident-response` | Checklists de ingeniería | Despliegue, pruebas, escalabilidad | LLM (ligero) | Plantillas de fase |
| `design:accessibility-review`, `design:design-critique`, `design:ux-copy` | Revisión a11y/UX | Usabilidad | LLM | Complemento a axe/Lighthouse |
| `data:sql-queries`, `data:validate-data` | SQL y validación | BD | LLM | Revisión de consultas |
| `code-review`, `security-review` (built-in) | Revisión de diff | Código/seguridad | LLM | Revisión de PR (ojo: excluye DoS/rate limit) |
| `superpowers:verification-before-completion`, `systematic-debugging`, `writing-skills`, `writing-plans` | Disciplina de proceso | Meta | LLM | Para construir el propio auditor |
| `graphify` | Grafo de conocimiento de un codebase | Arquitectura | Mixto | **Mapa de arquitectura barato** (alternativa a leer todo) |

**Nota:** el plugin `insecure-defaults` aparece en la lista de skills de sesión pero no expone `SKILL.md` en la ruta de caché revisada (probablemente comandos). Sin impacto práctico.

---

## 4. Repositorios externos evaluados

Columnas: estrellas / último push / licencia según `gh api` (2026-11-17). Costo tokens = ESTIMACIÓN.

### 4.1 Skills y plugins de agentes

| Repo | ★ | Último push | Licencia | Qué reutilizar | Costo tokens |
|---|---|---|---|---|---|
| [trailofbits/skills](https://github.com/trailofbits/skills) | 8 259 | 2026-11-12 | CC-BY-SA-4.0 | 47 plugins. Ya instalados 8. **Añadir:** `semgrep-rule-creator` (reglas propias para patrones vibe coding), `agentic-actions-auditor` (Actions con agentes IA), `mutation-testing`, `property-based-testing`, `spec-to-code-compliance` (¿el código cumple el flujograma/spec?), `cvss-scoring`, `trailmark` (grafo + taint), `firebase-apk-scanner` | Medio (skills SKILL.md largos; se cargan bajo demanda) |
| [anthropics/claude-plugins-official](https://github.com/anthropics/claude-plugins-official) | 47 587 | 2026-11-18 | Apache-2.0 | **`claude-security`** (escaneo profundo con verificación de cada hallazgo y conteo en código; parches verificados), **`security-guidance`** (hooks: avisos por patrón en ediciones + revisión LLM de diff en Stop; >25 clases de vulnerabilidad), `pr-review-toolkit`, `code-simplifier`, LSPs (`typescript-lsp`, `pyright-lsp`) para diagnósticos baratos, `hookify` | Bajo–medio (`security-guidance` por patrón es barato; revisión de diff es LLM) |
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | 6 982 | 2026-02-11 | MIT | GitHub Action + `/security-review`. Reutilizar su taxonomía de categorías y el archivo de **filtrado de falsos positivos** personalizable. No endurecido contra prompt injection (solo PR de confianza) | Medio–alto (Opus por defecto, timeout 20 min) |
| [anthropics/skills](https://github.com/anthropics/skills) | 196 763 | 2026-11-16 | sin SPDX | `webapp-testing` (Playwright para probar UI), `skill-creator`, `mcp-builder`. No tiene skills de auditoría de seguridad | Bajo |
| [obra/superpowers](https://github.com/obra/superpowers) | 319 374 | 2026-11-03 | MIT | Ya instalado (5.1.0). Patrones: `verification-before-completion` (evidencia antes de afirmar "listo"), `writing-skills` (TDD para skills) — clave para construir auditor-integral | Bajo |
| [supabase/agent-skills](https://github.com/supabase/agent-skills) | 3 101 | 2026-11-12 | MIT | `supabase-postgres-best-practices` (índices, RLS, rendimiento). Recomendado por el propio MCP de Supabase | Bajo |
| [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | 34 389 | 2026-11-12 | sin SPDX | `react-best-practices`, `web-design-guidelines`, `vercel-optimize`, `deploy-to-vercel` → dominios frontend/rendimiento/despliegue para stacks Next.js | Bajo–medio |
| [getsentry/skills](https://github.com/getsentry/skills) | 1 175 | 2026-11-14 | Apache-2.0 | Skills/agentes de ingeniería de Sentry (incluye `warden.toml`); revisar uno a uno antes de adoptar | NO VERIFICADO (no se revisó el contenido) |
| [wshobson/agents](https://github.com/wshobson/agents) | 42 629 | 2026-11-16 | MIT | Gran colección de subagentes (incluye roles de seguridad, BD, DevOps). Útil como **inspiración de prompts de rol**, no instalar en bloque (inflaría contexto) | Alto si se instala completo |
| [VoltAgent/awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents) | 26 636 | 2026-11-02 | MIT | Catálogo de subagentes; mismo uso que el anterior | Alto si se instala completo |
| [toshipon/claude-code-security-audit-skill](https://github.com/toshipon/claude-code-security-audit-skill) | 11 | 2026-11-03 | MIT | Ejemplo cercano a lo que se quiere: mezcla grep/regex JSON + Semgrep/CodeQL opcionales + SARIF 2.1.0 + fases LLM; cubre Next.js, Supabase, Vercel, Terraform, móvil, cumplimiento. **Reutilizar la arquitectura**, no la confianza (repo pequeño, poca adopción) | Medio |
| [golab-arch/synaptic-sentinel](https://github.com/golab-arch/synaptic-sentinel) | 6 | 2026-07-09 | Apache-2.0 | "Toolkit de seguridad agéntico para proyectos asistidos por IA"; contenido NO VERIFICADO | NO VERIFICADO |

### 4.2 Listas "awesome" (descubrimiento, no instalación)

| Repo | ★ | Último push | Licencia | Uso |
|---|---|---|---|---|
| [hesreallyhim/awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) | 58 248 | 2026-11-18 | NOASSERTION | Índice curado de comandos, hooks, skills. Consultar puntualmente |
| [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills) | 79 744 | 2026-09-18 | sin SPDX | Índice de skills |
| [travisvn/awesome-claude-skills](https://github.com/travisvn/awesome-claude-skills) | 15 856 | 2026-04-28 | sin SPDX | Índice de skills (menos activo) |
| [PatrickJS/awesome-cursorrules](https://github.com/PatrickJS/awesome-cursorrules) | 41 166 | 2026-05-30 | CC0-1.0 | Reglas por stack; útil para detectar "convenciones esperadas" |
| [arekusandr/awesome-vibe-coding-security](https://github.com/arekusandr/awesome-vibe-coding-security) | 10 | 2025-05-19 | sin SPDX | Papers/artículos sobre seguridad en vibe coding |
| [alisaeedkw/awesome-vibe-coding-security](https://github.com/alisaeedkw/awesome-vibe-coding-security) | 2 | 2026-07-09 | CC0-1.0 | Recursos para Lovable/Bolt/v0/Cursor/Replit |
| [pomerium/awesome-security-audits](https://github.com/pomerium/awesome-security-audits) | 211 | 2019-12-03 | — | Auditorías públicas (obsoleto; solo referencia) |

### 4.3 Checklists de vibe coding y de "production readiness"

| Repo | ★ | Último push | Licencia | Qué reutilizar |
|---|---|---|---|---|
| [boxed-dev/vibe-coding-security](https://github.com/boxed-dev/vibe-coding-security) | 15 | 2026-08-09 | **no declarada** | **69 chequeos en 8 categorías** (Auth 8, Secretos 7, API 10, BD 6, Frontend 8, IA/LLM 10, Agentes/supply chain 12, Despliegue 8), cada uno con paso de verificación (grep, SQL, curl). Excelente fuente de chequeos deterministas. Sin licencia → **citar y reescribir**, no copiar literal |
| [abenstirling/VibeSecurity](https://github.com/abenstirling/VibeSecurity) | 14 | 2025-09-02 | MIT | Escáner de seguridad vibe coding; contenido NO VERIFICADO |
| [buildwithdesi/vibeaudit](https://github.com/buildwithdesi/vibeaudit) | 4 | 2026-10-31 | MIT | Prácticas; NO VERIFICADO |
| [pranava0x0/vibe-coding-security](https://github.com/pranava0x0/vibe-coding-security) | 5 | 2026-11-17 | — | Seguimiento de ataques de supply chain, MCP maliciosos y prompt injection → **fuente para lista de paquetes/MCP bloqueados** |
| [mercari/production-readiness-checklist](https://github.com/mercari/production-readiness-checklist) | 950 | 2021-11-22 | MIT (corregido en verificación) | Checklist de microservicios (estable, antiguo). Base para niveles N4/N5 |
| [kgoralski/microservice-production-readiness-checklist](https://github.com/kgoralski/microservice-production-readiness-checklist) | 220 | 2024-10-23 | Apache-2.0 | Principios de despliegue seguro; licencia permite reutilizar |
| [mtdvio/going-to-production](https://github.com/mtdvio/going-to-production) | 1 457 | **2017-12-10** | — | Obsoleto (8 años sin push); usar solo como inspiración conceptual |
| [MarinJursic/production-readiness-checklist](https://github.com/MarinJursic/production-readiness-checklist) | 43 | 2026-11-04 | — | "Evidence-driven" para web apps; revisar |
| [oskar-makarov/pipeline-md](https://github.com/oskar-makarov/pipeline-md) | 14 | 2026-07-22 | — | Checklist de producción "que se enchufa al agente de IA" — concepto idéntico al buscado; NO VERIFICADO en profundidad |

### 4.4 Estándares abiertos (la base de los chequeos)

| Repo | ★ | Último push | Licencia | Uso |
|---|---|---|---|---|
| [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) | 34 103 | 2026-11-17 | CC-BY-SA-4.0 | Fuente de remediaciones: enlazar la hoja exacta por hallazgo (no cargarlas en contexto) |
| [OWASP/ASVS](https://github.com/OWASP/ASVS) | 3 800 | 2026-11-17 | CC-BY-SA-4.0 | Requisitos verificables por nivel (L1/L2/L3) → mapa natural a niveles de madurez. Versión vigente (5.0) y fecha: NO VERIFICADO en esta sesión |
| [OWASP/wstg](https://github.com/OWASP/wstg) | 10 298 | 2026-11-18 | CC-BY-SA-4.0 | Guía de pruebas web (DAST manual) |

### 4.5 Herramientas deterministas (CLI → JSON/SARIF)

| Herramienta | ★ | Último push | Licencia | Dominio | Salida | Costo tokens |
|---|---|---|---|---|---|---|
| [semgrep/semgrep](https://github.com/semgrep/semgrep) + [semgrep-rules](https://github.com/semgrep/semgrep-rules) (1 302 ★, NOASSERTION) | 17 783 | 2026-11-18 | LGPL-2.1 | SAST multilenguaje | JSON, SARIF | Bajo |
| [github/codeql](https://github.com/github/codeql) | 10 377 | 2026-11-17 | MIT (queries; CLI con licencia propia de GitHub) | SAST profundo | SARIF | Bajo (pero lento) |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | 31 145 | 2026-10-28 | MIT | Secretos | JSON, SARIF | Bajo |
| [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | 29 483 | 2026-11-16 | AGPL-3.0 | Secretos verificados | JSON | Bajo |
| [google/osv-scanner](https://github.com/google/osv-scanner) | 11 551 | 2026-11-18 | Apache-2.0 | Dependencias (CVE) | JSON, SARIF | Bajo |
| [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | 39 486 | 2026-11-17 | Apache-2.0 | Deps, contenedores, IaC, secretos | JSON, SARIF | Bajo |
| [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | 9 163 | 2026-11-17 | Apache-2.0 | IaC (Terraform, K8s, Docker, GHA) | JSON, SARIF | Bajo |
| [hadolint/hadolint](https://github.com/hadolint/hadolint) | 12 540 | 2026-10-19 | GPL-3.0 | Dockerfile | JSON, SARIF | Muy bajo |
| [sqlfluff/sqlfluff](https://github.com/sqlfluff/sqlfluff) | 10 028 | 2026-11-17 | MIT | Lint SQL | JSON | Bajo |
| [sbdchd/squawk](https://github.com/sbdchd/squawk) | 1 267 | 2026-11-18 | Apache-2.0 | Migraciones Postgres peligrosas (locks, downtime) | JSON | Muy bajo |
| [ankane/strong_migrations](https://github.com/ankane/strong_migrations) | 4 462 | 2026-11-02 | MIT | Migraciones Rails | texto | Muy bajo (condicional) |
| [GoogleChrome/lighthouse-ci](https://github.com/GoogleChrome/lighthouse-ci) | 7 154 | 2026-11-17 | Apache-2.0 | Rendimiento, a11y, SEO, buenas prácticas | JSON | Bajo (filtrar con jq) |
| [dequelabs/axe-core](https://github.com/dequelabs/axe-core) | 7 848 | 2026-11-17 | MPL-2.0 | Accesibilidad WCAG | JSON | Bajo |
| [grafana/k6](https://github.com/grafana/k6) | 32 342 | 2026-11-17 | AGPL-3.0 | Carga/saturación | JSON summary | Bajo |
| [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | 16 216 | 2026-11-16 | Apache-2.0 | DAST (baseline scan) | JSON, SARIF | Bajo–medio |
| [oxsecurity/megalinter](https://github.com/oxsecurity/megalinter) | 2 658 | 2026-11-18 | AGPL-3.0 | Agregador: [67 lenguajes según la documentación](https://megalinter.io/latest/) (la descripción del repo en GitHub dice 50: cifra inconsistente entre fuentes), flavors (incl. `security`, `javascript`, `python`), reporters SARIF/JSON | SARIF, JSON | Bajo en tokens, **alto en tiempo/imagen Docker** |
| [trunk-io/plugins](https://github.com/trunk-io/plugins) | 174 | 2026-11-04 | MIT | Definiciones de linters para Trunk Check (agregador alternativo; CLI de Trunk es producto comercial con capa gratuita — NO VERIFICADO términos actuales) | SARIF/JSON (NO VERIFICADO) | Bajo |

**Licencias AGPL (trufflehog, k6, MegaLinter):** ejecutarlas localmente como herramientas externas no obliga a licenciar el auditor como AGPL; sí lo haría modificarlas y ofrecerlas como servicio. ESTIMACIÓN; no es asesoría legal. Recomendación: invocarlas como binarios externos opcionales, nunca embebidas.

---

## 5. Stack mínimo de reutilización recomendado (GUÍA)

Criterio: máxima cobertura por dominio con mínima carga de contexto. El investigador decide la adopción final.

| Capa | Componente | Ya instalado | Acción |
|---|---|---|---|
| Orquestación | Skill nueva `auditor-integral` (fases + puntuación N1–N5) | No | **Construir** (único componente nuevo grande) |
| Normalización | `static-analysis:sarif-parsing` + script propio `normalize.py` (SARIF/JSON → tabla única deduplicada por regla/archivo/severidad) | Parcial | Construir script |
| Código/SAST | `semgrep` (reglas `p/owasp-top-ten`, `p/secrets`, más reglas propias vibe coding vía `semgrep-rule-creator`) | Sí (skill) | Instalar CLI + `semgrep-rule-creator` |
| Secretos | `gitleaks` (+ `secret-serialization` para fugas por serialización) | Skill sí, CLI no | Instalar CLI |
| Dependencias | `osv-scanner` + `supply-chain-risk-auditor` | Skill sí | Instalar CLI |
| Config insegura | `insecure-defaults`, `sharp-edges` | Sí | Reutilizar |
| IaC / contenedores | `trivy config` + `checkov` + `hadolint` | No | Instalar condicional (solo si hay Dockerfile/Terraform) |
| CI/CD | `gha-security-review` (+ `agentic-actions-auditor` si hay agentes IA en Actions) | Sí / No | Reutilizar / añadir |
| BD | `squawk` (migraciones Postgres) + `sqlfluff` + Supabase `get_advisors` + `supabase-postgres-best-practices` | Supabase sí | Instalar CLIs condicionales |
| Frontend / UX / a11y | `lighthouse-ci` + `axe-core` (vía Playwright/`webapp-testing`) + `design:accessibility-review` | design sí | Instalar CLIs |
| Carga / saturación | `k6` con script plantilla (smoke + ramp) | No | Instalar + plantilla |
| DAST | ZAP baseline scan (solo con entorno local/staging) | No | Opcional N3+ |
| Juicio de seguridad | `security-audit` o `claude-security` (oficial) + `fp-check` solo para crítico/alto | security-audit sí | Elegir uno (evitar duplicar) |
| Revisión incremental | `differential-review` / `security-guidance` (hooks) | diff sí | Opcional para modo continuo |
| Despliegue / readiness | `engineering:deploy-checklist` + checklist propio derivado de mercari/kgoralski + 69 ítems de boxed-dev (reescritos) | Sí | Construir checklist YAML |
| Mapa de arquitectura | `graphify` (grafo) en lugar de leer todo el código | Sí | Reutilizar |
| Proceso | `superpowers:verification-before-completion`, `writing-skills` | Sí | Usar para construir el auditor |

**Qué NO instalar:** colecciones completas de subagentes (`wshobson/agents`, `VoltAgent/...`) ni listas awesome: inflan el contexto y duplican roles. Tomar prompts puntuales.

---

## 6. Patrón de eficiencia de tokens (diseño)

1. **Detección de stack (determinista):** leer `package.json`, `requirements.txt`, `Dockerfile`, `supabase/`, `.github/workflows/`, `vercel.json` → decide qué herramientas condicionales correr. Costo LLM ≈ 0.
2. **Ejecución de herramientas:** cada una escribe `out/<tool>.sarif|json`.
3. **Normalización (script):** unifica a `{dominio, severidad, regla, archivo, línea, cwe, fuente}`; deduplica; cuenta por dominio/severidad; asigna puntaje por umbrales fijos (no por LLM).
4. **LLM recibe solo:** conteos agregados + top-N (p. ej. 20) crítico/alto con 5 líneas de contexto cada uno. ESTIMACIÓN: reduce órdenes de magnitud frente a leer el repo completo (NO VERIFICADO cuantitativamente; medir en el piloto).
5. **Juicio LLM dirigido:** solo para lo no detectable por herramientas: control de acceso/IDOR, lógica de negocio, coherencia flujograma ↔ código (`spec-to-code-compliance`), UX, arquitectura de escalabilidad.
6. **fp-check selectivo:** solo crítico/alto antes de reportar.
7. **Re-auditoría:** `differential-review` sobre el diff desde la última auditoría, no auditoría completa.

---

## 7. Fallos típicos de vibe coding cubiertos por este ecosistema (síntesis)

Detallados en el resumen estructurado. Fuentes principales: checklist de [boxed-dev](https://github.com/boxed-dev/vibe-coding-security), [Veracode 2025](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/), [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/), [README de security-review](https://github.com/anthropics/claude-code-security-review).

## 8. Limitaciones

- Estrellas cambian a diario; valores al 2026-11-17.
- No se leyó el contenido completo de: getsentry/skills, synaptic-sentinel, VibeSecurity, vibeaudit, pipeline-md, MarinJursic → marcados NO VERIFICADO.
- Cifras de Veracode 2026 provienen de resumen de buscador, no del informe original.
- Costos en tokens son estimaciones cualitativas; deben medirse en el piloto (auditar un proyecto real).

## Verificación

Verificador escéptico, 2026-11-17. Método: `gh api repos/OWNER/REPO` para los 49 repos de GitHub citados en el informe; WebFetch para las cifras clave.

### A. Repos (existencia, estado de archivado, estrellas, licencia)

| Resultado | Detalle |
|---|---|
| Existencia | **Los 49 repos citados existen.** Ninguno está archivado. No hay repos inventados. |
| Estrellas | Coinciden con lo que devuelve `gh` (diferencias de 1 a 5 estrellas por variación diaria: obra/superpowers 319 379; anthropics/skills 196 768; semgrep 17 784; ComposioHQ/awesome-claude-skills 79 745). |
| Fechas de push | Coinciden. Algunas fechas son 2026-11-18 en UTC (un día después de la fecha local del informe), lo que es coherente. |
| **ERROR corregido** | `mercari/production-readiness-checklist`: el informe y el JSON decían licencia "no declarada" o "—". **GitHub declara MIT.** Ya está corregido en la tabla. Por eso puede reutilizarse con atribución. |
| Licencias sin SPDX | anthropics/skills, vercel-labs/agent-skills, ComposioHQ/awesome-claude-skills, boxed-dev, mtdvio, pranava0x0, travisvn y arekusandr: `license = null` a nivel de repo (anthropics/skills puede declarar licencias por skill; NO VERIFICADO). Hay que tratarlos como "sin licencia reutilizable" mientras no se revise. |
| Repos sin mantenimiento | mercari (último push 2021-11), mtdvio (2017-12) y anthropics/claude-code-security-review (2026-02, unos 9 meses sin push). Este último no está obsoleto, pero conviene vigilarlo. |
| Señal baja | boxed-dev (15 ★), toshipon (11 ★), pranava0x0 (5 ★), vibeaudit (4 ★), alisaeedkw (2 ★): su valor está en el contenido, no en la adopción. Usarlos como fuente de ideas, no como dependencia. |

### B. Cifras y afirmaciones clave

| # | Afirmación | Fuente comprobada | Resultado |
|---|---|---|---|
| 1 | Veracode 2025: 45 % de 80 tareas con vulnerabilidad, >100 LLM, XSS 86 %, log injection 88 % | [Nota de prensa Veracode, 30-07-2025](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/) | **VERIFICADO** (todas las cifras coinciden) |
| 2 | OWASP Top 10:2025: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions | [top10.owasp.org/2025](https://top10.owasp.org/2025/0x00_2025-Introduction) (la URL owasp.org/Top10 redirige con 308) | **VERIFICADO** |
| 3 | trailofbits/skills tiene 47 plugins; existen semgrep-rule-creator, agentic-actions-auditor, spec-to-code-compliance, mutation-testing, cvss-scoring, trailmark, firebase-apk-scanner | `gh api repos/trailofbits/skills/contents/plugins` → 47 directorios | **VERIFICADO** |
| 4 | boxed-dev: 69 chequeos en 8 categorías | README del repo ("69 checks", 8 categorías nombradas) | **VERIFICADO** (el desglose por categoría 8/7/10/6/8/10/12/8 suma 69, pero no se contó ítem por ítem) |
| 5 | El security-review oficial excluye DoS y rate limiting | README de anthropics/claude-code-security-review (lista de exclusiones: "Denial of Service", "Rate limiting concerns") | **VERIFICADO** |
| 6 | MegaLinter "67 lenguajes" | megalinter.io dice 67; la descripción del repo dice 50 | **INCONSISTENTE**: se reporta como "50-67 según la fuente" |
| 7 | Veracode 2026 (56 %, Java 30 %, Python 63 %) | Solo resumen de SD Times | **NO VERIFICADO** (no se revisó en esta pasada) |
| 8 | Versión vigente de OWASP ASVS (5.0) | La release de GitHub tiene la etiqueta "latest" sin número | **NO VERIFICADO** |
| 9 | "8 plugins de ToB ya instalados" | Configuración local | **NO VERIFICADO** de forma independiente (en la lista de skills de la sesión aparecen static-analysis, insecure-defaults, sharp-edges, supply-chain-risk-auditor, differential-review, fp-check, audit-context-building y variant-analysis: son 8, así que es plausible) |
| 10 | Cifras de Escape.tech y GitGuardian citadas dentro del README de boxed-dev | De segunda mano | **NO VERIFICADO**: no usarlas sin ir a la fuente primaria |

### C. Conclusión del verificador

No se encontraron repos inexistentes ni archivados. Hubo un error factual (la licencia de mercari) y una cifra inconsistente (MegaLinter); ambos están corregidos arriba. Las cifras cuantitativas principales (Veracode 2025, OWASP 2025, ToB 47, boxed-dev 69 y las exclusiones de security-review) están verificadas contra la fuente. Quedan como NO VERIFICADO: Veracode 2026, la versión de ASVS y las cifras de segunda mano.
