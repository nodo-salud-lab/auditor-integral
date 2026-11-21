# 02 — Ciberseguridad de aplicaciones web, API y LLM

**Proyecto:** auditor-integral · **Dominio:** seguridad de aplicaciones (AppSec, API, LLM, cadena de suministro)
**Fecha de corte:** 2026-11-17 · **Sello:** SÍNTESIS (evidencia integrada) + GUÍA (orientación procedimental)

> Regla aplicada: cada cifra lleva URL. Lo que no se pudo contrastar con fuente primaria está marcado **NO VERIFICADO**. Las estrellas, licencias y fechas de último push de GitHub se obtuvieron con `gh api repos/OWNER/REPO` el 2026-11-17 y cambian con el tiempo.

---

## 1. Resumen ejecutivo

1. **La IA no escribe código seguro por defecto.** En el informe GenAI Code Security de Veracode (julio 2025), el código generado introdujo vulnerabilidades en el 45 % de 80 tareas probadas con más de 100 LLM; XSS y log injection fallaron en el 86 % y 88 % de los casos relevantes, y la seguridad no mejoró a medida que mejoraba la sintaxis ([Veracode](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/), [Help Net Security](https://www.helpnetsecurity.com/2025/08/07/create-ai-code-security-risks/)). Ojo: es un benchmark de tareas, no una prevalencia en código de producción.
2. **Las apps "vibe-coded" en producción filtran datos de forma masiva y trivial.** Escape.tech analizó más de 5.600 apps públicas hechas con plataformas de vibe coding y halló más de 2.000 vulnerabilidades, más de 400 secretos expuestos y 175 casos de PII ([Escape](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/)).
3. **El patrón de fallo dominante es de autorización, no de criptografía exótica.** OWASP Top 10:2025 mantiene *Broken Access Control* en A01 ([OWASP](https://top10.owasp.org/2025)); en CWE Top 25 2025, *Missing Authorization* (CWE-862) sube al #4 y aparecen CWE-863, CWE-284, CWE-306 y CWE-639 ([MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)). El caso emblemático es CVE-2025-48757 (Lovable + Supabase sin RLS efectiva): ~170 de 1.645 apps escaneadas con tablas legibles o escribibles ([resumen](https://www.superblocks.com/blog/lovable-vulnerabilities); [PT Security](https://dbugs.ptsecurity.com/vulnerability/PT-2025-23236)).
4. **La cadena de suministro es ahora categoría propia (A03:2025)** y la IA agrava el problema por dos vías: paquetes alucinados (19,7 % de los paquetes recomendados no existían en el estudio de Spracklen et al., 16 modelos, 576.000 muestras; [CSO](https://www.csoonline.com/article/3961304/ai-hallucinations-lead-to-new-cyber-threat-slopsquatting.html), [Kaspersky](https://www.kaspersky.com/blog/ai-slopsquatting-supply-chain-risk/53327/)) y la adopción de dependencias o acciones de CI sin fijar. Incidentes reales recientes: gusano Shai-Hulud en npm (más de 500 paquetes, alerta CISA del 23-09-2025; [CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)) y la reescritura de tags de `aquasecurity/trivy-action` en marzo de 2026 ([Aqua](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)). Que un escáner de seguridad haya sido el vector es una advertencia directa para el diseño del propio auditor.
5. **Los secretos son el hallazgo más barato de detectar y más caro de ignorar.** GitGuardian 2025: los repos públicos con Copilot activo tuvieron una tasa de fuga del 6,4 %, un 40 % más que el promedio ([GitGuardian](https://www.gitguardian.com/state-of-secrets-sprawl-report-2025)); el informe 2026 reporta 1,27 millones de secretos de servicios de IA filtrados en 2025 (+81 % interanual) ([Cybersecurity Dive](https://www.cybersecuritydive.com/press-release/20260317-ai-is-fueling-secrets-sprawl-gitguardian-reports-an-81-surge-of-ai-servic/)).
6. **Implicación de diseño para auditor-integral:** cerca del 70–80 % de los chequeos de este dominio se resuelven con herramientas deterministas que emiten SARIF/JSON y no necesitan cuenta (gitleaks, opengrep/semgrep, osv-scanner, trivy, bandit, checkov, zizmor, hadolint, syft/grype). *(La proporción es una ESTIMACIÓN del autor sobre la lista de chequeos de la sección 6, no una cifra publicada.)* El LLM queda reservado para lo que ninguna herramienta resuelve: **autorización por objeto (BOLA/IDOR), lógica de negocio, flujos de auth, modelado de amenazas y triage de falsos positivos**.

---

## 2. Estándares de referencia vigentes (a noviembre de 2026)

| Estándar | Versión vigente | Qué aporta al auditor | Fuente |
|---|---|---|---|
| OWASP Top 10 | **2025** | Taxonomía de riesgos para el informe final y el mapeo de hallazgos | [top10.owasp.org/2025](https://top10.owasp.org/2025) |
| OWASP ASVS | **5.0.0** (mayo 2025), 17 capítulos V1–V17, 3 niveles | Lista de requisitos verificables; base de los gates N2–N5 | [GitHub OWASP/ASVS](https://github.com/OWASP/ASVS) · [Intertek](https://assuranceinaction.intertek.com/post/102kghm/owasp-release-version-5-0-of-the-application-security-verification-standard-asvs) |
| OWASP API Security Top 10 | **2023** (sin edición posterior encontrada) | Riesgos específicos de APIs (BOLA, BOPLA, consumo de recursos) | [owasp.org API Security](https://owasp.org/projects/api-security-project) |
| OWASP Top 10 LLM | **2026** (agosto 2026); la 2025 sigue siendo muy citada | Riesgos de apps que integran LLM | [genai.owasp.org anuncio](https://genai.owasp.org/announcement/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/) · [Invicti](https://www.invicti.com/blog/web-security/owasp-llm-top-10-2026-whats-new) |
| OWASP Top 10 Agentic Applications | **2026** (publicado 9-12-2025) | Riesgos de agentes con herramientas, memoria y autoridad delegada | [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) |
| CWE Top 25 | **2025** (diciembre 2025; 39.080 CVE de jun-2024 a jun-2025: cifra tomada de BleepingComputer, **NO VERIFICADO** en la página de MITRE) | Identificadores CWE para clasificar hallazgos SARIF | [MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) · [BleepingComputer](https://www.bleepingcomputer.com/news/security/mitre-shares-2025s-top-25-most-dangerous-software-weaknesses/) |
| SLSA | v1.x | Niveles de integridad de build y procedencia | [slsa.dev](https://slsa.dev) |
| OpenSSF Scorecard | herramienta viva | Puntaje 0–10 de prácticas de seguridad de un repo y sus dependencias | [github.com/ossf/scorecard](https://github.com/ossf/scorecard) |
| SBOM (CycloneDX / SPDX) | CycloneDX 1.6 / SPDX 2.3–3.0 (**NO VERIFICADO** número exacto de versión vigente) | Inventario de componentes para cruzar con OSV | [cyclonedx.org](https://cyclonedx.org) · [spdx.dev](https://spdx.dev) |
| SARIF | 2.1.0 (OASIS) | Formato común de salida; permite que el LLM lea un resumen y no el código | [OASIS SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |

### 2.1 OWASP Top 10:2025
A01 Broken Access Control · A02 Security Misconfiguration · **A03 Software Supply Chain Failures** (nueva) · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures · **A10 Mishandling of Exceptional Conditions** (nueva) ([OWASP](https://top10.owasp.org/2025)).

Lectura para vibe coding: A02 (configuración por defecto insegura: CORS `*`, debug, buckets públicos), A03 (dependencias no revisadas que el asistente añade) y A10 (errores que filtran stack traces o fallan "abiertos") son exactamente los defectos que un generador de código no detecta porque el código "funciona".

### 2.2 OWASP ASVS 5.0
17 capítulos (V1 Encoding and Sanitization … V17 WebRTC); nuevos capítulos V9 *Self-contained Tokens* (JWT) y V10 *OAuth and OIDC*. Alrededor de 345–350 requisitos; una fuente secundaria da 70 L1 / 183 L2 / 92 L3 (**NO VERIFICADO** contra el CSV oficial) ([arc42](https://quality.arc42.org/standards/owasp-asvs), [OWASP leaders list](https://groups.google.com/a/owasp.org/g/leaders/c/Cj4Y6W1aZHg)).
**Uso propuesto:** mapear gates de madurez a niveles ASVS: N2 (MVP) ≈ subconjunto L1 crítico; N4 (producción) ≈ L1 completo + L2 de auth, sesión, control de acceso y API; N5 (escala) ≈ L2 completo y L3 selectivo si hay datos sensibles (p. ej., datos clínicos bajo Ley 19.628 o Ley 20.584 en Chile). Este mapeo es una propuesta del auditor (**ESTIMACIÓN**), no algo que defina OWASP.

### 2.3 OWASP API Security Top 10 (2023)
API1 BOLA · API2 Broken Authentication · API3 Broken Object Property Level Authorization · API4 Unrestricted Resource Consumption · API5 Broken Function Level Authorization · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs ([OWASP API](https://owasp.org/projects/api-security-project)).
API1, API3, API5 y API6 **no se detectan bien con SAST genérico**: requieren entender quién es dueño de qué objeto. Aquí el LLM (con contexto acotado a rutas y modelos) aporta valor real.

### 2.4 OWASP Top 10 LLM
- **2025:** LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data and Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector and Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption ([HackerOne](https://www.hackerone.com/ai/owasp-top-10-llms-2025), [Invicti](https://www.invicti.com/blog/web-security/owasp-top-10-risks-llm-security-2025)).
- **2026** (según Invicti, a contrastar con el PDF oficial): LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · **LLM03 Excessive Agency** (sube desde #6) · LLM04 Supply Chain · LLM05 Data and Model Poisoning · **LLM06 Unbounded Consumption** (sube desde #10, ahora enfocado en el costo) · LLM07 Misinformation · **LLM08 Hidden Context Exposure** (antes System Prompt Leakage) · LLM09 Vector and Embedding Weaknesses · LLM10 Improper Output Handling ([Invicti 2026](https://www.invicti.com/blog/web-security/owasp-llm-top-10-2026-whats-new)). Estado: **verificado solo contra una fuente secundaria**; el auditor debe referenciar el PDF oficial en [genai.owasp.org](https://genai.owasp.org/).
- Lectura práctica: para una app vibe-coded que llama a la API de un LLM, los riesgos más probables son **clave de API del LLM expuesta en el frontend**, **consumo sin límite (factura)**, **salida del LLM insertada en HTML/SQL/shell sin sanitizar** y **agencia excesiva** (herramientas con permisos de escritura sin confirmación humana).

### 2.5 CWE Top 25 2025 (completo)
1 CWE-79 XSS · 2 CWE-89 SQLi · 3 CWE-352 CSRF · 4 CWE-862 Missing Authorization · 5 CWE-787 OOB Write · 6 CWE-22 Path Traversal · 7 CWE-416 Use After Free · 8 CWE-125 OOB Read · 9 CWE-78 OS Command Injection · 10 CWE-94 Code Injection · 11 CWE-120 · 12 CWE-434 Unrestricted Upload · 13 CWE-476 · 14 CWE-121 · 15 CWE-502 Deserialization · 16 CWE-122 · 17 CWE-863 Incorrect Authorization · 18 CWE-20 Input Validation · 19 CWE-284 Improper Access Control · 20 CWE-200 Info Exposure · 21 CWE-306 Missing Authentication · 22 CWE-918 SSRF · 23 CWE-77 Command Injection · 24 CWE-639 Authz Bypass via User-Controlled Key (IDOR) · 25 CWE-770 Resources Without Limits ([MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)).
Para apps web en JS/TS/Python (el stack típico del vibe coding), los relevantes son **79, 89, 352, 862, 22, 78, 94, 434, 502, 863, 20, 284, 200, 306, 918, 77, 639 y 770**. Los de memoria (787, 416, 125, 120–122, 476) solo aplican si hay C/C++/Rust `unsafe`.

---

## 3. Qué falla más cuando el código lo escribe una IA (top de fallos)

| # | Fallo | Severidad | Por qué ocurre con IA/vibe coding | Detección | Evidencia |
|---|---|---|---|---|---|
| F1 | **Secretos en el repo o en el bundle del frontend** (`service_role` de Supabase, `sk-…` de OpenAI/Anthropic, Stripe secret, `.env` commiteado) | Crítica | El asistente "hace que funcione" llamando a la API desde el cliente; el usuario no distingue clave pública de privada | Determinista: gitleaks/trufflehog sobre el historial git + grep del `dist/` construido | [Escape](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/), [GitGuardian 2025](https://www.gitguardian.com/state-of-secrets-sprawl-report-2025) |
| F2 | **BaaS sin autorización en BD**: Supabase con RLS desactivada o `USING (true)`; reglas Firebase `allow read, write: if true` | Crítica | El frontend habla directo con la BD; el generador crea tablas sin políticas o con políticas permisivas para "destrabar" errores | Mixto: consulta SQL a `pg_tables`/`pg_policies` (determinista) + revisión LLM de la semántica de cada política | [CVE-2025-48757](https://dbugs.ptsecurity.com/vulnerability/PT-2025-23236), [Superblocks](https://www.superblocks.com/blog/lovable-vulnerabilities) |
| F3 | **BOLA/IDOR**: `GET /api/orders/:id` sin verificar que el pedido pertenece al usuario | Crítica | La IA implementa el *happy path*; la verificación de propiedad no aparece en el prompt | LLM sobre el inventario de rutas + prueba dinámica con dos usuarios (determinista si hay seed de test) | CWE-862 #4, CWE-639 #24 ([MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)); API1 ([OWASP](https://owasp.org/projects/api-security-project)) |
| F4 | **Autenticación o autorización solo en el cliente o solo en middleware** (rutas protegidas por un `if (user)` en React; confiar en un middleware omitible) | Crítica | La IA protege la UI, no el endpoint. Ejemplo real: CVE-2025-29927, bypass del middleware de Next.js con la cabecera `x-middleware-subrequest` | Mixto: semgrep con reglas de endpoints sin guardia + LLM; osv-scanner para la versión de Next.js | [NVD CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) |
| F5 | **Inyección SQL / NoSQL / comandos** por concatenación de strings, `raw()`, `$where`, `exec()` | Alta | Plantillas de ejemplo con f-strings o template literals | Determinista: semgrep/opengrep, bandit (Python) | CWE-89 #2, CWE-78 #9 ([MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)) |
| F6 | **XSS**: `dangerouslySetInnerHTML`, `v-html`, `innerHTML` con datos de usuario o salida de un LLM; Markdown renderizado sin sanitizar | Alta | El 86 % de fallo en XSS del benchmark Veracode | Determinista: semgrep + cabecera CSP con ZAP | [Veracode](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/) |
| F7 | **Dependencias alucinadas, typosquatting o vulnerables**; lockfile ausente o no comprometido | Alta | El LLM inventa nombres plausibles (19,7 %) o fija versiones viejas de su corpus de entrenamiento | Determinista: osv-scanner/trivy; verificación de existencia y antigüedad del paquete en el registro; lockfile-lint | [CSO](https://www.csoonline.com/article/3961304/ai-hallucinations-lead-to-new-cyber-threat-slopsquatting.html), [CISA Shai-Hulud](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) |
| F8 | **Sin rate limiting ni límites de recursos** (login sin bloqueo, endpoints LLM sin cuota, uploads sin tamaño máximo) | Alta | No forma parte del requisito funcional; tiene impacto económico directo cuando hay un LLM detrás | LLM + grep de middleware de rate limit; prueba dinámica con ráfaga controlada | CWE-770 #25; API4; LLM10:2025/LLM06:2026 ([Invicti](https://www.invicti.com/blog/web-security/owasp-llm-top-10-2026-whats-new)) |
| F9 | **Prompt injection con agencia excesiva**: el LLM lee contenido externo (web, PDF, email) y puede invocar herramientas con escritura; salida del LLM pasada a `eval`, SQL o HTML | Alta | Patrón "agente que hace todo" copiado de tutoriales | LLM (modelado de amenazas del flujo de datos) + red teaming con promptfoo/garak en N4+ | OWASP LLM01/LLM06 ([HackerOne](https://www.hackerone.com/ai/owasp-top-10-llms-2025)) |
| F10 | **SSRF**: endpoint que hace `fetch(url)` con URL del usuario ("previsualizar enlace", "importar desde URL") sin lista permitida; acceso a `169.254.169.254` | Alta | Funcionalidad frecuente en apps con IA (resumir una URL) | Semgrep (taint) + LLM; nuclei en dinámico | CWE-918 #22; API7 |
| F11 | **JWT/sesión mal implementados**: secreto hardcodeado o débil, `jwt.decode` sin verificar, sin `exp`, token en `localStorage`, cookies sin `HttpOnly/Secure/SameSite` | Alta | La IA genera auth "a mano" en vez de usar el proveedor | Semgrep (reglas jwt) + gitleaks + inspección de `Set-Cookie` con ZAP | ASVS V9 y V7 ([OWASP ASVS](https://github.com/OWASP/ASVS)) |
| F12 | **Configuración insegura**: CORS `*` con credenciales, `DEBUG=True`, cabeceras ausentes (CSP, HSTS, X-Content-Type-Options, frame-ancestors), buckets públicos, Dockerfile como root | Media | Valores por defecto de los ejemplos | Determinista: ZAP baseline, nuclei, checkov, trivy config, hadolint | A02:2025 ([OWASP](https://top10.owasp.org/2025)) |
| F13 | **Manejo de errores que filtra información o falla "abierto"** (stack trace al cliente; `catch` que devuelve `true`) | Media | El asistente añade `try/catch` genéricos para silenciar errores | Semgrep + ZAP (respuestas 500 con trazas) + LLM | A10:2025 ([OWASP](https://top10.owasp.org/2025)) |
| F14 | **Uploads sin validación** (tipo, tamaño, ruta; path traversal) | Alta | Ejemplo mínimo de multer/FastAPI sin restricciones | Semgrep + LLM | CWE-434 #12, CWE-22 #6 |
| F15 | **CSRF** en apps con cookies de sesión sin `SameSite` ni token | Media | Los frameworks SPA lo hacen invisible | ZAP baseline + LLM | CWE-352 #3 |
| F16 | **CI/CD inseguro**: acciones fijadas a tags mutables, `pull_request_target` con checkout del PR, secretos en logs, permisos `write-all` | Alta | Workflows copiados sin revisar | Determinista: zizmor, poutine, actionlint, Scorecard (Pinned-Dependencies, Token-Permissions) | [Aqua, trivy-action](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/) |
| F17 | **Logging ausente o con PII/secretos** | Media | Nadie lo pidió en el prompt | LLM + semgrep (logs con `password`, `token`) | A09:2025; log injection con 88 % de fallo en Veracode |

---

## 4. Herramientas deterministas (catálogo verificado)

Leyenda de la columna "Sin cuenta/servidor": **Sí** = corre local y offline o solo descarga una BD pública. **Red** = necesita Internet hacia una API pública, sin cuenta. **Target** = necesita la app desplegada o corriendo localmente. **Token** = necesita un token (p. ej., de GitHub).

| Herramienta | Repo · ★ · licencia · último push | Qué audita | Sin cuenta/servidor | Salida | Comando base (GUÍA) | Costo en tokens |
|---|---|---|---|---|---|---|
| **Opengrep** | [opengrep/opengrep](https://github.com/opengrep/opengrep) · 3.350 · LGPL-2.1 · 2026-11-17 | SAST multilenguaje (fork LGPL de Semgrep CE) | Sí (reglas locales) | SARIF, JSON | `opengrep scan --config reglas/ --sarif -o sast.sarif` | Bajo |
| **Semgrep CE** | [semgrep/semgrep](https://github.com/semgrep/semgrep) · 17.783 · LGPL-2.1 · 2026-11-18 | SAST; packs `p/owasp-top-ten`, `p/secrets`, `p/jwt` | Red (descarga packs del registry); sin login. Las reglas del registry usan la *Semgrep Rules License* (no OSI) desde dic-2024 ([Semgrep FAQ](https://semgrep.dev/docs/faq/comparisons/opengrep)) | SARIF, JSON | `semgrep scan --config p/owasp-top-ten --sarif` | Bajo |
| **Gitleaks** | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) · 31.145 · MIT · 2026-10-28 | Secretos en historial git y directorios | Sí | SARIF, JSON, CSV | `gitleaks git . --report-format sarif -r secrets.sarif` | Bajo |
| **TruffleHog** | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) · 29.483 · **AGPL-3.0** · 2026-11-16 | Secretos con **verificación activa** contra el proveedor | Sí con `--no-verification`; Red si verifica | JSON (SARIF nativo **NO VERIFICADO**) | `trufflehog git file://. --json --results=verified,unknown` | Bajo |
| **OSV-Scanner** | [google/osv-scanner](https://github.com/google/osv-scanner) · 11.551 · Apache-2.0 · 2026-11-18 | Vulnerabilidades conocidas en lockfiles y SBOM | Red (API osv.dev) o modo offline con BD descargada | SARIF, JSON, Markdown | `osv-scanner scan source -r . --format sarif` | Bajo |
| **Trivy** | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) · 39.486 · Apache-2.0 · 2026-11-17 | Vulnerabilidades, secretos, misconfig (IaC, Dockerfile, K8s), licencias, SBOM | Sí (descarga BD pública) | SARIF, JSON, CycloneDX, SPDX | `trivy fs --scanners vuln,secret,misconfig -f sarif .` | Bajo |
| **npm audit / pnpm audit** | integrado en npm | Advisories de dependencias JS | Red (registry) | JSON | `npm audit --json --omit=dev` | Bajo |
| **pip-audit** | [pypa/pip-audit](https://github.com/pypa/pip-audit) · 1.407 · Apache-2.0 · 2026-11-11 | Advisories de dependencias Python | Red | JSON, CycloneDX | `pip-audit -f json` | Bajo |
| **Bandit** | [PyCQA/bandit](https://github.com/PyCQA/bandit) · 8.392 · Apache-2.0 · 2026-11-09 | SAST Python | Sí | JSON, SARIF (extra `bandit[sarif]`) | `bandit -r . -f sarif -o bandit.sarif` | Bajo |
| **Checkov** | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) · 9.163 · Apache-2.0 · 2026-11-17 | IaC: Terraform, Dockerfile, K8s, GitHub Actions, secretos | Sí (API key de Prisma opcional) | SARIF, JSON, JUnit | `checkov -d . -o sarif --output-file-path .` | Bajo |
| **KICS** | [Checkmarx/kics](https://github.com/Checkmarx/kics) · 2.746 · Apache-2.0 · 2026-11-17 | IaC (alternativa a checkov) | Sí | SARIF, JSON | `kics scan -p . --report-formats sarif,json` | Bajo |
| **Hadolint** | [hadolint/hadolint](https://github.com/hadolint/hadolint) · 12.540 · GPL-3.0 · 2026-10-19 | Buenas prácticas de Dockerfile | Sí | SARIF, JSON | `hadolint -f sarif Dockerfile` | Bajo |
| **zizmor** | [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) · 7.077 · MIT · 2026-11-18 | Seguridad de GitHub Actions (pinning, injection, permisos) | Sí (`--offline`) | SARIF, JSON | `zizmor --format sarif .github/workflows` | Bajo |
| **poutine** | [boostsecurityio/poutine](https://github.com/boostsecurityio/poutine) · 537 · Apache-2.0 · 2026-11-16 | Pipelines CI/CD (GitHub/GitLab) | Sí (repo local) | SARIF, JSON | `poutine analyze_local . --format sarif` | Bajo |
| **actionlint** | [rhysd/actionlint](https://github.com/rhysd/actionlint) · 4.419 · MIT · 2026-07-16 | Lint de workflows | Sí | JSON (plantilla) | `actionlint -format '{{json .}}'` | Bajo |
| **Syft** | [anchore/syft](https://github.com/anchore/syft) · 9.918 · Apache-2.0 · 2026-11-16 | Generación de SBOM | Sí | CycloneDX, SPDX, JSON | `syft dir:. -o cyclonedx-json=sbom.json` | Bajo |
| **Grype** | [anchore/grype](https://github.com/anchore/grype) · 13.283 · Apache-2.0 · 2026-11-17 | Vulnerabilidades sobre SBOM o imagen | Sí (descarga BD) | SARIF, JSON | `grype sbom:sbom.json -o sarif` | Bajo |
| **cdxgen** | [cdxgen/cdxgen](https://github.com/cdxgen/cdxgen) · 1.121 · Apache-2.0 · 2026-11-18 | SBOM CycloneDX multilenguaje | Sí | CycloneDX JSON | `cdxgen -o bom.json` | Bajo |
| **OpenSSF Scorecard** | [ossf/scorecard](https://github.com/ossf/scorecard) · 5.845 · Apache-2.0 · 2026-11-16 | Higiene del repo y de dependencias (0–10) | **Token** de GitHub; el repo debe estar en GitHub | JSON, SARIF | `scorecard --repo=github.com/o/r --format json` | Bajo |
| **lockfile-lint** | [lirantal/lockfile-lint](https://github.com/lirantal/lockfile-lint) · 871 · Apache-2.0 · 2026-11-04 | Lockfile con hosts y protocolos permitidos (anti-inyección de registry) | Sí | texto / código de salida | `npx lockfile-lint --path package-lock.json --allowed-hosts npm --validate-https` | Bajo |
| **OWASP ZAP baseline** | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) · 16.216 · Apache-2.0 · 2026-11-16 | DAST pasivo: cabeceras, cookies, CSP, info leaks | **Target** (app corriendo, puede ser localhost); Docker | JSON, XML, HTML, Markdown (SARIF nativo **NO VERIFICADO**) | `docker run -t zaproxy/zap-stable zap-baseline.py -t http://host -J zap.json` | Bajo |
| **Nuclei** | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) · 33.059 · MIT · 2026-11-17; plantillas [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) · 13.358 · MIT | DAST por plantillas: misconfig, exposiciones, CVE, cabeceras | **Target**; sin cuenta | JSONL, SARIF (`-se`) | `nuclei -u http://host -tags misconfig,exposure -jsonl -o nuclei.jsonl` | Bajo |
| **promptfoo** | [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) · 27.394 · MIT · 2026-11-18 | Red teaming de apps LLM (inyección, jailbreak, fuga) | Necesita endpoint del LLM y **API key** (costo en tokens del modelo bajo prueba) | JSON, HTML | `promptfoo redteam run` | Alto |
| **garak** | [NVIDIA/garak](https://github.com/NVIDIA/garak) · 10.067 · Apache-2.0 · 2026-11-06 | Escáner de vulnerabilidades de LLM | Necesita endpoint del modelo | JSONL | `garak --model_type rest ...` | Alto |

**Descartados o con advertencia:**
- `mozilla/http-observatory` está **archivado** (último push 2024-10-22); usar ZAP o nuclei para las cabeceras.
- `praetorian-inc/noseyparker` y `protectai/llm-guard` están **archivados** según `gh api` (2026-11-17).
- `Yelp/detect-secrets` (4.681 ★, último push 2026-04-02) sigue siendo útil como *baseline* en pre-commit, pero gitleaks cubre el caso principal.
- **Advertencia de cadena de suministro del propio auditor:** entre el 19 y el 20 de marzo de 2026 se reescribieron por force-push 76 de los 77 tags de versión de `aquasecurity/trivy-action` (la propia página de Aqua también menciona "75"); Aqua cita el aviso GHSA-cxm3-wv7p-598c (el identificador CVE-2026-33634 queda **NO VERIFICADO**: no aparece en la página de Aqua) ([Aqua](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/), [Snyk](https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/)). El auditor debe **instalar los binarios con checksum o firma verificada (cosign)** y fijar a SHA cualquier acción de CI que proponga.

### 4.1 Skills y agentes de revisión existentes (para no reinventar)
| Recurso | ★ · licencia · último push | Uso en auditor-integral |
|---|---|---|
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | 6.982 · MIT · 2026-02-11 | Referencia de prompt y flujo para la revisión LLM de diffs; filtrado de falsos positivos |
| [trailofbits/skills](https://github.com/trailofbits/skills) | 8.259 · CC-BY-SA-4.0 · 2026-11-12 | Skills de Claude Code (semgrep, sarif-parsing, insecure-defaults, supply-chain-risk-auditor, fp-check). **Varias ya están instaladas en este entorno** y pueden invocarse directamente |
| [OWASP/ASVS](https://github.com/OWASP/ASVS) | 3.800 · CC-BY-SA-4.0 · 2026-11-17 | Fuente de requisitos en CSV/JSON para generar el checklist de los gates |
| [microsoft/sarif-sdk](https://github.com/microsoft/sarif-sdk) | 228 · 2026-11-14 | Combinar o deduplicar SARIF (`sarif merge`) antes de pasarlo al LLM |

---

## 5. Arquitectura recomendada del skill de seguridad (eficiencia de tokens)

```
fase 0  inventario (determinista, ~0 tokens)
        stack, lockfiles, Dockerfile, IaC, workflows, ¿BaaS?, ¿llama a un LLM?, ¿hay URL desplegada?
fase 1  escaneo determinista en paralelo -> SARIF/JSON en .auditor/raw/
        gitleaks | opengrep/semgrep | osv-scanner | trivy fs | bandit* | checkov | zizmor | hadolint | syft->grype
fase 2  normalización (script, ~0 tokens)
        sarif merge -> dedup por (regla, archivo, línea) -> mapear a CWE -> OWASP 2025 -> ASVS
        -> resumen compacto: máx. 1 línea por hallazgo, top N por severidad
fase 3  juicio LLM acotado (tokens medios)
        a) triage de falsos positivos SOLO de hallazgos críticos/altos (lee ±15 líneas por hallazgo)
        b) revisión de autorización: el script extrae el mapa de rutas -> handler -> consultas a BD;
           el LLM evalúa BOLA/BFLA/BOPLA ruta por ruta (no lee todo el repo)
        c) BaaS: el script vuelca pg_policies / firestore.rules; el LLM evalúa la semántica
        d) app con LLM: diagrama de flujo de datos -> LLM01/03/06/10
fase 4  dinámico opcional (requiere target y confirmación del usuario)
        ZAP baseline (pasivo) | nuclei (misconfig, exposure) | prueba IDOR con 2 usuarios de test
fase 5  scoring -> gate N1..N5 + hoja de ruta priorizada
```
\* solo si hay Python.

Reglas operativas del skill:
1. **Nunca pasar el SARIF crudo al LLM.** Pasar el resumen normalizado (regla, CWE, archivo:línea, severidad, 1 línea de evidencia). Los SARIF de semgrep o trivy en monorepos pueden ocupar megabytes.
2. **Secretos:** reportar solo la huella (tipo, archivo, commit, primeros 4 caracteres). Nunca imprimir el secreto en el informe ni en el contexto del LLM.
3. **El DAST activo** (nuclei con plantillas intrusivas, fuzzing) **requiere confirmación explícita** y solo contra hosts del propio usuario. ZAP baseline es pasivo.
4. **Fijar versiones** de cada herramienta y verificar checksums (lección de trivy-action y Shai-Hulud).
5. Si falta una herramienta, degradar con transparencia: marcar el chequeo como "no ejecutado" y no inferir que pasó.

---

## 6. Catálogo de chequeos (con gate de madurez)

Gates: **N1** prototipo · **N2** MVP (usuarios reales de prueba) · **N3** beta (usuarios externos) · **N4** producción · **N5** escala.

| ID | Chequeo | Método | Herramienta | Gate |
|---|---|---|---|---|
| SEC-01 | Sin secretos en el historial git ni en el working tree | determinista | gitleaks (+ trufflehog con verificación en N4) | N1 |
| SEC-02 | Sin secretos ni claves privilegiadas en el bundle del frontend construido (`dist/`, `.next/static`) | determinista | gitleaks dir + regex (`service_role`, `sk-`, `sk_live_`) | N1 |
| SEC-03 | `.env*` en `.gitignore` y `.env.example` sin valores reales | determinista | script | N1 |
| SEC-04 | Lockfile presente, comprometido y con hosts permitidos | determinista | lockfile-lint / script | N2 |
| SEC-05 | Todas las dependencias existen en el registro, tienen antigüedad mínima y no son typosquats (anti-slopsquatting) | determinista | script contra la API del registro + osv-scanner (detecta paquetes maliciosos reportados en OSV) | N2 |
| SEC-06 | Sin vulnerabilidades críticas o altas conocidas en dependencias de producción | determinista | osv-scanner / trivy / npm audit | N2 (críticas), N4 (altas) |
| SEC-07 | SAST: sin inyección (SQL/NoSQL/comandos/código), XSS ni path traversal | determinista | opengrep/semgrep (`p/owasp-top-ten`), bandit | N2 |
| SEC-08 | Triage de los hallazgos SAST críticos y altos (descartar falsos positivos) | llm | resumen SARIF + ±15 líneas de contexto | N2 |
| SEC-09 | BaaS: RLS habilitada en todas las tablas expuestas y sin políticas `USING (true)` para escritura; reglas Firebase no abiertas | mixto | SQL a `pg_tables` / `pg_policies` + LLM | N1 si hay BaaS |
| SEC-10 | Autorización por objeto (BOLA/IDOR) en cada endpoint con ID | mixto | script de inventario de rutas + LLM; prueba dinámica con 2 usuarios en N3+ | N2 |
| SEC-11 | Autorización por función (BFLA): rutas de admin protegidas en el servidor, no solo en la UI | mixto | inventario de rutas + LLM | N2 |
| SEC-12 | Asignación masiva / BOPLA: el endpoint no acepta campos como `role`, `isAdmin`, `owner_id` del cliente | mixto | semgrep (spread de `req.body` en ORM) + LLM | N3 |
| SEC-13 | Autenticación delegada a un proveedor probado o, si es propia, con hash de contraseña adecuado (argon2id, bcrypt o scrypt) | mixto | semgrep + LLM | N2 |
| SEC-14 | JWT: firma verificada, algoritmo fijado, `exp` presente, secreto no hardcodeado y con entropía suficiente | mixto | semgrep `p/jwt` + gitleaks + LLM | N2 |
| SEC-15 | Cookies de sesión `HttpOnly`, `Secure`, `SameSite`; token no guardado en `localStorage` | mixto | ZAP baseline + grep | N3 |
| SEC-16 | Protección CSRF si hay sesión por cookie | mixto | ZAP + LLM | N3 |
| SEC-17 | Rate limiting en login, registro, recuperación de contraseña y endpoints que llaman a un LLM o a servicios pagados | mixto | grep de middleware + LLM; ráfaga controlada en N4 | N3 |
| SEC-18 | Límites de tamaño en el body y en uploads; validación de tipo MIME y extensión; almacenamiento fuera de la raíz web | mixto | semgrep + LLM | N3 |
| SEC-19 | SSRF: los `fetch` con URL de usuario pasan por una lista permitida y bloquean IPs privadas y de metadatos | mixto | semgrep (taint) + LLM | N3 |
| SEC-20 | Cabeceras HTTP: CSP, HSTS, X-Content-Type-Options, frame-ancestors/X-Frame-Options, Referrer-Policy | determinista | ZAP baseline / nuclei | N3 |
| SEC-21 | CORS: sin `*` con credenciales; orígenes explícitos | mixto | ZAP + semgrep | N3 |
| SEC-22 | Errores: sin stack traces ni mensajes internos al cliente; los fallos no conceden acceso ("fail closed") | mixto | ZAP + semgrep + LLM | N3 |
| SEC-23 | Validación de entrada con esquema (zod, pydantic, joi) en cada endpoint | mixto | script de cobertura + LLM | N3 |
| SEC-24 | IaC, Dockerfile y K8s sin misconfiguración crítica (root, puertos abiertos, buckets públicos) | determinista | checkov / trivy config / hadolint / kics | N4 |
| SEC-25 | CI/CD: acciones fijadas a SHA, `permissions` mínimos, sin `pull_request_target` inseguro ni inyección de expresiones | determinista | zizmor / poutine / actionlint | N4 |
| SEC-26 | SBOM generado y versionado en cada release | determinista | syft / cdxgen | N4 |
| SEC-27 | OpenSSF Scorecard ≥ umbral acordado (p. ej., ≥ 6: **ESTIMACIÓN**, no es norma) | determinista | scorecard | N5 |
| SEC-28 | Procedencia de build firmada (SLSA Build L2+), artefactos firmados | determinista | slsa-github-generator / cosign | N5 |
| SEC-29 | Logging de eventos de seguridad (login fallido, cambio de permisos) sin PII ni secretos; alertas configuradas | mixto | semgrep + LLM + revisión de la configuración de observabilidad | N4 |
| SEC-30 | App con LLM: clave del LLM solo en el servidor; cuota y tope de gasto por usuario | mixto | gitleaks + LLM | N1 si hay LLM |
| SEC-31 | App con LLM: la salida del modelo nunca llega a `eval`, SQL, shell ni HTML sin sanitizar (Improper Output Handling) | mixto | semgrep (taint desde la respuesta del SDK del LLM) + LLM | N2 si hay LLM |
| SEC-32 | App con LLM: herramientas del agente con mínimo privilegio y confirmación humana para acciones destructivas (Excessive Agency) | llm | revisión del manifiesto de tools | N3 si hay LLM |
| SEC-33 | App con LLM: contenido externo (RAG, web, archivos) tratado como no confiable; segregación de instrucciones; sin secretos en el system prompt | llm | modelado de amenazas | N3 si hay LLM |
| SEC-34 | App con LLM: red teaming automatizado de inyección y fuga | determinista (ejecución) + llm (interpretación) | promptfoo / garak | N4 si hay LLM |
| SEC-35 | Modelo de amenazas (STRIDE ligero) del flujograma de la idea: activos, actores, fronteras de confianza | llm | plantilla del skill | N2 |
| SEC-36 | Cumplimiento normativo de datos personales o de salud declarado y verificado contra el texto legal (en Chile: Ley 19.628, Ley 20.584) | manual | checklist; el auditor no afirma cumplimiento | N4 si hay datos personales |
| SEC-37 | DAST pasivo sin hallazgos altos | determinista | ZAP baseline | N4 |
| SEC-38 | DAST por plantillas (exposición de `.git`, `.env`, paneles de admin, CVE conocidos) | determinista | nuclei `-tags exposure,misconfig` | N4 |
| SEC-39 | Rotación de secretos posible y documentada; secretos en un gestor (no en variables del repo) | manual | checklist | N5 |
| SEC-40 | Pentest humano o bug bounty antes de escalar con datos sensibles | manual | — | N5 |

---

## 7. Señales de madurez observables (escala de seguridad)

| Nivel | Señales mínimas observables |
|---|---|
| **N1 Prototipo** | Sin secretos en el repo ni en el bundle; claves privilegiadas solo en el servidor; si hay BaaS, RLS activada en todas las tablas |
| **N2 MVP** | Lockfile comprometido; sin CVE críticos; SAST sin inyección ni XSS sin triage; autorización verificada en el servidor en cada endpoint con ID; auth delegada o con hash fuerte; modelo de amenazas mínimo escrito |
| **N3 Beta** | Rate limiting en auth y en endpoints costosos; cabeceras de seguridad; cookies endurecidas; CORS explícito; validación de esquema en todos los endpoints; errores sin trazas; controles anti-SSRF y de uploads |
| **N4 Producción** | CI con escaneo automático (SARIF en PR) que bloquea críticos; acciones fijadas a SHA; IaC y Dockerfile limpios; SBOM por release; logging y alertas de seguridad; DAST pasivo limpio; red teaming si hay LLM; verificación normativa si hay datos personales |
| **N5 Escala** | Scorecard ≥ umbral; builds con procedencia firmada (SLSA L2+); gestor de secretos con rotación; ASVS L2 cubierto; pentest o bug bounty; plan de respuesta a incidentes probado |

---

## 8. Brechas, riesgos y decisiones pendientes para el investigador

1. **Semgrep vs Opengrep:** Semgrep CE es más conocido, pero sus reglas del registry están bajo una licencia no OSI desde diciembre de 2024. Opengrep es LGPL y offline, pero hay que traer o curar reglas propias. **Decisión pendiente** (no la autoselecciono): (a) Opengrep + reglas propias versionadas en el skill (más control, más mantenimiento) o (b) Semgrep CE con packs del registry (menos trabajo, dependencia de red y de licencia).
2. **TruffleHog es AGPL-3.0:** sin problema para uso interno, pero hay que revisarlo si auditor-integral se distribuye como servicio.
3. **Autorización (BOLA/BFLA)** es el fallo más grave y menos automatizable. La calidad del auditor dependerá del script que extrae el mapa ruta → handler → consulta. Ese extractor por framework (Next.js App Router, Express, FastAPI, Supabase) es el componente más valioso que habrá que construir.
4. **DAST** necesita un target. Hay que definir si el auditor levanta la app en local (Docker Compose) o pide la URL de staging; nunca debe escanear producción ajena.
5. **Cifras NO VERIFICADAS en este informe:** formato SARIF nativo de TruffleHog y de ZAP; distribución exacta de requisitos ASVS 5.0 por nivel; versión vigente exacta de CycloneDX y SPDX; estrellas de pip-audit; lista oficial de OWASP LLM Top 10 2026 (verificada solo con Invicti, no con el PDF de OWASP).

---

## 9. Fuentes principales
- OWASP Top 10:2025 — https://top10.owasp.org/2025
- OWASP ASVS — https://github.com/OWASP/ASVS
- OWASP API Security Project — https://owasp.org/projects/api-security-project
- OWASP GenAI (LLM Top 10 2026, Agentic Top 10 2026) — https://genai.owasp.org/announcement/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/ · https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Invicti, LLM Top 10 2026 — https://www.invicti.com/blog/web-security/owasp-llm-top-10-2026-whats-new
- MITRE CWE Top 25 2025 — https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- Veracode GenAI Code Security 2025 — https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/
- Escape.tech, apps vibe-coded — https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/
- CVE-2025-48757 — https://dbugs.ptsecurity.com/vulnerability/PT-2025-23236
- CVE-2025-29927 (Next.js) — https://nvd.nist.gov/vuln/detail/CVE-2025-29927
- GitGuardian 2025 — https://www.gitguardian.com/state-of-secrets-sprawl-report-2025
- GitGuardian 2026 (nota de prensa) — https://www.cybersecuritydive.com/press-release/20260317-ai-is-fueling-secrets-sprawl-gitguardian-reports-an-81-surge-of-ai-servic/
- Slopsquatting (Spracklen et al.) — https://www.csoonline.com/article/3961304/ai-hallucinations-lead-to-new-cyber-threat-slopsquatting.html
- CISA, Shai-Hulud — https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- Aqua, trivy-action — https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- Semgrep vs Opengrep — https://semgrep.dev/docs/faq/comparisons/opengrep
- Datos de repos: `gh api repos/<owner>/<repo>` (consultado el 2026-11-17)

---

## Verificación

Verificación escéptica realizada el 2026-11-17 (`gh api` sobre cada repo; WebFetch o WebSearch sobre las fuentes de las cifras clave).

### A. Repositorios (existencia, archivado, estrellas, licencia)

| Repo | Existe | Archivado | ★ verificado | Licencia | Resultado |
|---|---|---|---|---|---|
| opengrep/opengrep | Sí | No | 3.350 | LGPL-2.1 | Correcto |
| semgrep/semgrep | Sí | No | 17.784 | LGPL-2.1 | Correcto (±1★) |
| gitleaks/gitleaks | Sí | No | 31.145 | MIT | Correcto |
| trufflesecurity/trufflehog | Sí | No | 29.483 | AGPL-3.0 | Correcto |
| google/osv-scanner | Sí | No | 11.551 | Apache-2.0 | Correcto |
| aquasecurity/trivy | Sí | No | 39.486 | Apache-2.0 | Correcto |
| PyCQA/bandit | Sí | No | 8.392 | Apache-2.0 | Correcto |
| bridgecrewio/checkov | Sí | No | 9.163 | Apache-2.0 | Correcto |
| Checkmarx/kics | Sí | No | 2.746 | Apache-2.0 | Correcto |
| hadolint/hadolint | Sí | No | 12.540 | GPL-3.0 | Correcto |
| zizmorcore/zizmor | Sí | No | 7.077 | MIT | Correcto |
| boostsecurityio/poutine | Sí | No | 537 | Apache-2.0 | Correcto |
| rhysd/actionlint | Sí | No | 4.419 | MIT | Correcto (último push 2026-07-16: actividad menor) |
| anchore/syft | Sí | No | 9.918 | Apache-2.0 | Correcto |
| anchore/grype | Sí | No | 13.283 | Apache-2.0 | Correcto |
| cdxgen/cdxgen | Sí | No | 1.121 | Apache-2.0 | Correcto |
| ossf/scorecard | Sí | No | 5.845 | Apache-2.0 | Correcto |
| lirantal/lockfile-lint | Sí | No | 871 | Apache-2.0 | Correcto |
| zaproxy/zaproxy | Sí | No | 16.216 | Apache-2.0 | Correcto |
| projectdiscovery/nuclei | Sí | No | 33.059 | MIT | Correcto |
| projectdiscovery/nuclei-templates | Sí | No | 13.359 | MIT | Correcto (±1★) |
| promptfoo/promptfoo | Sí | No | 27.394 | MIT | Correcto |
| NVIDIA/garak | Sí | No | 10.068 | Apache-2.0 | Correcto (±1★) |
| anthropics/claude-code-security-review | Sí | No | 6.982 | MIT | Correcto; sin push desde 2026-02-11 (mantenimiento bajo) |
| trailofbits/skills | Sí | No | 8.259 | CC-BY-SA-4.0 | Correcto |
| microsoft/sarif-sdk | Sí | No | 228 | NOASSERTION | Correcto (licencia no detectada por GitHub) |
| OWASP/ASVS | Sí | No | 3.800 | CC-BY-SA-4.0 | Correcto |
| pypa/pip-audit | Sí | No | 1.407 | Apache-2.0 | **Corregido**: antes "★ NO VERIFICADO" |
| mozilla/http-observatory | Sí | **Sí** | 1.848 | MPL-2.0 | Descarte confirmado |
| praetorian-inc/noseyparker | Sí | **Sí** | 2.341 | Apache-2.0 | Descarte confirmado |
| protectai/llm-guard | Sí | **Sí** | 3.219 | MIT | Descarte confirmado |
| Yelp/detect-secrets | Sí | No | 4.681 | Apache-2.0 | Correcto |

Ningún repo resultó inexistente ni inventado.

### B. Cifras y estudios clave

| Afirmación | Fuente consultada | Resultado |
|---|---|---|
| Veracode: 45 % de tareas con vulnerabilidades, 80 tareas, >100 LLM, XSS 86 %, log injection 88 % | [Veracode](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/) | **VERIFICADO** |
| Escape: >5.600 apps, >2.000 vulnerabilidades, >400 secretos, 175 casos de PII | [Escape](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/) | **VERIFICADO** (los autores lo describen como cota inferior, escaneo pasivo) |
| CWE Top 25 2025: orden completo, CWE-352 #3, CWE-862 #4, CWE-639 #24, CWE-770 #25 | [MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) | **VERIFICADO** (las 25 posiciones coinciden) |
| CWE Top 25 2025 construido con 39.080 CVE | página de MITRE consultada | **NO VERIFICADO** en fuente primaria (solo en BleepingComputer) |
| Slopsquatting: 19,7 % de paquetes inexistentes, 16 modelos, 576.000 muestras | [CSO](https://www.csoonline.com/article/3961304/ai-hallucinations-lead-to-new-cyber-threat-slopsquatting.html) + [arXiv 2406.10279](https://arxiv.org/abs/2406.10279) | **VERIFICADO**. Matiz: 5,2 % en modelos comerciales frente a 21,7 % en modelos abiertos; la cifra global esconde esa diferencia |
| GitGuardian 2025: 6,4 % de fuga en repos con Copilot, 40 % más que el promedio | [GitGuardian](https://www.gitguardian.com/state-of-secrets-sprawl-report-2025) | **VERIFICADO** (promedio base 4,61 %; el 40 % es redondeo de ~39 %) |
| CVE-2025-48757: ~170 de 1.645 apps Lovable expuestas | búsqueda web (Superblocks, Habr, PT Security) | **PARCIAL**: la cifra 170/1.645 (303 endpoints) proviene del investigador Matt Palmer y la repiten fuentes secundarias; la página de PT Security no se pudo abrir (error de certificado). CVSS varía entre fuentes (8,26–9,8) |
| trivy-action: tags reescritos en marzo de 2026 | [Aqua](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/) | **VERIFICADO con corrección**: 76 de 77 tags, 19–20 de marzo de 2026, aviso GHSA-cxm3-wv7p-598c. El identificador **CVE-2026-33634 queda NO VERIFICADO** (Aqua no lo cita) |

### C. Correcciones aplicadas al texto
1. Sección 4, advertencia de trivy-action: fecha precisada, cifra de tags fijada en 76/77 y CVE marcado NO VERIFICADO.
2. Tabla de herramientas: estrellas, licencia y fecha de pip-audit completadas.
3. Tabla de estándares: la cifra de 39.080 CVE marcada NO VERIFICADO en fuente primaria.

### D. Pendientes no verificados en esta pasada
- Lista OWASP Top 10 LLM 2026 (solo fuente secundaria, Invicti).
- Recuento ASVS 5.0 por nivel (70/183/92).
- GitGuardian 2026 (1,27 millones de secretos de IA, +81 %): no se abrió la nota de prensa.
- Shai-Hulud "más de 500 paquetes" (CISA): no se abrió la alerta.
