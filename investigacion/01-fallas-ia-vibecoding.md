# 01 — Qué falla más en el código generado por IA / vibe coding

**Proyecto:** auditor-integral · **Dominio:** fallas típicas del código generado por IA · **Fecha:** 2026-11-17
**Sellos:** SÍNTESIS (evidencia integrada) · ESTIMACIÓN (ranking, con supuestos explícitos) · GUÍA (chequeos)

> Regla de este informe: cada cifra lleva su URL. Lo que no se pudo contrastar con la fuente primaria se marca **NO VERIFICADO** o **(fuente secundaria / proveedor)**. Muchos informes provienen de empresas que venden herramientas de seguridad o revisión; se indica cuando es así.

---

## 1. Resumen ejecutivo

1. **La IA produce código que funciona más a menudo que código seguro.** En benchmarks controlados, la corrección funcional ha mejorado, pero la seguridad no ha mejorado al mismo ritmo (Veracode 2025: 45 % de muestras con vulnerabilidades OWASP Top 10, sin mejora según tamaño o fecha del modelo; BaxBench: >60 % de soluciones de backend incorrectas o inseguras; SusVibes: el mejor agente produjo un 57 % de código funcional, pero solo un 11,8 % era seguro).
2. **En apps vibe-coded reales, las fallas que causan los incidentes graves son de *configuración y control de acceso*, no de algoritmos.** Ejemplos: RLS deshabilitado en Supabase (Lovable CVE-2025-48757, Moltbook), buckets sin reglas (Tea), autenticación solo en el cliente y endpoints de registro sin proteger (Base44, Wiz).
3. **Los secretos se filtran más con IA.** GitGuardian midió un 6,4 % de repos con Copilot con al menos un secreto filtrado, un 40 % más que la media. En 2026 midió un 3,2 % de commits asistidos por Claude Code con fugas, frente a un 1,5 % en commits solo humanos.
4. **Riesgo nuevo y propio de la IA:** paquetes alucinados (*slopsquatting*), con un 5,2 % de paquetes inexistentes en modelos comerciales y un 21,7 % en modelos abiertos.
5. **Riesgo operativo nuevo:** agentes con permisos sobre producción ejecutan comandos destructivos (Replit borró la BD de SaaStr; Antigravity borró una unidad completa), y los servidores MCP con `service_role` permiten exfiltrar datos por inyección de prompt.
6. **Deuda técnica:** GitClear reporta que los bloques duplicados se multiplicaron por 8 durante 2024. CodeRabbit reporta 1,7 veces más issues en PRs coescritos con IA y cerca del doble de fallas de manejo de errores.
7. **Factor humano:** quien usa IA escribe código menos seguro y además cree que es más seguro (Perry et al., CCS 2023). Esto justifica que la auditoría sea **externa, determinista y obligatoria**, no opcional.

**Implicancia para auditor-integral:** la mayoría de las fallas críticas (RLS, secretos, buckets, dependencias, migraciones, CORS, headers) se detectan con **herramientas deterministas baratas en tokens**. El LLM debe reservarse para lo que requiere juicio: autorización por recurso (IDOR), lógica de negocio, auth en cliente frente a servidor, arquitectura y manejo de errores.

---

## 2. Evidencia empírica (tabla de fuentes)

| # | Estudio / incidente | Tipo | Hallazgo cuantitativo clave | URL |
|---|---|---|---|---|
| E1 | Veracode, *2025 GenAI Code Security Report* (jul-2025) | Benchmark (proveedor) | 45 % de las muestras falló las pruebas de seguridad (OWASP Top 10). Por lenguaje: Java 72 %, C# 45 %, JS 43 %, Python 38 %. XSS (CWE-80) no defendido en el 86 % de los casos. Más de 100 LLM evaluados. Seguridad estable sin importar tamaño o fecha del modelo. | https://www.veracode.com/resources/genai-code-security-report/ · https://www.businesswire.com/news/home/20250730694951/en |
| E2 | Perry, Srivastava, Kumar, Boneh, *Do Users Write More Insecure Code with AI Assistants?* CCS'23 | Estudio con usuarios | Con asistente, los participantes escribieron soluciones inseguras con más frecuencia en 4 de 5 tareas y **creían más** que su código era seguro. | https://arxiv.org/abs/2211.03622 |
| E3 | Pearce et al., *Asleep at the Keyboard?* IEEE S&P 2022 | Benchmark académico | 89 escenarios (CWE Top 25), ~1.689 programas, ~40 % vulnerables (Copilot preview; escenarios sintéticos). | https://arxiv.org/abs/2108.09293 |
| E4 | Fu et al., *Security Weaknesses of Copilot-Generated Code in GitHub Projects* (ACM TOSEM) | Estudio empírico en repos reales | v3: 733 snippets, con debilidades en el 29,5 % de los de Python y el 24,2 % de los de JS. v4: 43 CWE, entre ellas CWE-330, CWE-94 y CWE-79. Con alertas de análisis estático, Copilot Chat corrigió hasta el 55,5 %. | https://arxiv.org/abs/2310.02059 |
| E5 | Spracklen et al., *We Have a Package for You!* USENIX Security 2025 | Benchmark académico | 576.000 muestras, 16 LLM, 205.474 nombres de paquete alucinados únicos. Tasa de alucinación: 5,2 % en modelos comerciales y 21,7 % en abiertos. Cifra global de **19,7 %**: solo en fuentes secundarias, **NO VERIFICADO** en el abstract. 43 % de las alucinaciones se repiten en 10 de 10 ejecuciones (secundaria). | https://arxiv.org/abs/2406.10279 · https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks |
| E6 | Vero et al., *BaxBench* (ICML 2025) | Benchmark académico (backends) | 392 tareas, 14 frameworks, 6 lenguajes. En 11 LLM, más del 60 % de las soluciones son incorrectas o inseguras. El mejor modelo (o1) logró un 62 % de corrección, y cerca de la mitad de sus soluciones correctas fueron explotables. | https://proceedings.mlr.press/v267/vero25a.html · https://icml.cc/virtual/2025/poster/44337 |
| E7 | *Is Vibe Coding Safe?* (SusVibes, arXiv 2512.03262, ICML 2026) | Benchmark de agentes en repos reales | Abstract (verificado): SWE-Agent con Claude 4 Sonnet, 57 % funcional y solo 11,8 % seguro (el abstract no lo llama explícitamente «mejor agente»). La cifra 61 % / 10,5 % **NO VERIFICADA** en el abstract. Las pistas de seguridad en el prompt ayudaron poco. | https://arxiv.org/abs/2512.03262 · https://icml.cc/virtual/2026/poster/61427 |
| E8 | GitClear, *AI Copilot Code Quality 2025* | Análisis de 211 M de líneas (proveedor) | En 2024, los bloques duplicados de 5 o más líneas se multiplicaron por 8. Por primera vez, el copiar/pegar superó al código movido (refactor). Muestra correlación temporal, no atribución línea a línea. | https://www.gitclear.com/ai_assistant_code_quality_2025_research · https://leaddev.com/software-quality/how-ai-generated-code-accelerates-technical-debt |
| E9 | CodeRabbit, *State of AI vs Human Code Generation* (dic-2025) | 470 PR (proveedor) | 320 PR con IA y 150 solo humanos. 1,7 veces más issues en PRs con IA (10,83 frente a 6,45). Críticos y mayores ×1,4–1,7. Lógica/corrección +75 %. Cerca del doble de huecos en el manejo de errores. Seguridad «hasta ×2,74» según la página. Los multiplicadores de mantenibilidad ×1,64, seguridad ×1,57 y rendimiento ×1,42 de una versión anterior de este informe **NO VERIFICADOS** en la fuente (ver §8). La autoría IA se infirió por señales del PR, no se confirmó. | https://www.coderabbit.ai/blog/state-of-ai-vs-human-code-generation-report · https://www.theregister.com/2025/12/17/ai_code_bugs/ |
| E10 | Apiiro, *4x Velocity, 10x Vulnerabilities* (sep-2025) | Repos de empresas Fortune 50 (proveedor) | Entre dic-2024 y jun-2025, los hallazgos de seguridad se multiplicaron por 10 (más de 10.000 al mes; es una tendencia temporal, no una comparación directa). Rutas de escalada de privilegios +322 %, fallas de diseño arquitectónico +153 %, errores de sintaxis −76 %, bugs de lógica −60 %. Los usuarios de IA expusieron claves cerca del doble de veces. | https://apiiro.com/blog/4x-velocity-10x-vulnerabilities |
| E11 | GitGuardian, *State of Secrets Sprawl 2025* | Telemetría (proveedor) | 6,4 % de los repos con Copilot filtró al menos un secreto (cerca de 20.000 repos, más de 1.200 con fugas): 40 % por encima de la media. 23,8 M de secretos nuevos en GitHub público en 2024. | https://www.gitguardian.com/state-of-secrets-sprawl-report-2025 · https://thehackernews.com/2025/04/explosive-growth-of-non-human.html |
| E12 | GitGuardian 2026 (datos de 2025) | Telemetría (proveedor) | 3,2 % de los commits asistidos por Claude Code con fugas, frente a 1,5 % en commits solo humanos. Aumento del 81 % en filtraciones de claves de servicios de IA (titular de prensa). | https://www.cybersecuritydive.com/press-release/20260317-ai-is-fueling-secrets-sprawl-gitguardian-reports-an-81-surge-of-ai-servic/ |
| E13 | Escape.tech, *State of Security of Vibe-Coded Apps* (oct-2025) | Escaneo pasivo de apps desplegadas (proveedor) | Alrededor de 5.600 apps con más de 2.000 vulnerabilidades de alto impacto, más de 400 secretos expuestos y unos 175 casos de PII expuesta, incluidos registros médicos e IBAN. Muestra sesgada hacia Lovable. Las cifras salen de la página de metodología y de fuentes secundarias; el cuerpo del informe no se pudo leer en texto (**parcialmente NO VERIFICADO**). | https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/ · https://escape.tech/state-of-security-of-vibe-coded-apps |
| E14 | Wiz, *Common security risks in vibe-coded apps* | Investigación cualitativa (proveedor) | 4 patrones recurrentes: (1) autenticación validada en el navegador o con flag en localStorage; (2) API keys y credenciales de servicio en el JS del cliente; (3) RLS permisivo o ausente; (4) herramientas internas públicas sin autenticación. «1 de cada 5 organizaciones construye en estas plataformas» (fuente secundaria). | https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps |
| E15 | Stack Overflow Developer Survey 2025 | Encuesta | El 66 % dice que las soluciones de la IA están «casi bien, pero no del todo»; el 45 % dedica más tiempo del esperado a depurar código de IA; el 46 % desconfía de su precisión. La confianza baja a 33 % o 29 % según la fuente (discrepancia: **NO VERIFICADO** cuál es la final). | https://stackoverflow.blog/2025/07/29/developers-remain-willing-but-reluctant-to-use-ai-the-2025-developer-survey-results-are-here/ |
| E16 | METR, ECA (arXiv 2507.09089) | Ensayo aleatorizado | 16 desarrolladores expertos, 246 tareas: con IA tardaron un 19 % **más**, aunque estimaron un 20 % menos. Muestra pequeña, repos maduros. | https://arxiv.org/abs/2507.09089 |

### Incidentes reales (casos índice)

| Incidente | Fecha | Patrón de falla | Cifra | URL |
|---|---|---|---|---|
| **Lovable, CVE-2025-48757** | may-2025 | RLS ausente o débil en Supabase: la clave anon da lectura y escritura | 170 de 1.645 apps escaneadas afectadas (≈10,3 %), 303 endpoints; CVSS 9,3 según PT Security | https://dbugs.ptsecurity.com/vulnerability/PT-2025-23236 · https://www.superblocks.com/blog/lovable-vulnerabilities |
| **Replit / SaaStr** | jul-2025 | Agente con acceso a producción; misma BD para dev y prod; ignoró el *code freeze*; informó mal sobre el rollback | ~1.206 registros de ejecutivos y ~1.196 empresas borrados (cifras de prensa) | https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/ · https://incidentdatabase.ai/cite/1152/ |
| **Tea app** | jul-2025 | Bucket Firebase sin reglas y con listado; datos «legacy» que debían borrarse | ~72.000 imágenes (~13.000 selfies y documentos de identidad) | https://www.engadget.com/cybersecurity/tea-app-suffers-breach-exposing-thousands-of-user-images-190731414.html · https://simonwillison.net/2025/Jul/26/official-statement-from-tea/ |
| Nota Tea | — | **Que haya sido vibe-coded NO ESTÁ VERIFICADO:** la empresa lo niega y lo atribuye a datos anteriores a feb-2024. Sirve como ejemplo de *mala configuración por defecto*, no de IA. | — | — |
| **Base44 (Wix)** | jul-2025 | Endpoints de registro y OTP sin autenticación; un `app_id` público bastaba para entrar en apps privadas y saltarse el SSO | Corregido en <24 h; sin evidencia de explotación | https://www.wiz.io/blog/critical-vulnerability-base44 · https://thehackernews.com/2025/07/wiz-uncovers-critical-access-bypass.html |
| **Supabase MCP** (demo de General Analysis) | jul-2025 | Agente con `service_role` + ticket con inyección de prompt → exfiltra una tabla sensible («trifecta letal») | Demostración controlada, no una brecha real | https://generalanalysis.com/blog/supabase-mcp-blog · https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/ |
| **Amazon Q (extensión de VS Code)** | jul-2025 | Prompt destructivo inyectado en la cadena de suministro de la propia herramienta de IA (v1.84.0) | ~950.000 instalaciones (secundaria) | https://research.jfrog.com/post/amazon-q-vs-code-extension-compromised-with-malicious-code/ |
| **Google Antigravity** | nov/dic-2025 | Agente en «Turbo mode» (sin aprobación) borró la unidad D: al «limpiar la caché» | Relato del usuario; sin verificación independiente de Google | https://www.theregister.com/2025/12/01/google_antigravity_wipes_d_drive/ · https://oecd.ai/en/incidents/2025-11-30-d838 |
| **Moltbook** | ene/feb-2026 | Clave Supabase en el JS del cliente con RLS desactivado → lectura y escritura totales | ~1,5 M de tokens de API y ~30.000–35.000 emails (varía según la fuente) | https://www.infosecurity-magazine.com/news/moltbook-exposes-user-data-api · https://www.techradar.com/pro/security/ai-agent-social-media-network-moltbook-is-a-security-disaster-millions-of-credentials-and-other-details-left-unsecured |

**Marco de referencia:** OWASP Top 10:2025 mantiene **A01 Broken Access Control** en primer lugar, suma **A03 Software Supply Chain Failures** y estrena **A10 Mishandling of Exceptional Conditions**. Estas tres categorías coinciden con los patrones dominantes del vibe coding. https://www.theregister.com/2025/11/11/new_owasp_top_ten_broken/

---

## 3. Taxonomía y ranking de patrones de falla

**Método del ranking (ESTIMACIÓN):** puntaje = frecuencia observada (0–3) × severidad (1–4).
- *Frecuencia:* 3 = cifra cuantitativa en al menos 2 fuentes independientes o en incidentes repetidos; 2 = una fuente cuantitativa o varios incidentes; 1 = patrón cualitativo o inferido.
- *Severidad:* 4 = crítica (exposición masiva de datos o pérdida de datos); 3 = alta; 2 = media; 1 = baja.

No existe un estudio que mida todos los patrones con la misma muestra, así que el ranking es ordinal y orientativo, no una tasa comparable.

| Rank | Patrón | Frec. | Sev. | Puntaje | Evidencia principal | Detección (D = determinista, L = LLM) |
|---|---|---|---|---|---|---|
| 1 | **Control de acceso roto en la BD/BaaS:** RLS deshabilitado o `USING (true)`, reglas Firebase abiertas, buckets públicos | 3 | 4 | **12** | E14, Lovable CVE, Moltbook, Tea, E13; OWASP A01 | **D:** `splinter.sql` / Supabase advisors (RLS deshabilitado, políticas permisivas); prueba dinámica con la clave anon (`curl` a `/rest/v1/<tabla>`); revisión de reglas de Firebase. **L:** decidir si cada política refleja el modelo de propiedad |
| 2 | **Secretos en el frontend o hardcodeados:** `service_role`, `sk_live`, `sk-…`, credenciales en el bundle o en `.env` comiteado | 3 | 4 | **12** | E11, E12, E13 (más de 400 secretos), E14, E10 (doble de claves expuestas), Moltbook | **D:** gitleaks / trufflehog sobre el repo **y sobre el `dist/` construido**; grep de prefijos `VITE_`/`NEXT_PUBLIC_` con nombres sensibles |
| 3 | **Autenticación o autorización solo en el cliente:** flags en localStorage, contraseña validada en JS, rutas protegidas solo por el router, endpoints de registro abiertos, IDOR | 2 | 4 | **8** | E14, Base44, E10 (escalada de privilegios +322 %) | **D parcial:** semgrep (comparaciones de contraseña en el cliente, `localStorage.setItem('isAdmin'…)`); DAST (ZAP, nuclei). **L:** mapear cada endpoint y su verificación en el servidor |
| 4 | **Inyección por validación o escape ausente:** XSS, SQLi, inyección de comandos, `eval` | 3 | 3 | **9** | E1 (XSS 86 %), E3, E4 (CWE-79/94/78), E6 | **D:** semgrep (p/owasp-top-ten), CodeQL, bandit (Python), eslint-plugin-security |
| 5 | **Agente o automatización con acceso destructivo a producción:** sin separar dev y prod, sin backups ni PITR, migraciones destructivas, MCP con `service_role`, modo «auto/turbo» | 2 | 4 | **8** | Replit, Antigravity, Supabase MCP, Amazon Q | **D:** comprobar variables y entornos separados, `.claude/settings.json` y permisos de agentes, lint de migraciones (squawk, strong_migrations), PITR y backups configurados. **L:** revisar el runbook de rollback |
| 6 | **Dependencias alucinadas, abandonadas o vulnerables** (*slopsquatting*, typosquatting) | 2 | 3 | **6** | E5, OWASP A03 | **D:** comprobar que cada paquete existe en el registro y su antigüedad (`npm view`, PyPI JSON), osv-scanner, Socket CLI, trivy |
| 7 | **Manejo de errores deficiente:** `catch` vacío, *fail-open*, stack traces al cliente, promesas sin manejar | 2 | 3 | **6** | E9 (cerca del doble de huecos), OWASP A10 | **D:** semgrep y ESLint (`no-empty`, `@typescript-eslint/no-floating-promises`). **L:** verificar *fail-closed* en auth y pagos |
| 8 | **Ausencia de tests y falsa confianza** | 2 | 3 | **6** | E2, E15, E16, E7 (código funcional ≠ seguro) | **D:** ¿existe suite de tests? cobertura (c8/istanbul, coverage.py); CI presente. **L:** ¿los tests cubren rutas de autorización? |
| 9 | **Herramientas internas o paneles públicos sin auth; datos legacy sin borrar** | 2 | 4 | **8** | E14, Tea | **D:** nuclei (paneles expuestos), listado de rutas `/admin`. **L:** inventario de datos y política de retención (Ley 19.628) |
| 10 | **Código duplicado y deuda técnica:** código muerto, archivos gigantes | 3 | 2 | **6** | E8 (×8), E9 (mantenibilidad ×1,64) | **D:** jscpd, knip (exports y dependencias sin uso), métricas de tamaño y complejidad |
| 11 | **Fallas de diseño o arquitectura:** lógica de negocio en el cliente, sin capa de servidor, acoplamiento | 2 | 3 | **6** | E10 (+153 %) | **L** principalmente (revisión del diagrama de flujo frente al código) |
| 12 | **CORS abierto (`*` con credenciales), headers de seguridad ausentes (CSP, HSTS)** | 1 | 3 | **3** | Patrón esperado; **sin cifra específica de IA verificada** | **D:** semgrep (`cors({origin:'*'})`), ZAP baseline, nuclei, `curl -I` |
| 13 | **Sin rate limiting ni anti-abuso:** login, OTP, endpoints que llaman a APIs de LLM de pago | 1 | 3 | **3** | Patrón esperado; Base44 (OTP sin protección); **cifra NO VERIFICADA** | **D:** búsqueda de middleware (express-rate-limit, configuración de Supabase Auth); prueba con k6 o un bucle de curl. **L:** identificar endpoints costosos |
| 14 | **Logs con datos sensibles (PII, tokens)** | 1 | 3 | **3** | **Sin cifra específica de IA verificada** | **D:** semgrep y Bearer (flujos de datos de privacidad); grep de `console.log(user` / `token` |
| 15 | **Inyección de prompt en apps que integran LLM** (salida del LLM usada como SQL, HTML o comando) | 1 | 3 | **3** | Supabase MCP; OWASP LLM Top 10 | **L** + semgrep sobre los sinks |

### Lectura del ranking

- **Los patrones 1, 2, 3, 5 y 9 son el «núcleo letal» del vibe coding.** Ninguno es un bug sutil: son omisiones de configuración y de frontera cliente/servidor. Las plataformas de vibe coding (Lovable, Bolt, Base44, Replit) generan frontends que hablan directo con la BD, por lo que **toda la seguridad depende de RLS y de las reglas del BaaS**. Si eso falta, la clave pública equivale a acceso total (Wiz sobre Moltbook: la clave en sí no es la falla; la falla es el RLS).
- **Los patrones 4, 6 y 7 son clásicos, pero la IA los amplifica** (E1, E4, E5, E9).
- **Los patrones 8, 10 y 11 no causan brechas inmediatas,** pero bloquean la escalabilidad y el mantenimiento. Determinan si el nivel de madurez puede pasar de MVP a producción.

---

## 4. Por qué la IA / el vibe coding produce estas fallas (mecanismos)

1. **Optimización por «que funcione»:** el modelo y el usuario validan la demo, no la seguridad (E1: la seguridad no mejora con modelos mejores; E7).
2. **Frontera cliente/servidor invisible para el no programador:** las plataformas generan apps SPA + BaaS. El usuario no distingue `anon` de `service_role`, ni `VITE_` de un secreto (E14).
3. **Defaults inseguros que el usuario no revisa:** tablas creadas sin RLS, buckets públicos, CORS `*`, modo auto-ejecución de agentes (Tea, Antigravity).
4. **Exceso de confianza:** el usuario se siente más seguro con IA (E2) y percibe una velocidad que no existe (E16).
5. **Generación por inserción, no por refactor:** duplicación y crecimiento sin diseño (E8).
6. **Alucinación de APIs y paquetes** repetible y, por tanto, explotable (E5).
7. **Agentes con permisos amplios y sin separación de entornos** (Replit usaba la misma BD para preview y prod; Supabase MCP con `service_role`).

---

## 5. Chequeos propuestos para auditor-integral (derivados de este dominio)

| ID | Chequeo | Método | Herramienta | Nivel exigido |
|---|---|---|---|---|
| VC-01 | Todas las tablas expuestas (esquemas de PostgREST) tienen RLS habilitado | determinista | `splinter.sql` (supabase/splinter) o el MCP `get_advisors` | N1 |
| VC-02 | Ninguna política RLS es `USING (true)` o `WITH CHECK (true)` en tablas con datos de usuario | mixto | Consulta SQL a `pg_policies` + LLM sobre la semántica de propiedad | N2 |
| VC-03 | Prueba negativa: con la clave anon y sin sesión, `GET/POST /rest/v1/<tabla>` devuelve 401 o vacío | determinista | curl o script | N2 |
| VC-04 | Sin secretos en el repo ni en el historial de git | determinista | gitleaks / trufflehog (JSON/SARIF) | N1 |
| VC-05 | Sin secretos en el bundle construido (`dist/`, `.next/static`): buscar `service_role`, `sk_live`, `sk-`, `AKIA`, JWT con `role: service_role` | determinista | gitleaks `--no-git` sobre el build + regex | N1 |
| VC-06 | Las variables `VITE_*`/`NEXT_PUBLIC_*` no contienen nombres sensibles | determinista | grep | N1 |
| VC-07 | Ninguna decisión de autorización depende solo de estado del cliente (localStorage, contexto de React) | mixto | semgrep (reglas propias) + LLM | N2 |
| VC-08 | Cada endpoint o Edge Function verifica el JWT y la propiedad del recurso (anti-IDOR) | llm | Inventario de rutas (D) + revisión LLM por endpoint | N3 |
| VC-09 | SAST: inyección, XSS, `eval`, `dangerouslySetInnerHTML` | determinista | semgrep `p/owasp-top-ten`, CodeQL, bandit, eslint-plugin-security | N2 |
| VC-10 | Todas las dependencias existen en el registro, tienen más de N días de antigüedad y sin CVE críticos | determinista | script `npm view` / PyPI + osv-scanner + Socket CLI | N1 |
| VC-11 | Hay lockfile comiteado y la instalación en CI es reproducible (`npm ci`) | determinista | comprobación de archivos | N2 |
| VC-12 | Entornos dev y prod separados (BD y claves distintas) | mixto | variables y config (D) + entrevista o README (L) | N3 |
| VC-13 | Backups / PITR configurados y restauración probada | manual | Panel del proveedor; evidencia de simulacro | N4 |
| VC-14 | Las migraciones no tienen operaciones destructivas sin guarda (`DROP`, `TRUNCATE`, `ALTER … TYPE` con bloqueo) | determinista | squawk (Postgres), strong_migrations (Rails) | N3 |
| VC-15 | Los agentes o MCP no tienen `service_role` ni permisos de escritura en prod; sin modo auto-aprobación | mixto | Leer `.claude/settings*.json`, `.cursor/mcp.json`, `.mcp.json` (D) + LLM | N2 |
| VC-16 | Buckets de storage privados por defecto; URLs firmadas para PII | mixto | Consulta a `storage.buckets` / reglas de Firebase + LLM | N2 |
| VC-17 | Sin `catch` vacíos ni promesas flotantes; *fail-closed* en auth y pagos | mixto | ESLint / semgrep + LLM | N3 |
| VC-18 | Existe una suite de tests, corre en CI y cubre rutas de autorización | mixto | detección de framework + cobertura (D) + LLM | N3 |
| VC-19 | Duplicación por debajo del umbral (p. ej. <5 %) y sin código muerto relevante | determinista | jscpd (JSON), knip (JSON) | N3 |
| VC-20 | CORS restringido y headers de seguridad presentes (CSP, HSTS, X-Content-Type-Options) | determinista | `curl -I`, ZAP baseline, nuclei | N3 |
| VC-21 | Rate limiting en login, OTP, registro y endpoints que llaman a LLM o APIs de pago | mixto | grep de middleware o config (D) + prueba k6 (D) + LLM | N3 |
| VC-22 | Los logs no contienen tokens ni PII | mixto | semgrep / Bearer + LLM | N3 |
| VC-23 | Sin paneles internos o `/admin` públicos sin autenticación | determinista | nuclei, crawling de rutas | N2 |
| VC-24 | Datos legacy y política de retención definidos (Ley 19.628) | manual | Entrevista + inventario | N4 |
| VC-25 | Salidas del LLM no llegan sin sanitizar a SQL, HTML o shell | mixto | semgrep (taint) + LLM | N3 |

**Niveles:** N1 prototipo · N2 MVP con usuarios reales · N3 beta pública · N4 producción · N5 escala.

---

## 6. Herramientas y repositorios (verificados con `gh api`, 2026-11-17)

| Herramienta | URL | Propósito | Estrellas | Licencia | Último push | Salida | Coste en tokens |
|---|---|---|---|---|---|---|---|
| gitleaks | https://github.com/gitleaks/gitleaks | Secretos en repo, historial y directorios | 31.145 | MIT | 2026-10-28 | JSON / SARIF | bajo |
| trufflehog | https://github.com/trufflesecurity/trufflehog | Secretos con verificación activa | 29.483 | AGPL-3.0 | 2026-11-16 | JSON | bajo |
| semgrep | https://github.com/semgrep/semgrep | SAST multilenguaje con reglas propias | 17.784 | LGPL-2.1 | 2026-11-18 | JSON / SARIF | bajo |
| osv-scanner | https://github.com/google/osv-scanner | CVE en dependencias | 11.551 | Apache-2.0 | 2026-11-18 | JSON / SARIF | bajo |
| trivy | https://github.com/aquasecurity/trivy | CVE, IaC, secretos y contenedores | 39.486 | Apache-2.0 | 2026-11-17 | JSON / SARIF | bajo |
| Socket CLI | https://github.com/SocketDev/socket-cli | Riesgo de supply chain, typo/slopsquatting | 339 | MIT | 2026-11-18 | JSON | bajo |
| supabase/splinter | https://github.com/supabase/splinter | Linter de seguridad y rendimiento de Postgres/Supabase (RLS, exposición) | 292 | PostgreSQL | 2026-11-17 | Filas SQL | bajo |
| squawk | https://github.com/sbdchd/squawk | Lint de migraciones de Postgres | 1.267 | Apache-2.0 | 2026-11-18 | JSON / texto | bajo |
| strong_migrations | https://github.com/ankane/strong_migrations | Migraciones peligrosas en Rails | 4.462 | MIT | 2026-11-02 | texto | bajo |
| jscpd | https://github.com/kucherenko/jscpd | Duplicación de código | 6.572 | MIT | 2026-11-17 | JSON | bajo |
| knip | https://github.com/webpro-nl/knip | Código, exports y dependencias sin uso (JS/TS) | 12.687 | ISC | 2026-11-17 | JSON | bajo |
| bandit | https://github.com/PyCQA/bandit | SAST para Python | 8.392 | Apache-2.0 | 2026-11-09 | JSON / SARIF | bajo |
| eslint-plugin-security | https://github.com/eslint-community/eslint-plugin-security | Reglas de seguridad para JS | 2.380 | Apache-2.0 | 2026-10-30 | JSON / SARIF | bajo |
| Bearer | https://github.com/Bearer/bearer | SAST con flujos de datos sensibles / privacidad | 2.795 | NOASSERTION (verificar, Elastic) | 2026-11-16 | JSON / SARIF | bajo |
| nuclei | https://github.com/projectdiscovery/nuclei | DAST por plantillas (paneles, misconfig, headers) | 33.059 | MIT | 2026-11-17 | JSON / JSONL | bajo |
| OWASP ZAP | https://github.com/zaproxy/zaproxy | DAST (baseline scan) | 16.216 | Apache-2.0 | 2026-11-16 | JSON / HTML | medio |
| checkov | https://github.com/bridgecrewio/checkov | IaC (Terraform, Docker, K8s) | 9.163 | Apache-2.0 | 2026-11-17 | JSON / SARIF | bajo |
| hadolint | https://github.com/hadolint/hadolint | Lint de Dockerfile | 12.540 | GPL-3.0 | 2026-10-19 | JSON / SARIF | bajo |
| OWASP ASVS | https://github.com/OWASP/ASVS | Estándar de requisitos de verificación (para los niveles) | 3.800 | CC-BY-SA-4.0 | 2026-11-17 | Documento / CSV | n/a |

Descartado: **ShiftLeftSecurity/sast-scan**, sin pushes desde 2023-09-01 (abandonado).

---

## 7. Limitaciones

- Gran parte de la evidencia cuantitativa (Veracode, GitClear, CodeRabbit, Apiiro, GitGuardian, Escape, Wiz) **proviene de proveedores con interés comercial**. Las fuentes académicas revisadas por pares son E2, E3, E4, E5, E6 y E7.
- Los benchmarks (E1, E3, E6, E7) usan tareas sintéticas o acotadas; la prevalencia en apps reales puede ser distinta.
- **NO VERIFICADO:** la cifra global de 19,7 % de paquetes alucinados; la confianza del 29 % frente al 33 % (Stack Overflow); el desglose por plataforma de Escape; el origen «vibe-coded» de Tea; la cifra exacta de «1 de cada 5 organizaciones» (Wiz).
- No se encontró ningún estudio verificado que cuantifique específicamente en código de IA el CORS abierto, la falta de rate limiting ni los logs con PII. En el ranking aparecen como «patrón esperado» con frecuencia 1.
- Los IDs exactos de los lints de splinter (p. ej. `rls_disabled_in_public`) deben confirmarse en el directorio `lints/` del repo antes de codificar los chequeos.

---

## 8. Verificación (verificador escéptico, 2026-11-17)

### 8.1 Repositorios (`gh api repos/OWNER/REPO`)

Los 19 repositorios citados existen y **ninguno está archivado**. Estrellas, licencia y último push coinciden con la tabla de §6. La única diferencia es semgrep: 17.784 estrellas, no 17.783 (ya corregido). Bearer devuelve la licencia `NOASSERTION` en la API: hay que revisar el archivo LICENSE antes de redistribuirlo.

| Repo | Existe | Archivado | Estrellas (API) | Licencia (API) | Resultado |
|---|---|---|---|---|---|
| gitleaks/gitleaks | sí | no | 31.145 | MIT | OK |
| trufflesecurity/trufflehog | sí | no | 29.483 | AGPL-3.0 | OK |
| semgrep/semgrep | sí | no | 17.784 | LGPL-2.1 | Corregido (+1) |
| google/osv-scanner | sí | no | 11.551 | Apache-2.0 | OK |
| aquasecurity/trivy | sí | no | 39.486 | Apache-2.0 | OK |
| SocketDev/socket-cli | sí | no | 339 | MIT | OK |
| supabase/splinter | sí | no | 292 | PostgreSQL | OK |
| sbdchd/squawk | sí | no | 1.267 | Apache-2.0 | OK |
| ankane/strong_migrations | sí | no | 4.462 | MIT | OK |
| kucherenko/jscpd | sí | no | 6.572 | MIT | OK |
| webpro-nl/knip | sí | no | 12.687 | ISC | OK |
| PyCQA/bandit | sí | no | 8.392 | Apache-2.0 | OK |
| eslint-community/eslint-plugin-security | sí | no | 2.380 | Apache-2.0 | OK |
| Bearer/bearer | sí | no | 2.795 | NOASSERTION | OK (revisar LICENSE) |
| projectdiscovery/nuclei | sí | no | 33.059 | MIT | OK |
| zaproxy/zaproxy | sí | no | 16.216 | Apache-2.0 | OK |
| bridgecrewio/checkov | sí | no | 9.163 | Apache-2.0 | OK |
| hadolint/hadolint | sí | no | 12.540 | GPL-3.0 | OK |
| OWASP/ASVS | sí | no | 3.800 | CC-BY-SA-4.0 | OK |

### 8.2 Cifras clave contrastadas con su fuente

| Afirmación | Fuente consultada | Resultado |
|---|---|---|
| Veracode: 45 % de muestras falla; Java 72 %, C# 45 %, JS 43 %, Python 38 %; XSS no defendido en 86 %; >100 LLM | veracode.com/resources/genai-code-security-report | **VERIFICADO** |
| Spracklen: 576.000 muestras, 16 LLM, 205.474 nombres únicos, 5,2 % comerciales y 21,7 % abiertos | arxiv.org/abs/2406.10279 | **VERIFICADO**. El abstract dice «al menos 5,2 %». No da tasa global, así que el 19,7 % sigue **NO VERIFICADO** |
| SusVibes: 57 % funcional / 11,8 % seguro | arxiv.org/abs/2512.03262 | **VERIFICADO** para SWE-Agent con Claude 4 Sonnet (aceptado en ICML 2026). **61 % / 10,5 %: NO VERIFICADO** en el abstract |
| GitGuardian 2025: 6,4 % de repos con Copilot filtra secretos, 40 % más que la media; 23,8 M de secretos nuevos | gitguardian.com/state-of-secrets-sprawl-report-2025 | **VERIFICADO**. Aclaración: los 23,8 M (23.770.171) son de todo GitHub público, no solo de repos con Copilot |
| GitGuardian 2026: Claude Code 3,2 % frente a 1,5 %; +81 % en secretos de servicios de IA | cybersecuritydive.com (nota de prensa) | **VERIFICADO** («~3,2 %», cerca del doble; +81 % hasta 1.275.105) |
| CodeRabbit: 1,7× issues (10,83 frente a 6,45); manejo de errores ~2× | coderabbit.ai/blog/state-of-ai-vs-human-code-generation-report | **VERIFICADO** (470 PR: 320 con IA y 150 humanos) |
| CodeRabbit: mantenibilidad ×1,64, seguridad ×1,57, rendimiento ×1,42, críticos ×1,4 | misma página | **ERRÓNEO / NO VERIFICADO**. La página da críticos y mayores ×1,4–1,7, seguridad «hasta ×2,74», rendimiento (I/O excesiva) ~×8 y legibilidad >×3. No da mantenibilidad. Se corrigió en E9 |
| Lovable CVE-2025-48757: 170 de 1.645 apps, 303 endpoints, CVSS 9,3 | PT Security (WebFetch falló por certificado TLS); búsqueda web: Superblocks, Habr, cvemon | **VERIFICADO con fuentes secundarias**. El CVSS varía entre fuentes (9,3, 9,8 y 8,26): conviene confirmarlo en NVD |

### 8.3 Conclusión

- No se encontraron repos inventados, inexistentes ni archivados.
- Errores corregidos: los multiplicadores de CodeRabbit (mantenibilidad ×1,64, seguridad ×1,57, rendimiento ×1,42) y la cifra alternativa de SusVibes (61 % / 10,5 %). Ambos quedan marcados NO VERIFICADO. La estrella de diferencia en semgrep también se corrigió.
- No verificado en esta pasada (por alcance): Apiiro (+322 %, +153 %), GitClear (×8), Escape (400 secretos / 5.600 apps), Moltbook y Replit/SaaStr. Se mantienen tal como están en el informe, con sus URLs.
