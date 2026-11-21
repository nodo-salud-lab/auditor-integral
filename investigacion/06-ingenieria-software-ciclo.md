# 06 — Ingeniería de software de punta a punta (idea → producción) para "auditor-integral"

> Fecha: 2026-11-17 · Sello: **SÍNTESIS** (evidencia integrada) + **GUÍA** (procedimiento) + **ESTIMACIÓN** (escala N1–N5, umbrales propuestos).
> Regla aplicada: toda cifra lleva URL; lo que no se pudo confirmar en fuente primaria va marcado **NO VERIFICADO**. Estrellas/licencias/último push de repos obtenidos con `gh api repos/OWNER/REPO` el 2026-11-17/18 UTC.

---

## 1. Qué cubre este dominio y por qué importa en "vibe coding"

El dominio "ciclo de ingeniería" es transversal: no busca un bug concreto sino **si existen las prácticas que evitan que los bugs lleguen a producción** (requisitos verificables, diseño explícito, tipado, pruebas que de verdad prueban, CI que bloquea, release reversible, operación medida). En proyectos generados por IA por no-programadores, el código "funciona en la demo" pero suelen faltar estas capas.

### Evidencia 2024–2026 sobre fallas típicas del código asistido por IA

| Hallazgo | Cifra | Fuente | Estado |
|---|---|---|---|
| Duplicación: bloques de ≥5 líneas duplicadas aumentaron ~8× en 2024; líneas copy/paste superaron a líneas "movidas" (proxy de refactorización) por primera vez | 211 M líneas cambiadas 2020–2024 | GitClear 2025, vía https://www.devclass.com/ai-ml/2025/02/20/ai-is-eroding-code-quality-states-new-in-depth-report/1626250 y https://leaddev.com/software-quality/how-ai-generated-code-accelerates-technical-debt | Verificado en fuentes secundarias; cifras exactas de "moved code" (24,8%→9,5%) **difieren entre fuentes** → tratar como orden de magnitud |
| Código generado por IA introdujo vulnerabilidades en 45% de las tareas de prueba (80 tareas, >100 LLM); XSS fallado 86%, log injection 88%; Java >70% | 2025 | https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/ | Verificado (nota: 45% es de *casos de prueba*, no de "todo el código IA") |
| PRs coautorados por IA: ~1,7× más issues que PRs humanos; 1,4–1,7× más issues críticos+mayores (combinados; corregido en Verificación); foco en lógica, mantenibilidad, seguridad, rendimiento (n=470 PRs) | dic-2025 | https://www.coderabbit.ai/blog/state-of-AI-vs-human-code-generation-report ; https://www.theregister.com/2025/12/17/ai_code_bugs/ | Verificado; muestra pequeña y etiquetado humano/IA imperfecto (lo reconoce el autor) |
| Paquetes alucinados: 19,7% global (NO VERIFICADO en abstract; abstract: ≥5,2% modelos comerciales, 21,7% open source) de paquetes recomendados no existían; 205.474 nombres únicos inventados (base del ataque "slopsquatting") | USENIX Security 2025 (Spracklen et al.) | https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419/ | Verificado en fuente secundaria; tamaño de muestra difiere entre resúmenes |
| DORA 2025: la adopción de IA se asocia a **más throughput pero también más inestabilidad** de entrega (~5.000 profesionales) | 2025 | https://services.google.com/fh/files/misc/2025_state_of_ai_assisted_software_development.pdf ; https://www.infoq.com/news/2025/09/dora-state-of-ai-in-dev-2025 | Verificado (dirección del efecto); magnitudes no extraídas |
| ECA METR: desarrolladores OSS experimentados tardaron 19% más con IA, aunque creyeron ir 20% más rápido (16 devs, 246 tareas) | jul-2025 | https://arxiv.org/abs/2507.09089 | Verificado; no generalizable a no-programadores |

**Lectura para el auditor:** la IA amplifica velocidad y deuda a la vez. Los tres riesgos con mejor evidencia y que son **detectables de forma determinista** son: duplicación, vulnerabilidades por patrones conocidos y dependencias inexistentes/no usadas. La "percepción de rapidez" (METR) justifica que el auditor no confíe en la autoevaluación del usuario sino en evidencia de herramientas.

---

## 2. Fases del ciclo: qué debe existir, qué falla con IA, cómo detectarlo

### 2.1 Idea → requisitos (flujograma, historias de usuario, criterios de aceptación)
- **Debe existir:** un flujograma o diagrama de flujo de usuario (Mermaid sirve; versionable en el repo), historias "Como <rol> quiero <x> para <y>", criterios de aceptación verificables (Gherkin Given/When/Then o lista checkable), requisitos no funcionales mínimos (usuarios concurrentes esperados, datos sensibles sí/no, disponibilidad objetivo).
- **Falla típica vibe coding:** no hay requisitos escritos; el "spec" es el historial del chat. Imposible saber si la app "está lista" porque no hay definición de "listo". Casos de error y bordes (sin conexión, campos vacíos, permisos) nunca se especificaron.
- **Detección:** determinista para *existencia* (buscar `docs/`, `*.feature`, `README` con sección de alcance, bloques ```mermaid```); **LLM** para *calidad* (¿los criterios son verificables?, ¿cubren casos de error?). Costo de tokens bajo si se le pasa solo el README + docs, no el código.
- **Skill propuesta:** entrevista guiada que genera `docs/requisitos.md` + `docs/flujo.mmd` antes de auditar; sin esto, el auditor no puede pasar de N1.

### 2.2 Diseño (C4, ADRs, modelado de amenazas STRIDE)
- **C4 model** (Contexto, Contenedores, Componentes, Código): basta con niveles 1–2 para un proyecto pequeño. https://c4model.com
- **ADR (Architecture Decision Records):** un archivo corto por decisión (contexto, decisión, consecuencias). Repo de referencia `architecture-decision-record/architecture-decision-record` (17.485★, push 2026-11-17). Herramientas: `npryce/adr-tools` (5.781★, último push 2024-04 → poco mantenido), `thomvaill/log4brains` (1.613★, Apache-2.0, último push 2024-12).
- **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege) por cada flujo de datos que cruce una frontera de confianza. Herramientas: `OWASP/threat-dragon` (1.694★, Apache-2.0, activo), `OWASP/pytm` (1.201★, threat-model-as-code en Python, activo).
- **Falla típica vibe coding:** arquitectura emergente sin decisión explícita (p. ej., lógica de negocio y claves en el cliente, Supabase sin RLS, "todo en un archivo"); nadie modeló quién puede ver qué.
- **Detección:** existencia de `docs/adr/`, diagramas C4 → determinista. Calidad del modelo de amenazas y coherencia arquitectura/código → **LLM** (alimentado con el grafo de dependencias de `madge`/`dependency-cruiser` en JSON, no con el código completo).

### 2.3 Implementación (calidad, complejidad, duplicación, tipado, lint, código muerto)
| Chequeo | JS/TS | Python | Salida | Notas |
|---|---|---|---|---|
| Lint | `eslint` (27.627★, MIT) o `biome` (26.131★, Apache-2.0) | `ruff` (51.421★, MIT) | JSON / SARIF (eslint con formatter SARIF; ruff `--output-format sarif`) | ruff y biome son muy rápidos → ideales para corrida completa |
| Tipado | `tsc --noEmit` (TypeScript 111.838★) ; revisar `strict: true` en tsconfig | `mypy` (20.725★) / `pyright` (15.750★) | texto parseable / JSON (`pyright --outputjson`) | Señal fuerte: `any` explícitos, `// @ts-ignore`, `strict:false` |
| Duplicación | `jscpd` (6.572★, MIT; multi-lenguaje) | `jscpd` | JSON, SARIF, HTML | Prioritario por la evidencia GitClear |
| Complejidad ciclomática | `lizard` (2.604★, multi-lenguaje, activo) / regla `complexity` de eslint | `radon` (2.045★, MIT; último push 2024-10) / `ruff` regla C901 | lizard: CSV/XML; radon: JSON | Usar lizard como motor único multi-lenguaje |
| Código/deps muertos | `knip` (12.687★, ISC; archivos, exports y deps no usados) | `vulture` (4.976★) + `deptry` (1.505★) | JSON | **`depcheck` está ARCHIVADO** (4.901★, archived=true) → no usar |
| Ciclos y arquitectura | `madge` (10.185★; último push 2026-01) / `dependency-cruiser` (7.437★, reglas de capas) | `import-linter` (NO VERIFICADO stats) | JSON / DOT | dependency-cruiser permite reglas "UI no importa DB" |
| Patrones a medida (anti-patrones IA) | `ast-grep` (16.616★, MIT) | `ast-grep` | JSON | Reglas YAML baratas: `console.log` de secretos, `eval`, `fetch` sin manejo de error, `catch {}` vacío |
| Plataforma agregadora | `qlty` (3.226★; ejecuta muchos linters y unifica) | idem | SARIF/JSON | Opción para no orquestar cada CLI a mano; evaluar licencia (NOASSERTION en GitHub) |
| Gate de referencia | SonarQube (11.190★, LGPL-3.0) | idem | API JSON | Requiere servidor; para N4–N5 |

**Fallas típicas vibe coding en implementación:** duplicación por copy-paste del asistente; funciones gigantes; `any` y `ts-ignore` para "callar" errores; dependencias instaladas y nunca usadas (o inexistentes: slopsquatting); `try/catch` que traga errores; código muerto de iteraciones anteriores del chat; mezcla de varios estilos/librerías para lo mismo (dos clientes HTTP, dos librerías de fechas).

### 2.4 Pruebas (pirámide, cobertura, mutation testing)
- **Pirámide:** muchas unitarias, menos de integración, pocas E2E. En vibe coding suele haber **cero pruebas** o pruebas generadas por IA que solo verifican que "no lanza" (aserciones débiles) o que mockean todo.
- **Cobertura:** `vitest` (17.391★) / `jest` (45.475★) con `--coverage` (v8/istanbul → `coverage-summary.json`), `c8` (2.126★); Python `pytest-cov` (2.080★) → `coverage.json`. Umbral de referencia: el quality gate "Sonar way" exige ≥80% de cobertura en **código nuevo** (https://docs.sonarsource.com/sonarqube-server/10.6/user-guide/quality-gates). Para proyectos heredados vibe-coded, exigir 80% global de entrada es irreal: aplicar el principio "clean as you code" (umbral sobre código nuevo).
- **Mutation testing:** detecta exactamente el problema de "pruebas que no prueban". `stryker-js` (3.387★, Apache-2.0) → reporte JSON (mutation-testing-report-schema); Python `mutmut` (1.545★, BSD-3). Es **caro en tiempo de CPU** (no en tokens): correr solo sobre módulos críticos (auth, pagos, cálculo) y solo desde N3.
- **Aceptación ejecutable:** `cucumber-js` (5.407★) conecta criterios Gherkin de 2.1 con pruebas → trazabilidad requisito→prueba (determinista: % de escenarios con step definitions).

### 2.5 Revisión de código
- Señales deterministas vía `gh`: ¿rama principal protegida?, ¿PRs con revisión?, ¿commits directos a main?, tamaño medio de PR. (`gh api repos/O/R/branches/main/protection`).
- Falla vibe coding: commits gigantes "update" directo a main, sin revisión; historial que no permite revertir un cambio aislado.
- Revisión semántica (lógica de negocio, autorización) → **LLM**, pero acotada al diff o a los archivos marcados por las herramientas.

### 2.6 CI/CD y release
- **Existencia y contenido de CI:** `.github/workflows/*.yml` que ejecute lint + typecheck + tests + build en cada PR. Validar workflows con `actionlint` (4.419★, MIT). (La seguridad de GitHub Actions se cubre en otro informe del proyecto.)
- **Hooks locales:** `pre-commit` (15.705★) / `lint-staged` (14.760★).
- **Release:** versionado semántico y changelog automáticos con `semantic-release` (24.180★) o `release-please` (7.783★); commits convencionales (`commitizen/cz-cli`, 17.503★).
- **Falla vibe coding:** deploy manual desde la laptop o "auto-deploy de main" sin ninguna verificación previa; sin entornos separados (dev/staging/prod); variables de entorno pegadas en el código; sin forma de rollback.
- **Google SRE — Launch Coordination Checklist / PRR:** la PRR es el paso inicial típico del modelo de compromiso SRE e identifica necesidades de confiabilidad del servicio (https://sre.google/sre-book/evolving-sre-engagement-model/). El checklist de lanzamiento (https://sre.google/sre-book/launch-checklist/) cubre arquitectura, capacidad/carga, modos de falla, dependencias externas, monitoreo, rollout gradual, backups — **contenido exacto no extraído en esta sesión → NO VERIFICADO literal**, usar como guía.

### 2.7 Operación (DORA metrics)
- DORA usa ahora **cinco métricas** agrupadas en *throughput* (frecuencia de despliegue, lead time de cambio, tiempo de recuperación de despliegue fallido) e *inestabilidad* (tasa de fallo de cambios, tasa de retrabajo de despliegue) (https://dora.dev/guides/dora-metrics/history/ ; https://cd.foundation/blog/2025/10/16/dora-5-metrics/). La fecha exacta de adopción de la 5.ª métrica difiere entre fuentes (2024 según dora.dev).
- `dora-team/fourkeys` (2.235★) está **ARCHIVADO** → no basar el auditor en él; calcular aproximaciones con `gh api` (deploys vía GitHub Deployments/Releases, lead time = merge→deploy, change fail = reverts/hotfixes) — **determinista y barato en tokens**.
- Operación mínima: logs estructurados, manejo de errores con reporte (p. ej., Sentry), health check, backups probados, alertas. Para vibe coding lo típico es "me entero de la caída porque un usuario me escribe".

### 2.8 Documentación
- Determinista: README con instalación/ejecución/variables de entorno, `.env.example` sin valores reales, LICENSE, CHANGELOG, docs/adr.
- LLM: ¿un tercero puede levantar el proyecto solo con el README? (prueba práctica: el auditor intenta seguir el README en sandbox → resultado determinista: build/test pasa o no).

---

## 3. Modelos de madurez existentes y cómo encajan

| Modelo | Qué aporta | Escala original | Uso en auditor-integral | Fuente |
|---|---|---|---|---|
| **ISO/IEC 25010:2023** | Taxonomía de calidad de producto: 9 características (2023) | Sin niveles (modelo de calidad) | Eje "QUÉ se mide": cada hallazgo se etiqueta con su característica. Nombres de las 9 (idoneidad funcional, eficiencia de desempeño, compatibilidad, capacidad de interacción, fiabilidad, seguridad, mantenibilidad, flexibilidad, protección/safety) → **NO VERIFICADO contra texto ISO** (norma de pago); el n.º de 9 sí está en https://www.iso.org/standard/78176.html | ISO |
| **OWASP SAMM v2** | 5 funciones (Gobernanza, Diseño, Implementación, Verificación, Operaciones) × 3 prácticas = 15 prácticas, niveles 1–3 (0 implícito) | 0–3 | Eje de madurez de *proceso* de seguridad; las funciones calzan 1:1 con las fases del ciclo | https://owaspsamm.org/model/ ; https://owaspsamm.org/release-notes-v2/ (repo GitHub `OWASP/samm` archivado; el modelo sigue vigente en el sitio) |
| **Google PRR / Launch checklist** | Lista de verificación operacional antes de lanzar | Pasa/no pasa | Puerta N3→N4 ("listo para usuarios reales") | https://sre.google/sre-book/evolving-sre-engagement-model/ |
| **TRL (Technology Readiness Levels)** | Escala 1–9 de madurez tecnológica (NASA), de "principio observado" a "probado en operación" | 1–9 | Inspiración del lenguaje de "nivel": prototipo (TRL 3–4) → validado en entorno relevante (5–6) → demostrado en entorno operacional (7–9) | https://www.nasa.gov/directorates/somd/space-communications-navigation-program/technology-readiness-levels/ (URL no reabierta en esta sesión → **NO VERIFICADO** enlace exacto) |
| **CMMI** | Madurez de *organización* (Inicial, Gestionado, Definido, Gestionado cuantitativamente, Optimizando) | 1–5 | Solo como analogía: N1–N5 se nombra parecido pero mide el *producto + su pipeline*, no la organización; aplicar CMMI a un proyecto unipersonal es desproporcionado | ISACA/CMMI Institute (NO VERIFICADO URL en esta sesión) |
| **SonarQube quality gate "Sonar way"** | Condiciones sobre código nuevo: sin issues nuevos, 100% hotspots revisados, cobertura ≥80%, duplicación ≤3% (umbral de duplicación varía por versión) | Pasa/falla | Umbrales numéricos de las puertas N3–N4 | https://docs.sonarsource.com/sonarqube-server/10.6/user-guide/quality-gates |
| **DORA (5 métricas)** | Desempeño de entrega y estabilidad | Continuo (arquetipos en 2025, ya no tiers elite/high/...) | Puerta N5 (operación medida) | https://dora.dev/guides/dora-metrics/history/ |

---

## 4. Propuesta: escala N1–N5 "listo para producción" (ESTIMACIÓN — a validar por el investigador)

Principio: **cada nivel es una puerta acumulativa**; no se puede ser N3 sin cumplir todo N1–N2. El nivel global = el **mínimo** entre dominios (código, seguridad, BD, UX, infra…), porque una cadena es tan fuerte como su eslabón más débil. Se reporta además el perfil por dominio (radar) para la hoja de ruta.

| Nivel | Nombre | Pregunta que responde | Puertas del dominio ingeniería (resumen) | Analogía |
|---|---|---|---|---|
| **N1** | Prototipo | ¿Funciona en mi máquina y sé qué quiero? | Repo versionado (git); build/arranque reproducible desde README; flujograma + lista de funcionalidades; sin secretos en el repo; deps existen en el registro | TRL 3–4; SAMM 0→1 |
| **N2** | MVP / demo con usuarios de confianza | ¿Puedo mostrarlo sin que se rompa lo básico? | Lint sin errores; typecheck pasa (TS `strict` o mypy básico); historias + criterios de aceptación para flujos críticos; tests de humo de flujos críticos; CI que corre lint+typecheck+test en cada push; `.env.example`; sin dependencias no usadas/inexistentes | TRL 5; SAMM 1 |
| **N3** | Beta (usuarios reales, datos reales no críticos) | ¿Puedo recibir usuarios reales y corregir rápido? | Cobertura ≥60% global y ≥80% en código nuevo/crítico; duplicación ≤5% global (≤3% nuevo); complejidad ciclomática por función ≤15 (umbral propuesto); sin ciclos de dependencias; ADRs de decisiones clave; C4 nivel 1–2; STRIDE de flujos con datos personales; rama main protegida + PR; entornos dev/prod separados; rollback documentado | TRL 6–7; Sonar way en código nuevo; SAMM 1–2 |
| **N4** | Producción | ¿Puedo operar con SLA y datos sensibles? | Quality gate tipo "Sonar way" verde; mutation score ≥60% en módulos críticos (umbral propuesto); E2E de flujos críticos; release automatizado con versionado semántico y changelog; monitoreo + alertas + logs estructurados; backups probados; checklist PRR completo; pruebas de carga del informe de saturación | TRL 8; PRR aprobado; SAMM 2 |
| **N5** | Escala | ¿Puedo crecer sin degradar y medir mi mejora? | Métricas DORA medidas y con tendencia; SLO/error budget; ADRs al día; arquitectura con reglas de capas verificadas (dependency-cruiser); mutation testing en CI; postmortems; revisión periódica (re-auditoría) | TRL 9; DORA; SAMM 2–3 |

Los umbrales numéricos marcados "propuesto" son **ESTIMACIÓN** del diseño (no provienen de una norma); los de Sonar (80% / 3% / 100% hotspots) sí tienen fuente. Recomendación: dejar los umbrales en un `config/umbrales.yaml` editable, no en el prompt.

### Puntaje y hoja de ruta
1. Cada chequeo devuelve `pass | fail | n/a | unknown` + evidencia (archivo:línea o métrica).
2. Nivel por dominio = mayor N cuyas puertas están todas en `pass`.
3. Nivel global = min(niveles por dominio).
4. Hoja de ruta = lista ordenada de chequeos `fail` del **siguiente** nivel (no de todos), priorizados por severidad × esfuerzo estimado. Esto evita abrumar a un usuario no programador con 300 hallazgos.

---

## 5. Arquitectura de ejecución eficiente en tokens (GUÍA)

1. **Fase 0 — Inventario determinista (0 tokens de código):** detectar stack (package.json, pyproject, lockfiles), contar LOC (`cloc`/`tokei`), listar existencia de artefactos (README, docs/adr, .github/workflows, tests/, .env.example). Salida: `inventario.json`.
2. **Fase 1 — Herramientas CLI en paralelo**, todas a JSON/SARIF en `.auditoria/raw/`: ruff|eslint/biome, tsc|pyright, jscpd, lizard, knip|vulture+deptry, madge|dependency-cruiser, cobertura, ast-grep con reglas anti-IA.
3. **Fase 2 — Normalizador (script, no LLM):** convierte todo a un esquema único `{id, dominio, iso25010, severidad, archivo, linea, regla, herramienta, nivel_gate}` y lo agrega en `hallazgos.json` + métricas en `metricas.json`. Deduplicar por archivo:línea. Aquí se aplican umbrales → asignación N1–N5 **determinista**.
4. **Fase 3 — LLM solo sobre lo resumido:** recibe `metricas.json` + top-N hallazgos + docs (requisitos/ADRs) + diffs de archivos señalados. Tareas LLM: calidad de requisitos y criterios de aceptación, coherencia arquitectura-código, STRIDE, priorización de hoja de ruta, redacción en español del informe. Nunca "lee todo el repo".
5. **Fase 4 — Informe:** escala N, radar por dominio, hoja de ruta del siguiente nivel, evidencia enlazada.

Costo estimado de tokens: dominado por Fase 3; acotable con top-N (p. ej., 50 hallazgos) → **bajo/medio** independientemente del tamaño del repo (ESTIMACIÓN).

---

## 6. Repositorios/herramientas evaluados (datos `gh api`, 2026-11-17)

| Repo | ★ | Licencia | Último push | Estado | Uso |
|---|---|---|---|---|---|
| astral-sh/ruff | 51.421 | MIT | 2026-11-18 | activo | lint Python (SARIF/JSON) |
| eslint/eslint | 27.627 | MIT | 2026-11-17 | activo | lint JS/TS |
| biomejs/biome | 26.131 | Apache-2.0 | 2026-11-18 | activo | lint+format JS/TS rápido |
| microsoft/TypeScript | 111.838 | Apache-2.0 | 2026-11-18 | activo | tsc typecheck |
| python/mypy | 20.725 | NOASSERTION (MIT en la práctica, no verificado) | 2026-11-17 | activo | typecheck Python |
| microsoft/pyright | 15.750 | NOASSERTION | 2026-11-17 | activo | typecheck Python, `--outputjson` |
| kucherenko/jscpd | 6.572 | MIT | 2026-11-17 | activo | duplicación multi-lenguaje |
| terryyin/lizard | 2.604 | NOASSERTION | 2026-11-18 | activo | complejidad multi-lenguaje |
| rubik/radon | 2.045 | MIT | 2024-10-20 | poco activo | complejidad/mantenibilidad Python |
| webpro-nl/knip | 12.687 | ISC | 2026-11-17 | activo | archivos/exports/deps no usados |
| depcheck/depcheck | 4.901 | MIT | 2025-02-27 | **ARCHIVADO** | no usar |
| jendrikseipp/vulture | 4.976 | MIT | 2026-11-16 | activo | código muerto Python |
| osprey-oss/deptry | 1.505 | MIT | 2026-11-17 | activo | deps Python no usadas/faltantes |
| pahen/madge | 10.185 | MIT | 2026-01-21 | activo | ciclos de dependencias |
| sverweij/dependency-cruiser | 7.437 | MIT | 2026-11-17 | activo | reglas de arquitectura/capas |
| ast-grep/ast-grep | 16.616 | MIT | 2026-11-17 | activo | reglas estructurales a medida |
| vitest-dev/vitest | 17.391 | MIT | 2026-11-17 | activo | tests + cobertura |
| jestjs/jest | 45.475 | MIT | 2026-11-16 | activo | tests + cobertura |
| bcoe/c8 | 2.126 | ISC | 2026-11-16 | activo | cobertura V8 |
| pytest-dev/pytest-cov | 2.080 | MIT | 2026-10-18 | activo | cobertura Python |
| stryker-mutator/stryker-js | 3.387 | Apache-2.0 | 2026-11-16 | activo | mutation testing JS/TS |
| boxed/mutmut | 1.545 | BSD-3 | 2026-11-07 | activo | mutation testing Python |
| cucumber/cucumber-js | 5.407 | MIT | 2026-11-17 | activo | aceptación ejecutable (Gherkin) |
| SonarSource/sonarqube | 11.190 | LGPL-3.0 | 2026-11-17 | activo | quality gate (servidor) |
| qltysh/qlty | 3.226 | NOASSERTION | 2026-11-18 | activo | agregador de linters |
| rhysd/actionlint | 4.419 | MIT | 2026-07-16 | activo | valida workflows CI |
| pre-commit/pre-commit | 15.705 | MIT | 2026-11-09 | activo | hooks locales |
| lint-staged/lint-staged | 14.760 | MIT | 2026-11-15 | activo | hooks sobre staged |
| semantic-release/semantic-release | 24.180 | MIT | 2026-11-17 | activo | release automatizado |
| googleapis/release-please | 7.783 | Apache-2.0 | 2026-11-03 | activo | release por PR |
| commitizen/cz-cli | 17.503 | MIT | 2026-11-16 | activo | commits convencionales |
| architecture-decision-record/architecture-decision-record | 17.485 | NOASSERTION | 2026-11-17 | activo | plantillas ADR |
| npryce/adr-tools | 5.781 | NOASSERTION | 2024-04-25 | poco activo | CLI ADR |
| OWASP/threat-dragon | 1.694 | Apache-2.0 | 2026-11-16 | activo | modelado de amenazas |
| OWASP/pytm | 1.201 | NOASSERTION | 2026-11-16 | activo | threat model as code |
| mermaid-js/mermaid | 91.139 | MIT | 2026-11-17 | activo | flujogramas/C4 como texto |
| dora-team/fourkeys | 2.235 | Apache-2.0 | 2024-01-23 | **ARCHIVADO** | no usar; calcular DORA con `gh api` |

---

## 7. Decisiones abiertas para el investigador (no autoseleccionadas)
1. ¿Nivel global = mínimo entre dominios (conservador, recomendado) o media ponderada (más "amable")?
2. ¿Incluir SonarQube (requiere servidor/Docker) desde N4, o mantener todo en CLI locales + qlty?
3. Umbrales "propuestos" (complejidad ≤15, mutation ≥60%, cobertura global ≥60% en N3): ¿aceptar, endurecer o relajar?
4. Stacks soportados en v1: ¿solo JS/TS + Python (lo más común en vibe coding) o también otros?

## Fuentes principales
- GitClear 2025 (vía devclass/leaddev): https://www.devclass.com/ai-ml/2025/02/20/ai-is-eroding-code-quality-states-new-in-depth-report/1626250
- Veracode 2025: https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/
- CodeRabbit 2025: https://www.coderabbit.ai/blog/state-of-AI-vs-human-code-generation-report
- Slopsquatting / Spracklen et al. (CSA): https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419/
- DORA 2025: https://services.google.com/fh/files/misc/2025_state_of_ai_assisted_software_development.pdf ; https://dora.dev/guides/dora-metrics/history/
- METR 2025: https://arxiv.org/abs/2507.09089
- SonarQube quality gates: https://docs.sonarsource.com/sonarqube-server/10.6/user-guide/quality-gates
- OWASP SAMM: https://owaspsamm.org/model/
- Google SRE PRR: https://sre.google/sre-book/evolving-sre-engagement-model/ ; https://sre.google/sre-book/launch-checklist/
- ISO/IEC 25010:2023: https://www.iso.org/standard/78176.html
- C4 model: https://c4model.com

---

## Verificación

Verificador escéptico, 2026-11-17. Repos comprobados con `gh api repos/OWNER/REPO` (estrellas, último push, licencia SPDX, archived); cifras contrastadas con WebFetch sobre la fuente citada.

### Repositorios (37 consultados)

| Resultado | Detalle |
|---|---|
| Existen los 37 | Ninguno inventado. Todos los nombres OWNER/REPO resuelven. |
| Archivados | Solo `depcheck/depcheck` (último push 2025-02-27) y `dora-team/fourkeys` (2024-01-23), y el informe ya los marca "NO USAR". Correcto. |
| Estrellas | Coinciden (diferencias de ±2 por variación diaria: ruff 51.419, ast-grep 16.617). |
| Licencias | Coinciden con GitHub. `NOASSERTION` en pyright, mypy, lizard, qlty, pytm, ADR y adr-tools significa que GitHub no detecta la licencia, no que no la tengan. Hay que revisar el archivo LICENSE antes de redistribuirlas. |
| Poca actividad | `rubik/radon` (último push 2024-10-20), `npryce/adr-tools` (2024-04-25). `pahen/madge` sin push desde 2026-01-21; sigue activo, pero con menos movimiento. |
| Otros verificados | c8 2.126★ ISC; pre-commit 15.705★ MIT; lint-staged 14.760★ MIT; cz-cli 17.503★ MIT; ninguno archivado. |

### Cifras y estudios

| Afirmación | Fuente revisada | Resultado |
|---|---|---|
| GitClear: bloques duplicados ≥5 líneas ~8× en 2024; 211 M líneas; copy/paste > moved | devclass (URL citada) | **VERIFICADO**. La fuente da una caída de *moved lines* de 39,9%. La cifra 24,8%→9,5% del informe no aparece en esta fuente: queda NO VERIFICADO. |
| Veracode 2025: 45% de casos con vulnerabilidad; XSS 86%; log injection 88%; Java >70%; 80 tareas; >100 LLM | press release Veracode | **VERIFICADO** |
| CodeRabbit: 1,7× issues (10,83 vs 6,45 por PR); n=470 (320 IA / 150 humanos) | blog CodeRabbit | 1,7× y n están **VERIFICADOS**. **CORREGIDO:** la fuente no da "1,4× más críticos". Da un rango de 1,4–1,7× para issues *críticos y mayores combinados*. |
| METR: 19% más lentos; creyeron ir 20% más rápido; 16 devs, 246 tareas | arXiv 2507.09089 | **VERIFICADO** (además, antes del estudio pronosticaron −24%) |
| Spracklen et al.: 19,7% de paquetes alucinados; 205.474 nombres únicos; USENIX Security 2025 | arXiv 2406.10279 (abstract) | 205.474 y la venue están **VERIFICADOS**. El abstract reporta un promedio de ≥5,2% (comerciales) y 21,7% (open source). El 19,7% global está **NO VERIFICADO en el abstract** (proviene de una fuente secundaria). Conviene citar 5,2% / 21,7%. |
| Sonar way: sin issues nuevos, 100% hotspots revisados, cobertura ≥80% y duplicación ≤3,0% en código nuevo | docs Sonar 10.6 | **VERIFICADO** para v10.6. La nota "varía por versión" no se comprobó en otras versiones. |
| DORA: 5 métricas (throughput: lead time, frecuencia, recuperación; inestabilidad: change fail rate, rework rate) | dora.dev history | **VERIFICADO** (rework rate se añadió en 2024) |

### Sin verificar en esta pasada
- La URL de TRL de la NASA, la URL de CMMI y el contenido literal del checklist PRR/launch de Google SRE: siguen NO VERIFICADOS, como ya indicaba el informe.
- Los nombres de las 9 características de ISO/IEC 25010:2023 no se contrastaron con el texto ISO, que es de pago.
- Que la IA silencie errores de tipos (`any`, `ts-ignore`) es un patrón sin cifra: NO VERIFICADO cuantitativamente.
- Los umbrales "propuestos" (complejidad ≤15, mutation ≥60%, cobertura global ≥60%) son una ESTIMACIÓN de diseño y no salen de ninguna norma.

### Conclusión
No hay repos inventados ni archivados sin marcar. Se corrigen dos errores menores de cifra: el multiplicador de críticos de CodeRabbit y la precisión del 19,7% de Spracklen. Todo lo demás queda verificado.
