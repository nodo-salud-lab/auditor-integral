# 12 — Umbrales con evidencia de industria (DECISIÓN 2)

Fecha: 2026-11-18. Alcance: cada umbral de `config/umbrales.toml` y de la tabla §4.3 del PLAN_MAESTRO, más los que la tabla nombra sin número (complejidad cognitiva, longitud de función y archivo, Lighthouse, bundle, p95, tasa de error, recuperación, edad de dependencias, cortes CVSS).
Producto: propuesta en `investigacion/propuestas/umbrales.toml` (no se tocó `config/`, `catalogo/` ni `scripts/`).

**Método (GUÍA).** Para cada umbral se buscó, en este orden: (1) norma o guía publicada (W3C, FIRST, web.dev, Google), (2) valor por defecto documentado o en el código fuente de la herramienta más adoptada (leído con `gh api` cuando fue posible), (3) si no hay ninguna, el umbral queda como `propuesta` (ESTIMACIÓN) con la evidencia de apoyo que exista. Todas las URL se leyeron el 2026-11-18. Lo que no se pudo confirmar se marca **NO VERIFICADO**.

**Etiquetas de `origen`:** `norma` = norma, especificación o guía publicada · `default-herramienta` = valor por defecto de una herramienta ampliamente adoptada · `propuesta` = decisión de diseño del investigador.

---

## 1. Resultado resumido

| Umbral (clave) | Valor actual | Valor con evidencia | Origen propuesto | Fuente principal | Cambio |
|---|---|---|---|---|---|
| `cobertura_codigo_nuevo` | ≥ 80 % | ≥ 80 % | default-herramienta | Sonar way ([docs](https://docs.sonarsource.com/sonarqube-server/10.6/user-guide/quality-gates)) | Reetiquetado (era `norma`) |
| `duplicacion_codigo_nuevo` | ≤ 3 % | ≤ 3 % | default-herramienta | Sonar way (misma URL) | Reetiquetado |
| `cobertura_global` | ≥ 60 % | ≥ 60 % (75 / 90 informativos) | norma (guía) | [Google Testing Blog 2020](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html) | Ahora con fuente |
| `duplicacion_global` | ≤ 5 % | ≤ 5 % | propuesta | [jscpd README](https://github.com/kucherenko/jscpd) (ejemplo, no default) | Fuente de apoyo |
| `complejidad_ciclomatica_max` | ≤ 15 | ≤ 15 | default-herramienta | [lizard `options.py`](https://github.com/terryyin/lizard/blob/master/lizard_core/options.py) | Ahora con fuente |
| `complejidad_cognitiva_max` | — | ≤ 15 | default-herramienta | [SonarJS S3776](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S3776/config.ts) | **Nuevo** |
| `funcion_lineas_max` | — | ≤ 200 (alt. 50 / 1000) | default-herramienta | [SonarJS S138](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S138/config.ts) | **Nuevo**, sin consenso |
| `archivo_lineas_max` | — | ≤ 1000 (alt. 300) | default-herramienta | [SonarJS S104](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S104/config.ts) | **Nuevo**, sin consenso |
| `ts_any_explicitos_max` / `ts_ignore_max` | — | 0 / 0 | default-herramienta | [typescript-eslint recommended](https://typescript-eslint.io/rules/no-explicit-any/) | **Nuevo** (COD-TIPOS) |
| `mutacion_criticos` | ≥ 60 % | ≥ 60 % (alt. 80) | default-herramienta | [StrykerJS thresholds](https://stryker-mutator.io/docs/stryker-js/configuration/) | Ahora con fuente |
| `cwv_lcp_p75` / `inp` / `cls` | 2,5 s / 200 ms / 0,1 | igual | norma | [web.dev](https://web.dev/articles/defining-core-web-vitals-thresholds) | Confirmado |
| `lcp_laboratorio_n2` | < 4 s | < 4 s | propuesta | web.dev (límite "poor" de campo) | Confirmado el número |
| `lighthouse_performance_min` | — | ≥ 90 (alt. 80) | default-herramienta | [Lighthouse scoring](https://developer.chrome.com/docs/lighthouse/performance/performance-scoring) | **Nuevo** |
| `lighthouse_accesibilidad_min` | — | ≥ 90 | propuesta | [LHCI configuration](https://github.com/GoogleChrome/lighthouse-ci/blob/main/docs/configuration.md) | **Nuevo** |
| `objetivo_tactil_min` | 24 px | 24 px | norma | [WCAG 2.2 SC 2.5.8](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html) | Confirmado |
| `axe_critical_n2` / `axe_serious_n3` | 0 / 0 | 0 / 0 | propuesta | [axe-core API](https://github.com/dequelabs/axe-core/blob/develop/doc/API.md) | Fuente de apoyo |
| `sus_n4` | ≥ 68 | ≥ 68 | norma (benchmark publicado) | [MeasuringU](https://measuringu.com/sus/) | Ahora con fuente |
| `bundle_chunk_max_kb` | — | ≤ 500 kB | default-herramienta | [Vite build options](https://vite.dev/config/build-options) | **Nuevo** |
| `peso_pagina_max_kib` | — | ≤ 5000 KiB | default-herramienta | [Lighthouse total-byte-weight](https://developer.chrome.com/docs/lighthouse/performance/total-byte-weight) | **Nuevo** |
| `latencia_p95_ms` | — | ≤ 500 ms | propuesta | [SRE Workbook](https://sre.google/workbook/implementing-slos/) (ejemplos) | **Nuevo** |
| `tasa_error_max` | — | ≤ 1 % | propuesta | SRE Workbook (ejemplos 97 / 99,9 / 99,99 %) | **Nuevo** |
| `recuperacion_despliegue_fallido_h` | — | < 24 h (Elite < 1 h) | norma (benchmark) | [DORA 2024, p. 13](https://services.google.com/fh/files/misc/2024_final_dora_report.pdf) | **Nuevo** |
| `cvss_critico_min` / `alto` / `medio` | — | 9,0 / 7,0 / 4,0 | norma | [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document), [v4.0](https://www.first.org/cvss/v4.0/specification-document) | **Nuevo** |
| `dependencia_edad_min_horas` | — | ≥ 24 h (alt. 72 h) | default-herramienta (solo pnpm ≥ 11) | [pnpm minimumReleaseAge](https://pnpm.io/settings/dependency-resolution) | **Nuevo** |
| `dependencia_sin_mantenimiento_dias` | — | ≤ 90 días | default-herramienta | [OpenSSF Scorecard Maintained](https://github.com/ossf/scorecard/blob/main/docs/checks.md) | **Nuevo** |

Conteo en la propuesta (45 umbrales, corregido en la verificación): 11 `norma`, 15 `default-herramienta`, 19 `propuesta`. De las 19 propuestas, 9 son parámetros internos de orquestación (timeouts, límites de evidencia, triage), que por naturaleza no tienen referencia externa.

**Ningún valor numérico existente cambia.** Cambian 7 etiquetas de `origen` (incluye `lighthouse_corridas`, reetiquetado en la verificación) y se agregan 18 claves. Las claves y campos actuales se conservan, así que `gates.py` y `score.py` siguen leyendo `umbral.<clave>.valor` igual. Se agregan dos campos opcionales: `alternativas` y `verificado`.

---

## 2. Evidencia por umbral

### 2.1 Código (COD)

**Cobertura y duplicación en código nuevo (Sonar way).** El quality gate integrado "Sonar way" tiene cuatro condiciones sobre código nuevo: no hay issues nuevos, todos los security hotspots están revisados, la cobertura es ≥ 80,0 % y la duplicación es ≤ 3,0 % ([SonarSource](https://docs.sonarsource.com/sonarqube-server/10.6/user-guide/quality-gates)). Corrección: el archivo actual los etiqueta como `norma`, pero son el **default de una herramienta**, no una norma. Se reetiquetan a `default-herramienta`.

**Cobertura global.** Google Testing Blog (2020): sin un número ideal, la guía interna de Google es 60 % "acceptable", 75 % "commendable" y 90 % "exemplary", y la propia guía se aleja de los mandatos de arriba hacia abajo ([fuente](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html), texto leído directamente del HTML). El 60 % del plan coincide con "acceptable". Se agrega `cobertura_global_destacable = 75` solo como dato informativo para la hoja de ruta, no como compuerta.

**Duplicación global.** No hay un default de industria. jscpd no trae umbral por defecto. Super Linter y MegaLinter lo corren con `threshold: 0`, y el README de jscpd lo desaconseja porque falla con clones heredados. El ejemplo oficial de la GitHub Action usa `threshold: 5`, y los adoptantes listados en el README usan 4-5 % ([jscpd](https://github.com/kucherenko/jscpd)). Se mantiene 5 % como `propuesta` con ese apoyo. El README recomienda además medir solo la duplicación **nueva** (`--fail-on-new-clones 0`), lo que coincide con el enfoque de Sonar.

**Complejidad ciclomática por función.** Los defaults no coinciden:
- lizard: `DEFAULT_CCN_THRESHOLD = 15`, en el código fuente ([options.py](https://github.com/terryyin/lizard/blob/master/lizard_core/options.py), línea 12) y en `docs/cli.rst`.
- ESLint `complexity`: default 20 ([eslint](https://eslint.org/docs/latest/rules/complexity)).
- SonarJS S1541: default 10 ([config.ts](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S1541/config.ts)), pero **no está** en el perfil "Sonar way" (campo `defaultQualityProfiles` vacío en `S1541.json`).

Se propone 15, porque lizard es la herramienta del plan (§8.1). Las alternativas quedan registradas.

**Complejidad cognitiva (nuevo).** SonarJS S3776 tiene default 15 y **sí** está en "Sonar way" ([config.ts](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S3776/config.ts); `S3776.json` lista "Sonar way"). Un empleado de SonarSource explicó en el foro que el 15 se eligió de forma empírica, partiendo de 10 y subiéndolo para reducir ruido en proyectos open source, y que no hay una fórmula detrás ([foro Sonar](https://community.sonarsource.com/t/s3776-reason-for-the-current-default-value-of-15/127103); lectura vía resumen de búsqueda, **cita textual NO VERIFICADA**). lizard coincide: su extensión `-Ecognitive` usa `DEFAULT_COGNITIVE_THRESHOLD = 15` ([lizardcognitive.py](https://github.com/terryyin/lizard/blob/master/lizard_ext/lizardcognitive.py), verificado con `gh api`).

**Longitud de función y de archivo (nuevo).** No hay consenso entre herramientas, y ninguna de estas reglas está en una configuración "recommended" o en "Sonar way".

| Herramienta | Función | Archivo |
|---|---|---|
| ESLint | `max-lines-per-function` 50 | `max-lines` 300 |
| SonarJS | S138: 200 | S104: 1000 |
| lizard | `-L`: 1000 (NLOC) | — |

Fuentes: [max-lines-per-function](https://eslint.org/docs/latest/rules/max-lines-per-function), [max-lines](https://eslint.org/docs/latest/rules/max-lines), [S138](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S138/config.ts), [S104](https://github.com/SonarSource/SonarJS/blob/master/packages/analysis/src/jsts/rules/S104/config.ts), [lizard options.py](https://github.com/terryyin/lizard/blob/master/lizard_core/options.py).

La propuesta usa los valores de SonarJS (200 y 1000) porque generan menos ruido en código generado por IA. **Esto es una elección entre defaults y la decide el investigador.**

**Tipado (nuevo, COD-TIPOS).** La configuración `recommended` de typescript-eslint incluye `no-explicit-any` (reporta todo `any` explícito) y `ban-ts-comment`, con `ts-ignore: true`, `ts-nocheck: true`, `ts-expect-error: 'allow-with-description'` y `minimumDescriptionLength: 3` ([no-explicit-any](https://typescript-eslint.io/rules/no-explicit-any/), [ban-ts-comment](https://typescript-eslint.io/rules/ban-ts-comment/)). Por eso el default de la herramienta equivale a un umbral de 0.

**Mutation score.** El default de StrykerJS es `thresholds: { high: 80, low: 60, break: null }` ([Stryker](https://stryker-mutator.io/docs/stryker-js/configuration/)). El 60 % del plan coincide con `low`. Matiz: como `break` es `null`, Stryker no falla por defecto, así que convertir el 60 en compuerta sigue siendo una decisión de diseño apoyada en un default.

### 2.2 Usabilidad y frontend (UX)

**Core Web Vitals.** Se confirman los valores en p75 de campo: LCP "good" ≤ 2500 ms y "poor" > 4000 ms; INP ≤ 200 ms y > 500 ms; CLS ≤ 0,1 y > 0,25 ([web.dev](https://web.dev/articles/defining-core-web-vitals-thresholds)). El "LCP lab < 4 s" de N2 usa el límite "poor" de **campo** en laboratorio, por lo que sigue como `propuesta`.

**Lighthouse.**
- Performance: bandas 0-49 "Poor", 50-89 "Needs Improvement" y 90-100 "Good". Pesos en Lighthouse 10: FCP 10 %, SI 10 %, LCP 25 %, TBT 30 %, CLS 25 % ([scoring](https://developer.chrome.com/docs/lighthouse/performance/performance-scoring)). La página solo documenta Lighthouse 10, pero el código fuente vigente (`core/config/default-config.js`, rama principal; última versión publicada v13.6.0) mantiene FCP 10, LCP 25, TBT 30, CLS 25 y SI 10 (verificado con `gh api`).
- Accesibilidad: es un promedio ponderado de auditorías pasa/falla, con pesos derivados del impacto axe ([a11y scoring](https://developer.chrome.com/docs/lighthouse/accessibility/scoring)). Esa página **no** publica bandas de color, así que aplicar el ≥ 90 a accesibilidad queda **NO VERIFICADO** como default.
- LHCI: el preset `lighthouse:recommended` exige puntaje perfecto en toda auditoría fuera de performance y advierte cuando las métricas bajan de 90. La aserción `categories:performance minScore 0.9` aparece solo como ejemplo, no como default ([LHCI configuration](https://github.com/GoogleChrome/lighthouse-ci/blob/main/docs/configuration.md)).

Propuesta: performance ≥ 90 (`default-herramienta`, banda "Good") y accesibilidad ≥ 90 (`propuesta`). El informe 05 proponía 80 para performance móvil; la elección entre 90 y 80 es del investigador.

**axe.** axe-core define cuatro impactos (minor, moderate, serious, critical) y no fija un umbral ([API](https://github.com/dequelabs/axe-core/blob/develop/doc/API.md)). Los valores "0 critical en N2" y "0 serious en N3" siguen como `propuesta`. Apoyo indirecto: el preset recomendado de LHCI exige 100 en cada auditoría de accesibilidad.

**Objetivo táctil.** WCAG 2.2 SC 2.5.8 (nivel AA) exige un objetivo de al menos 24 × 24 px CSS, con excepciones ([W3C Understanding](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)). Confirmado.

**Viewports de reflow.** La lista 360/768/1280 no tiene fuente estándar. WCAG 2.2 SC 1.4.10 Reflow (AA) exige que el contenido de scroll vertical funcione a un ancho equivalente a 320 px CSS ([W3C Understanding 1.4.10](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html), verificado). Se recomienda agregar 320 a la lista (queda como alternativa en la propuesta).

**SUS 68.** MeasuringU: el promedio de SUS en 500 estudios es 68 ([MeasuringU](https://measuringu.com/sus/)). El informe 05 añade que 68 corresponde al percentil 50 ([MeasuringU p=170](https://measuringu.com/?p=170)). Se etiqueta `norma` en el sentido de referencia empírica publicada, no de norma formal. El mínimo de 5 usuarios por perfil queda **NO VERIFICADO** (sin fuente primaria en esta revisión).

**Bundle (nuevo).** Vite, el stack del proyecto: `build.chunkSizeWarningLimit` tiene default 500 kB, medido sobre el tamaño sin comprimir ([Vite](https://vite.dev/config/build-options)). Angular CLI coincide: budget `initial` con advertencia en 500 kB y error en 1 MB ([Angular](https://angular.dev/tools/cli/build)). El peso total de página lo marca Lighthouse sobre 5.000 KiB; la mediana de HTTP Archive citada en la misma página es 1.700-1.900 KiB ([Lighthouse](https://developer.chrome.com/docs/lighthouse/performance/total-byte-weight)).

### 2.3 Escala, SLO y recuperación (ESC, OPS)

**Latencia p95 y tasa de error.** No existe un valor universal. El Google SRE Workbook sostiene que el SLO sale del producto y da ejemplos:
- Latencia de API: "90 % de requests < 450 ms" y "99 % < 900 ms".
- Disponibilidad: 97 % para una API de ejemplo, 99,9 % para un tier Free y 99,99 % para un tier Premium.

Fuente: [SRE Workbook, Implementing SLOs](https://sre.google/workbook/implementing-slos/). Los valores p95 ≤ 500 ms y error ≤ 1 % son `propuesta` y solo se aplican cuando el proyecto no declaró su propio SLO. El catálogo ya exige declararlo (ESC-SLO).

**Tiempo de restauración.** En el informe DORA 2024 (p. 13, clústeres emergentes de la encuesta), el *failed deployment recovery time* es menor a 1 hora en Elite, menor a 1 día en High y Medium, y de 1 semana a 1 mes en Low ([PDF](https://services.google.com/fh/files/misc/2024_final_dora_report.pdf); tabla leída del PDF con pdftotext). Se propone < 24 h (nivel High/Medium) con la alternativa de < 1 h. **Advertencia:** esta métrica no es el RTO de restauración de la base de datos (DAT-RESTORE). Para el RTO no se encontró un valor de industria: lo declara el dueño (OPS-RPO-RTO).

### 2.4 Dependencias y CVE (SEG)

**Cortes CVSS.** La escala cualitativa de FIRST es idéntica en v3.1 (tabla 14) y v4.0 (tabla 22): None 0,0; Low 0,1-3,9; Medium 4,0-6,9; High 7,0-8,9; Critical 9,0-10,0 ([v3.1](https://www.first.org/cvss/v3.1/specification-document), [v4.0](https://www.first.org/cvss/v4.0/specification-document)). Así quedan fijados SEG-DEPS-CVE-CRIT (≥ 9,0, N2) y SEG-DEPS-CVE-ALTO (≥ 7,0, N4).

**Edad de dependencias.** Son dos conceptos distintos:
- **Edad mínima de publicación** (anti-slopsquatting): pnpm `minimumReleaseAge` tiene default 1440 minutos, es decir, 1 día, en la documentación vigente (pnpm 11) ([pnpm](https://pnpm.io/settings/dependency-resolution)). **Corrección:** en pnpm 10 (desde v10.16.0) el default era 0, o sea, desactivado (`versioned_docs/version-10.x/settings.md` del repo `pnpm/pnpm.io`). El 1 día es default solo en pnpm ≥ 11. El preset de Renovate `security:minimumReleaseAgeNpm` espera 3 días ([Renovate](https://docs.renovatebot.com/presets-security/)).
- **Dependencia abandonada:** el check "Maintained" de OpenSSF Scorecard usa una ventana de 90 días y da el puntaje máximo con al menos un commit por semana. Scorecard no recomienda un puntaje global mínimo ([Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md)). Esto afecta a SEG-SCORECARD: el "umbral acordado" del catálogo no tiene un default de industria y debe decidirlo el investigador.

---

## 3. Decisiones que quedan para el investigador

Son elecciones entre valores con fuente, no vacíos de evidencia:
1. Longitud de función: 50 (ESLint), 200 (SonarJS) o 1000 (lizard). Longitud de archivo: 300 (ESLint) o 1000 (SonarJS).
2. Complejidad ciclomática: 15 (lizard), 20 (ESLint) o 10 (SonarJS, fuera de Sonar way).
3. Lighthouse performance móvil: 90 (banda "Good") u 80 (informe 05).
4. Tiempo de recuperación: < 24 h o < 1 h (Elite).
5. p95, tasa de error y duplicación global: siguen como `propuesta`. Solo hay ejemplos o adopción parcial que los respalden.
6. Puntaje mínimo de OpenSSF Scorecard para N5: sin default publicado.

## 4. Lo que quedó NO VERIFICADO
- Si las bandas 0-49 / 50-89 / 90-100 de Lighthouse se aplican también a la categoría de accesibilidad.
- ~~Los pesos de performance de Lighthouse en versiones posteriores a la 10~~ → resueltos: sin cambios en el código vigente.
- ~~El umbral cognitivo por defecto de lizard~~ → resuelto: 15.
- ~~El ancho de 320 px de WCAG 1.4.10~~ → resuelto: 320 px CSS, nivel AA.
- La fuente primaria del mínimo de 5 usuarios por perfil para SUS.
- ~~El número de corridas por defecto de LHCI~~ → resuelto: 3.
- La cita textual del foro de SonarSource sobre el origen del 15 (se leyó vía resumen de búsqueda).

## 5. Aplicación
Para adoptar la propuesta: revisar la sección 3 y luego copiar `investigacion/propuestas/umbrales.toml` sobre `config/umbrales.toml`. Lo hace el proceso que construye el código, con la aprobación del investigador. Las 18 claves nuevas solo tienen efecto cuando `controles.toml` o los checks las referencien. Hoy `score.py` solo lee `cobertura_controles_puntaje`.

---

## Verificación

Verificador escéptico, 2026-11-18. Cada cifra se volvió a leer en la fuente primaria con `gh api` (código fuente o docs en el repositorio) o WebFetch. Las correcciones ya se aplicaron en este archivo y en `investigacion/propuestas/umbrales.toml`. La propuesta sigue siendo TOML válido (se comprobó con `tomllib`).

| # | Afirmación | Fuente consultada | Resultado |
|---|---|---|---|
| 1 | Sonar way: cobertura ≥ 80,0 % y duplicación ≤ 3,0 % en código nuevo | [docs SonarQube 10.6](https://docs.sonarsource.com/sonarqube-server/10.6/user-guide/quality-gates) (WebFetch) | CONFIRMADO |
| 2 | Google: 60 / 75 / 90 % = acceptable / commendable / exemplary | [Google Testing Blog](https://testing.googleblog.com/2020/08/code-coverage-best-practices.html) (HTML con curl) | CONFIRMADO. Se agregó el matiz del mismo texto: 90 % es un límite inferior razonable para la cobertura por commit |
| 3 | lizard: CCN 15 y longitud de función 1000 | [options.py línea 12](https://github.com/terryyin/lizard/blob/master/lizard_core/options.py) (`DEFAULT_CCN_THRESHOLD, DEFAULT_MAX_FUNC_LENGTH = 15, 1000`) | CONFIRMADO |
| 4 | Umbral cognitivo de lizard (estaba NO VERIFICADO) | [lizardcognitive.py](https://github.com/terryyin/lizard/blob/master/lizard_ext/lizardcognitive.py) (`DEFAULT_COGNITIVE_THRESHOLD = 15`) | RESUELTO: 15, coincide con SonarJS |
| 5 | ESLint: `complexity` 20, `max-lines` 300, `max-lines-per-function` 50 | `eslint/eslint` `lib/rules/*.js` (gh api: `THRESHOLD_DEFAULT = 20`, `defaultOptions: [300]`, `defaultOptions: [50]`) | CONFIRMADO |
| 6 | SonarJS: S3776 = 15 (en Sonar way), S1541 = 10, S138 = 200, S104 = 1000 (fuera de Sonar way) | `SonarSource/SonarJS`: `config.ts` y `S*.json` (`defaultQualityProfiles`) | CONFIRMADO. S3776 también figura en el perfil "Sonar agentic AI" |
| 7 | StrykerJS: thresholds `{high: 80, low: 60, break: null}` | `stryker-mutator/stryker-js` `packages/api/schema/stryker-core.json` | CONFIRMADO |
| 8 | Core Web Vitals p75: LCP 2,5 / 4 s; INP 200 / 500 ms; CLS 0,1 / 0,25 | [web.dev](https://web.dev/articles/defining-core-web-vitals-thresholds) | CONFIRMADO |
| 9 | Pesos de Lighthouse posteriores a la v10 (estaba NO VERIFICADO) | `GoogleChrome/lighthouse` `core/config/default-config.js` (rama principal; última versión v13.6.0) | RESUELTO: FCP 10, SI 10, LCP 25, TBT 30, CLS 25, sin cambios. Bandas 0-49 / 50-89 / 90-100 confirmadas en la [página de scoring](https://developer.chrome.com/docs/lighthouse/performance/performance-scoring) |
| 10 | LHCI `numberOfRuns` por defecto (estaba NO VERIFICADO) | [LHCI configuration.md](https://github.com/GoogleChrome/lighthouse-ci/blob/main/docs/configuration.md) (`[default: 3]`) | RESUELTO: 3. `lighthouse_corridas` pasa de `propuesta` a `default-herramienta` |
| 11 | WCAG 1.4.10: 320 px (estaba NO VERIFICADO) | [W3C Understanding Reflow](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html) | RESUELTO: 320 px CSS, nivel AA. Se agregó como alternativa en `viewports_reflow` |
| 12 | Vite `chunkSizeWarningLimit` = 500 | `vitejs/vite` `docs/config/build-options.md` | CONFIRMADO |
| 13 | Lighthouse marca > 5.000 KiB; mediana HTTP Archive 1.700-1.900 KiB | [total-byte-weight](https://developer.chrome.com/docs/lighthouse/performance/total-byte-weight) | CONFIRMADO |
| 14 | pnpm `minimumReleaseAge` default 1440 min | `pnpm/pnpm.io`: `docs/settings/dependency-resolution.md` (1440) frente a `versioned_docs/version-10.x/settings.md` (0, desde v10.16.0) | **CORREGIDO**: es default solo en pnpm ≥ 11. En pnpm 10 el default es 0 (desactivado) |
| 15 | Renovate `security:minimumReleaseAgeNpm` = 3 días | `renovatebot/renovate` `lib/config/presets/internal/security.preset.ts` (`minimumReleaseAge: '3 days'`) | CONFIRMADO |
| 16 | Scorecard Maintained: ventana de 90 días, ≥ 1 commit por semana | `ossf/scorecard` `docs/checks.md`, línea 415 | CONFIRMADO |
| 17 | CVSS: Low 0,1-3,9; Medium 4,0-6,9; High 7,0-8,9; Critical 9,0-10,0 | [FIRST CVSS v4.0, tabla 22](https://www.first.org/cvss/v4.0/specification-document) | CONFIRMADO (la tabla 14 de v3.1 no se releyó) |
| 18 | DORA 2024 p. 13: recovery Elite < 1 h; High y Medium < 1 día; Low 1 semana a 1 mes | [PDF DORA 2024](https://services.google.com/fh/files/misc/2024_final_dora_report.pdf) (pdftotext, p. 13) | CONFIRMADO |
| 19 | SUS: promedio 68 en 500 estudios | [MeasuringU](https://measuringu.com/sus/) | CONFIRMADO |
| 20 | typescript-eslint `ban-ts-comment` en recommended: ts-ignore y ts-nocheck = true; ts-expect-error con descripción; mínimo 3 caracteres | [typescript-eslint](https://typescript-eslint.io/rules/ban-ts-comment/) | CONFIRMADO |

**Correcciones aplicadas:**
1. pnpm `minimumReleaseAge`: se acotó a pnpm ≥ 11, porque en pnpm 10 el default es 0. El valor de 24 h se mantiene, pero ahora su respaldo depende de la versión. Si el proyecto usa pnpm 10 o npm, funciona como `propuesta` y el investigador decide.
2. `lighthouse_corridas` se reetiquetó a `default-herramienta`, porque el default 3 de LHCI quedó verificado. El conteo pasa a 11 `norma`, 15 `default-herramienta` y 19 `propuesta`.
3. Cuatro ítems NO VERIFICADO quedaron resueltos: el cognitivo de lizard (15), los pesos de Lighthouse posteriores a la v10, los 320 px de WCAG 1.4.10 y las corridas de LHCI.
4. `viewports_reflow` incluye ahora la alternativa con 320 px y su fuente.

**Siguen NO VERIFICADOS:** las bandas de color aplicadas a la categoría accesibilidad de Lighthouse, la fuente primaria del mínimo de 5 usuarios por perfil en SUS, la cita textual del foro de SonarSource y la tabla 14 de CVSS v3.1 (solo se releyó la v4.0). Tampoco se releyeron los defaults de Angular CLI ni el ejemplo `threshold: 5` del README de jscpd.

**Sin errores numéricos:** ningún valor de la propuesta resultó falso. El único hallazgo sustantivo es el alcance por versión del default de pnpm.
