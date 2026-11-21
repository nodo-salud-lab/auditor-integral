# 11 · Pesos del puntaje 0-100 y del IUA basados en plataformas similares

Fecha: 2026-11-18. Responde a DECISIONES.md #1 ("basarlos en evidencia y en plataformas similares, no en pesos inventados"). Este informe **no modifica** `config/pesos.toml`: la propuesta está en `investigacion/propuestas/pesos.toml` y la adopción la decide el investigador.

Sellos: **SÍNTESIS** = evidencia verificada integrada · **ESTIMACIÓN** = inferencia con supuestos declarados · **GUÍA** = paso de implementación. Lo que no pude comprobar va marcado **NO VERIFICADO**.

---

## 1. Resumen

1. **Pesos por severidad (score.py):** la única plataforma revisada que publica pesos numéricos por nivel de riesgo para **promediar controles binarios o cuasi binarios** es OpenSSF Scorecard: Critical 10, High 7,5, Medium 5, Low 2,5 (verificado en el código fuente). Lighthouse publica una segunda escala, también verificada, para reglas de accesibilidad según el impacto axe: 10 / 7 / 3 / 1. Propongo Scorecard como valor por defecto y Lighthouse-axe como alternativa. Los pesos actuales (10/5/2/1) **no tienen fuente**.
2. **Peso `info` = 0:** lo respaldan Sonar (en modo MQR los issues *info* no bajan el rating de A) y Lighthouse (las reglas experimentales pesan 0).
3. **Pesos entre dominios:** ninguna plataforma revisada publica pesos entre dominios equivalentes a SEG/DAT/COD/UX/INF/ESC/OPS. Scorecard junta todos los checks en una sola media ponderada por riesgo; SonarQube no agrega sus ratings. Propongo **agrupar al estilo Scorecard** (cada dominio pesa lo que pesan sus controles evaluados) y dejar los **pesos iguales entre dominios** como alternativa declarada (ESTIMACIÓN sin evidencia).
4. **Multiplicador ×1,5 para SEG/DAT con salud o pagos:** tiene un precedente numérico exacto en CVSS v3.1 (Security Requirements: High = 1,5). CVSS v4.0 abandonó los multiplicadores, así que el precedente es histórico; se declara así.
5. **Limitación estructural detectada:** con cualquier esquema de pesos, una media compensatoria casi no cambia cuando falla **un** control crítico (≈ 99/100 sobre el catálogo completo, §5). SonarQube (rating = peor issue abierto) y SSL Labs (topes de nota) resuelven esto con reglas **no compensatorias**. Propongo agregar un **rating A-E por dominio al estilo Sonar**, que se muestre junto al puntaje.
6. **IUA:** ninguna plataforma combina accesibilidad, rendimiento, teclado, etc., en un solo índice; Lighthouse reporta sus categorías por separado. Los pesos entre componentes del IUA (25/15/15/15/15/15) quedan como **ESTIMACIÓN**; propongo pesos iguales como alternativa neutral. Para el componente de accesibilidad propongo reemplazar las penalizaciones 25/10/3 (sin fuente) por **la fórmula verificada de Lighthouse**: media ponderada pass/fail de reglas axe con pesos 10/7/3/1.

---

## 2. Evidencia por plataforma (SÍNTESIS)

### 2.1 OpenSSF Scorecard: pesos por nivel de riesgo

- **Código:** `pkg/scorecard/scorecard_result.go`, función `GetAggregateScore`:
  `weights := map[string]float64{"Critical": 10, "High": 7.5, "Medium": 5, "Low": 2.5}`
  Se verificó con `gh api` el 2026-11-18 en el commit `e78ecbbade8f79491d71125c14409065a69d6b4c` (último que toca el archivo).
  URL: https://github.com/ossf/scorecard/blob/e78ecbbade8f79491d71125c14409065a69d6b4c/pkg/scorecard/scorecard_result.go
- **Agregación:** `score = Σ(peso_riesgo × puntaje_check) / Σ peso_riesgo`. Los checks **inconclusos** (puntaje < mínimo) **se excluyen** del numerador y del denominador (`continue`). Si ninguno es concluyente, el resultado es inconcluso. Es la misma regla que ya usa `score.py` con `no_evaluado` (se excluye y se informa la cobertura aparte).
- **Asignación de riesgo:** `docs/checks/internal/checks.yaml` (https://github.com/ossf/scorecard/blob/main/docs/checks/internal/checks.yaml). Critical: Dangerous-Workflow y Webhooks. High: Maintained, Dependency-Update-Tool, Binary-Artifacts, Branch-Protection, Code-Review, Signed-Releases, Token-Permissions y Vulnerabilities. Medium: Fuzzing, Packaging, Pinned-Dependencies, SAST, SBOM y Security-Policy. Low: CI-Tests, CII-Best-Practices, Contributors y License.
- **Pertinencia:** es el análogo más cercano al auditor, porque son checks de prácticas de seguridad del repositorio, con un nivel de riesgo fijo por check, agregados en un número 0-10. La diferencia es que en Scorecard cada check puntúa 0-10 y en el auditor cada control es pass/fail (0 o 1). La fórmula vale igual.
- **Observación:** el código dice "aggregate score changes depending on which checks are run": el puntaje depende del subconjunto evaluado. Es la misma razón por la que el plan exige mostrar la cobertura junto al puntaje.

### 2.2 Lighthouse (rama main al 2026-11-18; última release v13.6.0)

Fuente primaria: `core/config/default-config.js`, commit `5d395351e8953c8e79ceea5246ed5b198b588d1d`: https://github.com/GoogleChrome/lighthouse/blob/5d395351e8953c8e79ceea5246ed5b198b588d1d/core/config/default-config.js

*Corrección de verificación (2026-11-18):* ese commit **no es** la release v13.6.0. Es el último commit de `main` que toca el archivo (10-11-2026) y va 31 commits por delante del tag `v13.6.0` (commit `edc407d72179bbc4d4de8a40ef0311ca87dff89c`, publicado el 27-10-2026). Comparé el archivo en ambos commits: solo difiere el orden y la lista de *gatherers*; los pesos de rendimiento y de accesibilidad son **idénticos**. URL fijada a la release: https://github.com/GoogleChrome/lighthouse/blob/edc407d72179bbc4d4de8a40ef0311ca87dff89c/core/config/default-config.js

**Rendimiento:** FCP 10, LCP 25, TBT 30, CLS 25, SI 10. INP pesa 0 en laboratorio y los *insights* pesan 0. Coincide con la documentación (que rotula la tabla como "Lighthouse 10" y no publica una tabla distinta para versiones posteriores): https://developer.chrome.com/docs/lighthouse/performance/performance-scoring. Cada métrica se convierte en un puntaje 0-100 con una curva log-normal construida con datos de HTTP Archive. Bandas: 0-49 pobre, 50-89 mejorable, 90-100 bueno.

**Accesibilidad:** el comentario del archivo de configuración publica la tabla que deriva cada peso del impacto axe y de las etiquetas de la regla:

| Impacto axe | WCAG A/AA | best-practice (sin etiqueta WCAG) | experimental |
|---|---|---|---|
| Minor | 1 | 0 | 0 |
| Moderate | 3 | 3 | 0 |
| Serious | 7 | 7 | 0 |
| Critical | 10 | 10 | 0 |

La documentación (https://developer.chrome.com/docs/lighthouse/accessibility/scoring) confirma que el puntaje es "a weighted average of all accessibility audits" y que cada auditoría es pass/fail, **sin crédito parcial**. La documentación muestra 3/7/10. El peso 1 de *minor* aparece solo en el código y **sí se usa**: `aria-deprecated-role` pesa 1 (comentario "Minor, wcag2a"). *Corrección de verificación:* la versión anterior de este informe decía que ninguna auditoría *minor* WCAG tenía peso, y eso era falso. Además, tres auditorías marcadas "Informational" (`autocomplete-valid`, `presentation-role-conflict`, `svg-img-alt`) pesan 1 aunque no encajan en la tabla Impact/Weight. Las reglas *minor* best-practice (`empty-heading`, `table-duplicate-name`, `aria-allowed-role`, `image-redundant-alt`) pesan 0, como indica la tabla.

**Combinación entre categorías:** Lighthouse **no** combina Performance, Accessibility, Best Practices y SEO en un índice global; cada categoría se reporta por separado. Esto es evidencia **en contra** de presentar el IUA como si tuviera respaldo de plataforma (ver §4).

### 2.3 SonarQube Server (documentación 2026.5)

- **Ratings de seguridad y fiabilidad:** usan la regla del **peor issue abierto**, que es no compensatoria. En modo MQR: A = solo issues info o ninguno; B ≥ 1 low; C ≥ 1 medium; D ≥ 1 high; E ≥ 1 blocker. En Standard Experience la escala es la misma con minor/major/critical/blocker. https://docs.sonarsource.com/sonarqube-server/latest/user-guide/code-metrics/metrics-definition/
- **Rating de mantenibilidad:** usa el ratio de deuda técnica. A ≤ 5 %, B 5-<10 %, C 10-<20 %, D 20-<50 %, E ≥ 50 % (misma URL).
- **Quality gate "Sonar way"** (sobre código nuevo): sin issues nuevos (falla si el rating es peor que A), 100 % de hotspots revisados, cobertura ≥ 80 % y duplicación ≤ 3 %. https://docs.sonarsource.com/sonarqube-server/latest/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates/
- **Pertinencia:** Sonar **no publica pesos numéricos** que promedien severidades. Su modelo es categórico: una letra por la peor severidad abierta, más un gate binario. Respalda dos cosas: (a) que el nivel N0-N5 lo decida una compuerta y no el puntaje (el plan §4.2 ya lo hace) y (b) mostrar un rating por peor hallazgo junto al puntaje.

### 2.4 OWASP Risk Rating Methodology

https://community.owasp.org/OWASP_Risk_Rating_Methodology (owasp.org/www-community redirige con 308 a esta URL).

- La probabilidad y el impacto se miden en una escala 0-9: 0 a <3 LOW, 3 a <6 MEDIUM, 6 a 9 HIGH. La severidad global sale de una matriz 3×3: (HIGH, HIGH) es Critical, (LOW, LOW) es Note, y las combinaciones intermedias son Low, Medium o High.
- Sobre los pesos: el modelo "assumes that all the factors are equally important" y admite ponderarlos según el negocio con un "weighted average". Recomienda usar el impacto de negocio en lugar del técnico cuando se conoce.
- **Pertinencia:** OWASP no da pesos numéricos por severidad. Sí respalda **pesos iguales por defecto** cuando no hay información, y **ajustar por contexto de negocio**, que es la base conceptual del multiplicador por salud o pagos.

### 2.5 CVSS

- **v4.0:** None 0,0 · Low 0,1-3,9 · Medium 4,0-6,9 · High 7,0-8,9 · Critical 9,0-10,0. La escala cualitativa es "optional". La especificación pide enriquecer el puntaje Base con las métricas Threat y Environmental para evaluar riesgo. Ya no usa multiplicadores: los vectores se agruparon en 270 conjuntos de equivalencia disjuntos (*MacroVectors*) que ordenaron expertos, y los requisitos CR/IR/AR entran por EQ6; si no se especifican, se asume el peor caso (H). https://www.first.org/cvss/v4.0/specification-document
- **v3.1:** los Security Requirements (CR/IR/AR) eran multiplicadores: High = **1,5**, Medium = 1, Low = 0,5, Not Defined = 1 (§7.4, tabla 16). Su función, según la especificación, es ajustar el puntaje "depending on the importance of the affected IT asset". https://www.first.org/cvss/v3.1/specification-document
- **Pertinencia:** (a) el auditor puede mapear los hallazgos de CVE a crítica/alta/media/baja con la escala de v4.0 (osv-scanner ya entrega CVSS); (b) el ×1,5 del plan coincide con el valor *High* de CVSS v3.1 para activos importantes. Es un precedente numérico real, aunque v4.0 lo reemplazó.

### 2.6 Mozilla HTTP Observatory

https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md

- Parte de 100 y suma o resta modificadores por test, con piso 0. Los bonos solo cuentan si el puntaje sin ellos ya es ≥ 90; el máximo es 135. Notas: A+ ≥ 100, A 90-99, … F 0-24.
- Penalizaciones de ejemplo: sin CSP −25; sin HSTS −20; cookie de sesión sin Secure −40; CORS universal −50; scripts externos sin HTTPS ni SRI −50; sin X-Content-Type-Options −5.
- **Pertinencia:** es un modelo **sustractivo** (base 100 menos penalizaciones). Las fórmulas del IUA para accesibilidad (100 − 25·critical − …) y limpieza (100 − 20·tipo) tienen esa misma forma. Los números de Observatory pesan **headers concretos**, no severidades genéricas, así que no se pueden trasladar a esas fórmulas. Sí sirven como referencia directa para ponderar dentro del control SEG-HEADERS si se quisiera graduarlo (fuera del alcance de este informe).

### 2.7 Qualys SSL Labs (guía 2009r, 16-05-2025)

https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide

- Pesos por categoría: soporte de protocolo 30 %, intercambio de claves 30 % y fuerza del cifrado 40 %. Notas: A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, E ≥ 20, F < 20.
- "A zero in any category will push the overall score to zero". Además aplica **topes** por vulnerabilidad: por ejemplo, Heartbleed o ROBOT dan F, y TLS 1.0/1.1 o la falta de forward secrecy limitan la nota a B. Estos topes figuran en el changelog de la guía (2009e, 2009p, 2009q). La propia guía advierte que su cuerpo "has not been fully updated to reflect the changes".
- **Pertinencia:** es el precedente más claro de **regla no compensatoria** sobre una media ponderada (cero o tope). Los pesos 30/30/40 son propios de TLS y no se pueden trasladar a dominios del auditor.

### 2.8 Google SRE: Production Readiness Review y Launch Coordination Checklist

- Capítulo 32 del SRE Book (https://sre.google/sre-book/evolving-sre-engagement-model/): revisa arquitectura y dependencias, instrumentación y monitoreo, respuesta a emergencias, planificación de capacidad, gestión de cambios y rendimiento. **No define puntaje ni pesos**; solo dice que las mejoras "are prioritized based upon importance for service reliability".
- Apéndice E (https://sre.google/sre-book/launch-checklist/): es una lista de calificación, no un puntaje. Conclusión de la búsqueda: no encontré ninguna rúbrica numérica oficial de Google para PRR (**ausencia verificada solo en esas dos fuentes**).
- **Pertinencia:** respalda que los dominios INF, ESC y OPS se juzguen con **compuertas** (sí/no por nivel), como hace `gates.py`, y no aporta pesos.

---

## 3. Propuesta para `score.py` (puntaje 0-100 por dominio y global)

### 3.1 Pesos por severidad

| Severidad del auditor | Opción A: Scorecard (**propuesta por defecto**) | Opción B: Lighthouse/axe | Actual (sin fuente) |
|---|---|---|---|
| crítica | 10 | 10 | 10 |
| alta | 7,5 | 7 | 5 |
| media | 5 | 3 | 2 |
| baja | 2,5 | 1 | 1 |
| info | 0 | 0 | 0 |

**Por qué A por defecto (ESTIMACIÓN sobre el ajuste, no sobre los valores):** Scorecard pondera **checks de prácticas de seguridad e ingeniería de un repositorio**, que es el mismo tipo de objeto que los controles del auditor. Lighthouse/axe pondera reglas de accesibilidad de una página. **Correspondencia de etiquetas:** Scorecard usa Critical/High/Medium/Low y el catálogo usa crítica/alta/media/baja. La correspondencia es nominal: nadie validó que la "alta" del catálogo equivalga al "High" de Scorecard (**NO VERIFICADO**; depende de cómo se asignó `severidad_base`, que en el catálogo también es ESTIMACIÓN).

**Opción B:** es coherente si el investigador prefiere un esquema más "empinado" (alta pesa 7 veces baja en vez de 3). La opción A es lineal (2,5 por escalón).

**Info = 0:** Sonar MQR ("A = 0 or more info issues") y Lighthouse (reglas experimentales con peso 0).

### 3.2 Agregación global

| Opción | Fórmula | Evidencia |
|---|---|---|
| **G1 · agrupada estilo Scorecard (propuesta)** | `Global = 100 × Σ_c w(c)·m(c)·[pass] / Σ_c w(c)·m(c)` sobre todos los controles evaluados; m = 1,5 si el control es de SEG o DAT y la bandera salud o pagos está activa, si no 1 | Misma fórmula que `GetAggregateScore` (Scorecard). El multiplicador replica el CR = High de CVSS v3.1 |
| G2 · pesos iguales entre dominios | `Global = media simple de Puntaje(d)` sobre los dominios con puntaje; con salud o pagos, SEG y DAT ×1,5 | OWASP RRM: "all the factors are equally important" por defecto. No hay plataforma que pese dominios equivalentes (**ESTIMACIÓN**) |
| G3 · actual | media de dominios ponderada por número de controles aplicables (×1,5 SEG/DAT) | Sin fuente. Pondera por aplicables (incluye no evaluados), no por evaluados: un dominio con mucho `no_evaluado` pesa en la media aunque su puntaje se calcule sobre pocos controles |

**Por qué G1:** es la única de las tres que copia literalmente una plataforma publicada. Además corrige el sesgo de G3, que mezcla controles aplicables con evaluados. Su costo: los dominios con más controles críticos y altos (SEG: 11 críticos y 18 altos de 40) dominan el global. Es coherente con Scorecard, pero hay que declararlo.

**GUÍA (impacto en código, no aplicado):** G1 requiere cambiar `score.calcular` (hoy aplica G3 y lee `[severidad]`, `[multiplicador_contextual]` y `[puntaje_global].metodo` solo como texto). El `pesos.toml` propuesto mantiene las mismas claves numéricas en `[severidad]`, así que el `score.py` actual lo lee sin error. El cambio de método requiere que quien construye el código implemente `metodo = "agrupado_scorecard"`.

### 3.3 Rating no compensatorio por dominio (agregar, no reemplazar)

Sobre el catálogo actual (174 controles: 17 críticos, 61 altos, 73 medios, 23 bajos), si **todos pasan menos un crítico**, el puntaje global queda en 98,4 con los pesos actuales, 99,0 con Scorecard y 98,8 con Lighthouse/axe (cálculo propio, reproducible con las cifras de `catalogo/controles.toml`). **Ningún esquema de pesos resuelve esto**, porque una media ponderada es compensatoria por diseño. Las plataformas lo resuelven así:

- **SonarQube:** letra por la **peor severidad abierta** (A-E).
- **SSL Labs:** topes y cero automático.

**Propuesta (sección nueva `[rating_dominio]`; score.py la ignora hasta que se implemente):** mostrar al lado de cada puntaje una letra estilo Sonar MQR:

| Peor `fail` abierto en el dominio | Letra |
|---|---|
| ninguno (o solo info) | A |
| baja | B |
| media | C |
| alta | D |
| crítica | E |

Correspondencia: el *blocker* de Sonar equivale a la crítica del auditor; *high* a alta; *medium* a media; *low* a baja. Sonar tiene un nivel más que el auditor (blocker y high por separado). Juntar "crítica" con blocker es **ESTIMACIÓN**.

No propongo topes numéricos al estilo SSL Labs (por ejemplo, "un crítico limita a 60"): no hay fuente para el valor, y el nivel N0-N5 ya cumple esa función bloqueante (§4.2 regla 5).

---

## 4. Propuesta para el IUA (`iua.py`)

### 4.1 Pesos entre componentes

**No hay evidencia de plataforma.** Lighthouse, que mide accesibilidad y rendimiento, deliberadamente **no** los combina. Los pesos actuales (accesibilidad 25 y 15 para los otros cinco componentes) y la alternativa de pesos iguales (1/6 cada uno) son ambos **ESTIMACIÓN**. Propongo pesos iguales como alternativa neutral, siguiendo el criterio de OWASP RRM de igualdad por defecto. El investigador elige. Queda una recomendación metodológica que no cambia los pesos: **reportar siempre los seis subpuntajes junto al IUA**, porque así lo hace Lighthouse por categoría.

### 4.2 Componente accesibilidad: reemplazar la fórmula sin fuente por la de Lighthouse

- **Actual (sin fuente):** `100 − 25·critical − 10·serious − 3·moderate`, con piso 0. Cuenta violaciones, no reglas. Además satura: 4 violaciones críticas ya llevan el componente a 0.
- **Propuesta (verificada):** `Acc = 100 × Σ_r w(r)·[r pasa] / Σ_r w(r)`, sobre las reglas axe con resultado `passes` o `violations` (se excluyen `incomplete` e `inapplicable`). Pesos según impacto y etiqueta: critical 10, serious 7, moderate 3, minor 1 si la regla tiene etiqueta WCAG A/AA (0 si no); las reglas experimentales valen 0. Es la tabla de `default-config.js` de Lighthouse.
- **Diferencia práctica:** la propuesta mide la **proporción de reglas cumplidas** y no el número de nodos fallidos, así que no se satura con muchas instancias de la misma regla. Contrapartida: igual que en Lighthouse, una regla con 1 nodo fallido cuenta lo mismo que una con 50.
- **Compatibilidad:** se agrega la sección `[iua.accesibilidad_lighthouse]` y se conserva `[iua.accesibilidad]` para que el código actual no falle. Activar el método nuevo requiere cambiar `iua.py`. **NO VERIFICADO:** no encontré `iua.py` en `scripts/` el 2026-11-18, así que asumo que aún no existe.

### 4.3 Componente rendimiento

Ya usa el puntaje de rendimiento de Lighthouse, que trae sus propios pesos verificados: FCP 10, SI 10, LCP 25, TBT 30, CLS 25. No requiere cambio. Se documenta el origen en la propuesta.

### 4.4 Componente limpieza

La forma "100 − penalización por tipo, piso 0" coincide con el modelo sustractivo de Mozilla Observatory. El valor **20 por tipo** no tiene fuente y queda como **ESTIMACIÓN**.

### 4.5 Bandas del IUA (nota para la Decisión 2, sin cambiar `umbrales.toml`)

Las bandas actuales (< 50 / 50-69 / 70-84 / ≥ 85) son propuesta. La única banda publicada en una herramienta análoga es la de Lighthouse: 0-49 pobre, 50-89 mejorable, 90-100 bueno (https://developer.chrome.com/docs/lighthouse/performance/performance-scoring). Si se quiere evidencia de plataforma, ese es el candidato. Lo decide el investigador en `umbrales.toml`.

---

## 5. Sensibilidad (ESTIMACIÓN, cálculo propio sobre `catalogo/controles.toml`)

Participación de cada severidad en el peso total, con todos los controles evaluados:

| Esquema | Σw | crítica | alta | media | baja |
|---|---|---|---|---|---|
| Actual 10/5/2/1 | 644 | 26,4 % | 47,4 % | 22,7 % | 3,6 % |
| Scorecard 10/7,5/5/2,5 | 1050 | 16,2 % | 43,6 % | 34,8 % | 5,5 % |
| Lighthouse/axe 10/7/3/1 | 839 | 20,3 % | 50,9 % | 26,1 % | 2,7 % |

- **Lectura:** Scorecard da más peso relativo a los controles medios y bajos que el esquema actual. Por eso el puntaje castigará más la higiene acumulada y menos los críticos aislados; por esto mismo el rating no compensatorio de §3.3 se vuelve más importante.
- **Validación pendiente:** el plan (§4.4, F6) prevé comparar el orden de proyectos por puntaje con el juicio experto (Spearman). Es la única forma de validar empíricamente cualquiera de los tres esquemas. Sugerencia: calcular los tres en paralelo durante el piloto y reportar los tres rho con IC95 % (exploratorio, n pequeño, DECISIONES.md #8).

---

## 6. Qué decide el investigador

1. Pesos por severidad: **A Scorecard** (propuesta) · B Lighthouse/axe · mantener la actual (declarando que no tiene fuente).
2. Agregación global: **G1 agrupada Scorecard** (propuesta) · G2 pesos iguales entre dominios · G3 actual.
3. Si se agrega el rating A-E por dominio (estilo Sonar).
4. Pesos del IUA: actuales 25/15×5 · iguales. Ambos son ESTIMACIÓN.
5. Fórmula de accesibilidad del IUA: **Lighthouse ponderada pass/fail** (propuesta) · penalización actual.

## 7. No verificado / límites

- La equivalencia semántica entre la severidad del catálogo y los niveles de riesgo de Scorecard, Sonar y axe (**NO VERIFICADO**).
- La existencia de `scripts/iua.py` (no se encontró al 2026-11-18).
- Que Google publique una rúbrica numérica de PRR fuera de los dos capítulos revisados (**NO VERIFICADO**; en ellos no existe).
- El peso 1 de *minor* en Lighthouse se tomó del código (lo usa `aria-deprecated-role`); la página de documentación solo muestra 3/7/10.
- Los conteos de estrellas o versiones cambian; los commits citados fijan la evidencia a la fecha.

## 8. Fuentes

- OpenSSF Scorecard, `scorecard_result.go` (commit e78ecbb): https://github.com/ossf/scorecard/blob/e78ecbbade8f79491d71125c14409065a69d6b4c/pkg/scorecard/scorecard_result.go
- OpenSSF Scorecard, `checks.yaml`: https://github.com/ossf/scorecard/blob/main/docs/checks/internal/checks.yaml
- Lighthouse `default-config.js` (commit 5d39535 de main, posterior a v13.6.0): https://github.com/GoogleChrome/lighthouse/blob/5d395351e8953c8e79ceea5246ed5b198b588d1d/core/config/default-config.js
- Lighthouse `default-config.js` en la release v13.6.0 (commit edc407d, mismos pesos): https://github.com/GoogleChrome/lighthouse/blob/edc407d72179bbc4d4de8a40ef0311ca87dff89c/core/config/default-config.js
- Lighthouse performance scoring: https://developer.chrome.com/docs/lighthouse/performance/performance-scoring
- Lighthouse accessibility scoring: https://developer.chrome.com/docs/lighthouse/accessibility/scoring
- SonarQube metrics definition (2026.5): https://docs.sonarsource.com/sonarqube-server/latest/user-guide/code-metrics/metrics-definition/
- SonarQube quality gates (2026.5): https://docs.sonarsource.com/sonarqube-server/latest/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates/
- OWASP Risk Rating Methodology: https://community.owasp.org/OWASP_Risk_Rating_Methodology
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
- Mozilla HTTP Observatory scoring: https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md
- SSL Labs Server Rating Guide: https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
- Google SRE Book cap. 32: https://sre.google/sre-book/evolving-sre-engagement-model/
- Google SRE Book apéndice E: https://sre.google/sre-book/launch-checklist/

---

## Verificación

Verificador escéptico, 2026-11-18. Revisé las fuentes con `gh api` (contenido y commits de GitHub) y WebFetch (documentación), y rehíce los cálculos sobre `catalogo/controles.toml` con Python.

| # | Afirmación | Fuente | Resultado |
|---|---|---|---|
| 1 | Scorecard: `weights` Critical 10 / High 7,5 / Medium 5 / Low 2,5; los inconclusos se excluyen (`continue`); `score/total` | `gh api repos/ossf/scorecard/contents/pkg/scorecard/scorecard_result.go?ref=e78ecbb…` (línea 81) | **CONFIRMADO**. e78ecbb sigue siendo el último commit que toca el archivo |
| 2 | Scorecard: asignación de riesgo por check (2 Critical, 8 High, 6 Medium, 4 Low) | `gh api …/docs/checks/internal/checks.yaml` | **CONFIRMADO** (los 20 checks coinciden) |
| 3 | Lighthouse 5d39535 = release v13.6.0 | `gh api repos/GoogleChrome/lighthouse/compare/v13.6.0...5d39535` | **ERROR, CORREGIDO**: 5d39535 va 31 commits por delante del tag (release = edc407d). Los pesos son idénticos en ambos |
| 4 | Lighthouse rendimiento FCP 10, LCP 25, TBT 30, CLS 25, SI 10, INP 0 | `default-config.js` líneas 419-424; https://developer.chrome.com/docs/lighthouse/performance/performance-scoring | **CONFIRMADO** (la documentación rotula la tabla "Lighthouse 10") |
| 5 | Lighthouse accesibilidad: tabla de impacto 1/3/7/10, best-practice 0/3/7/10, experimental 0 | `default-config.js` líneas 490-501; https://developer.chrome.com/docs/lighthouse/accessibility/scoring | **CONFIRMADO**: pass/fail sin crédito parcial; la documentación muestra solo 10/7/3 |
| 6 | "Ninguna auditoría *minor* WCAG tiene peso" | `default-config.js` línea 512 | **ERROR, CORREGIDO**: `aria-deprecated-role` pesa 1 (Minor, wcag2a). Además hay 3 auditorías "Informational" con peso 1 |
| 7 | Sonar MQR: A = 0 o más info, B low, C medium, D high, E blocker; mantenibilidad 5/10/20/50 %; docs 2026.5 | https://docs.sonarsource.com/sonarqube-server/latest/user-guide/code-metrics/metrics-definition/ | **CONFIRMADO** |
| 8 | Sonar way: sin issues nuevos, 100 % de hotspots revisados, cobertura ≥ 80 %, duplicación ≤ 3 % | https://docs.sonarsource.com/sonarqube-server/latest/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates/ | **CONFIRMADO** |
| 9 | CVSS v3.1 CR/IR/AR: High 1,5 · Medium 1 · Low 0,5 · ND 1 (§7.4, tabla 16) | https://www.first.org/cvss/v3.1/specification-document | **CONFIRMADO** |
| 10 | CVSS v4.0: escala 0 / 0,1-3,9 / 4-6,9 / 7-8,9 / 9-10, opcional; 270 conjuntos; CR/IR/AR en EQ6 y X = H | https://www.first.org/cvss/v4.0/specification-document | **CONFIRMADO**, con redacción precisada ("270 conjuntos de equivalencia") |
| 11 | OWASP RRM: 0-<3 / 3-<6 / 6-9; matriz 3×3; "all the factors are equally important"; "weighted average" | https://community.owasp.org/OWASP_Risk_Rating_Methodology | **CONFIRMADO** |
| 12 | Mozilla Observatory: base 100, bonos solo con ≥ 90, máximo 135; CSP −25, HSTS −20, cookie −40, CORS −50, SRI −50, XCTO −5 | https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md | **CONFIRMADO** |
| 13 | SSL Labs 2009r (16-05-2025): 30/30/40; A ≥ 80 … F < 20; cero en una categoría lleva el total a cero; topes Heartbleed/ROBOT F y TLS 1.0-1.1/sin FS B | https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide | **CONFIRMADO**. Agregué la advertencia de la propia guía de que no está totalmente actualizada |
| 14 | Catálogo: 174 controles (17 críticos/61 altos/73 medios/23 bajos); SEG: 11 críticos y 18 altos de 40 | `catalogo/controles.toml` (recálculo local) | **CONFIRMADO** |
| 15 | Σw 644/1050/839, participaciones de §5 y un solo crítico fallido → 98,4/99,0/98,8 | recálculo local | **CONFIRMADO** (todas las cifras coinciden) |
| 16 | `scripts/iua.py` no existe | `ls scripts/` al 2026-11-18 | **CONFIRMADO** (sigue sin existir) |
| 17 | Google SRE cap. 32 y apéndice E sin rúbrica numérica | — | **NO VERIFICADO** en esta pasada (no reabierto) |

**Notas que no requirieron corrección:**
- El informe no cita defaults de eslint, lizard o Stryker, umbrales CWV ni estrellas de repositorios. Esas cifras están en `config/umbrales.toml`, que queda fuera del alcance de este archivo y no se editó.
- La propuesta `propuestas/pesos.toml` sigue siendo TOML válido (se comprobó con `tomllib`). Solo se le agregó un comentario de verificación en `[iua.accesibilidad_lighthouse]`; no cambió ningún valor numérico.
