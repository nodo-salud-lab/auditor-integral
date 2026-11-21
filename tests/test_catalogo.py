"""Tests del catálogo canónico de controles (F0-A).

Cubre: integridad de catalogo/controles.toml, alias_fuente.json y
perfil_riesgo.toml, y el módulo scripts/catalogo.py (mapeo regla→control,
evaluador seguro de condiciones y selección de controles aplicables).
"""

import json
import re
import sys
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import catalogo  # noqa: E402

RUTA_CONTROLES = RAIZ / "catalogo" / "controles.toml"
RUTA_PERFIL_RIESGO = RAIZ / "catalogo" / "perfil_riesgo.toml"
RUTA_ALIAS = RAIZ / "catalogo" / "alias_fuente.json"

CAMPOS_REQUERIDOS = {
    "id": str, "titulo": str, "alias": list, "dominio": str, "etapa": str,
    "gate": str, "severidad_base": str, "metodo": str, "herramientas": list,
    "condicion": str, "bloquea_global": bool, "mapea_reglas": list,
    "esfuerzo": str, "fuente": str,
}
DOMINIOS = {"SEG", "DAT", "COD", "UX", "INF", "ESC", "OPS"}
ETAPAS = {f"E{i}" for i in range(7)}
GATES = {f"N{i}" for i in range(1, 6)}
SEVERIDADES = {"critica", "alta", "media", "baja", "info"}
METODOS = {"determinista", "mixto", "llm", "manual"}
ESFUERZOS = {"S", "M", "L"}

# Tabla §4.3 del PLAN_MAESTRO, expandida a IDs canónicos.
# Notas de expansión (decisiones documentadas en controles.toml):
#  - Un mismo nombre en dos niveles se separa en dos controles
#    (INF-ENTORNOS / INF-ENTORNOS-SEPARADOS, INF-PLATAFORMA /
#    INF-PLATAFORMA-CUMPLIDA, OPS-CUENTAS / OPS-CUENTAS-EFECTIVO,
#    UX-HEURISTICA / UX-HEURISTICA-SEV4).
#  - DAT-RLS-ON figura en N1 "si hay datos reales" y en N2: el gate base es
#    N2 y perfil_riesgo.toml lo baja a N1 con datos reales (test aparte).
#  - Celdas descriptivas → ID: "sin SQL concatenado" = DAT-SQL-CONCATENADO;
#    "Flujo feliz funciona" = UX-FLUJO-FELIZ; "LCP lab < 4 s" = UX-LCP-LAB;
#    "CWV campo" = UX-CWV-CAMPO; "UMUX-Lite continuo" = UX-UMUX;
#    "costo en escenario viral" = ESC-COSTO-VIRAL; "DR multi-región" = OPS-DR.
TABLA_43 = {
    "SEG": {
        "N1": ["SECRETO-REPO", "SECRETO-BUNDLE", "ENV-PUBLICAS", "ENV-EJEMPLO", "DEPS-EXISTEN", "LLM-CLAVE"],
        "N2": ["DEPS-CVE-CRIT", "LOCKFILE", "SAST-INY", "AUTH-CLIENTE", "IDOR", "BFLA", "AUTH-HASH", "JWT",
               "RESET-PWD", "AGENTES-IA", "LLM-SALIDA", "STRIDE", "PAGOS-FIRMA", "PAGOS-SERVIDOR", "RATELIMIT"],
        "N3": ["MASIVA", "COOKIES", "CSRF", "VALIDACION", "SSRF", "HEADERS", "CORS", "ERRORES", "LLM-AGENCIA",
               "CICD", "SECURITY-TXT"],
        "N4": ["DEPS-CVE-ALTO", "DAST-PASIVO", "DAST-PLANTILLAS", "SBOM", "REDTEAM-LLM"],
        "N5": ["SCORECARD", "PENTEST"],
    },
    "DAT": {
        "N1": ["SQL-CONCATENADO"],
        "N2": ["RLS-ON", "RLS-PERMISIVA", "RLS-SEMANTICA", "RLS-METADATA", "ANON-NEGATIVA", "SECDEF", "BUCKETS",
               "GRANTS", "ESQUEMA-VERSIONADO", "PK-FK", "PII-INVENTARIO", "BACKUP", "POOLER"],
        "N3": ["RLS-TESTS", "MIGRACIONES-SEGURAS", "FK-INDICE", "TIPOS", "TRANSACCIONES", "N+1", "PAGINACION",
               "AUDITORIA-ACCESOS"],
        "N4": ["TIMEOUTS", "RESTORE", "CONSULTAS-LENTAS", "HIGIENE", "EXPAND-CONTRACT"],
        "N5": ["ESCALADO"],
    },
    "COD": {
        "N1": ["REPRO", "FLUJOGRAMA"],
        "N2": ["LINT", "TIPOS", "CRITERIOS", "CI-BASICO", "TESTS-HUMO", "DOC-AGENTE"],
        "N3": ["COBERTURA", "AUTHZ-TESTS", "DUPLICACION", "COMPLEJIDAD", "CICLOS-MUERTO", "ADR-C4",
               "RAMA-PROTEGIDA", "LICENCIAS"],
        "N4": ["MUTACION", "E2E-TRAZA", "RELEASE"],
        "N5": ["DORA"],
    },
    "UX": {
        "N1": ["FLUJO-FELIZ"],
        "N2": ["A11Y-ESTATICA", "AXE-CRIT", "REFLOW", "ESTADOS", "ERRORES-VISIBLES", "FORMULARIOS", "LANG",
               "HEURISTICA", "FECHAS", "LCP-LAB"],
        "N3": ["AXE-SERIOUS", "TECLADO", "TACTIL", "FOCO-OCULTO", "LIGHTHOUSE", "NAVEGADORES", "CONSENTIMIENTO",
               "SW-PWA", "SUS-MEDIDO", "HEURISTICA-SEV4"],
        "N4": ["CWV-CAMPO", "SUS-68", "TOKENS", "LECTOR-PANTALLA", "I18N"],
        "N5": ["REGRESION", "UMUX"],
    },
    "INF": {
        "N1": ["INVENTARIO", "PLATAFORMA"],
        "N2": ["ENTORNOS", "TAREAS-LARGAS", "TIMEOUTS-SALIDA", "DOCKERFILE", "EMAIL-DNS"],
        "N3": ["ENTORNOS-SEPARADOS", "SIN-ESTADO", "CACHE-CDN", "REGION", "EMAIL-ASYNC", "MOVIL",
               "PLATAFORMA-CUMPLIDA"],
        "N4": ["IAC", "K8S", "ROLLBACK", "IAC-REPRO"],
    },
    "ESC": {
        "N2": ["SMOKE", "LLM-TOPE", "PRESUPUESTO"],
        "N3": ["CARGA-PROMEDIO", "BREAKPOINT", "SLO", "COSTO-UNITARIO"],
        "N4": ["SOAK-SPIKE", "COSTO-VIRAL"],
        "N5": ["CAPACIDAD"],
    },
    "OPS": {
        "N1": ["CUENTAS"],
        "N2": ["CUENTAS-EFECTIVO", "PLAN-GRATIS", "ERROR-TRACKING", "HEALTH", "PRIVACIDAD", "LEY-VIGENCIA",
               "LLM-PII"],
        "N3": ["LOGS-ESTRUCTURADOS", "DERECHOS-TITULAR", "LICITUD", "TRANSFERENCIAS", "BRECHAS", "RPO-RTO",
               "SECRETOS-CICLO", "RUNBOOK", "TRASPASO", "LLM-TRAZAS", "LOGICA-ABUSO"],
        "N4": ["OTEL-RED", "RETENCION", "JURIDICO", "EIPD", "SALIDA-PROVEEDOR", "EVALS-LLM", "REAUDITORIA"],
        "N5": ["DR"],
    },
}

# Controles marcados con * (condicionales) en §4.3: no pueden ser "siempre".
CONDICIONALES_43 = {
    "SEG-LLM-CLAVE", "SEG-LLM-SALIDA", "SEG-LLM-AGENCIA", "SEG-REDTEAM-LLM", "SEG-PAGOS-FIRMA",
    "SEG-PAGOS-SERVIDOR", "DAT-RLS-ON", "UX-SW-PWA", "UX-I18N", "INF-DOCKERFILE", "INF-EMAIL-DNS",
    "INF-EMAIL-ASYNC", "INF-MOVIL", "INF-IAC", "INF-K8S", "ESC-LLM-TOPE", "OPS-PRIVACIDAD",
    "OPS-LEY-VIGENCIA", "OPS-LLM-PII", "OPS-DERECHOS-TITULAR", "OPS-LICITUD", "OPS-TRANSFERENCIAS",
    "OPS-BRECHAS", "OPS-LLM-TRAZAS", "OPS-JURIDICO", "OPS-EIPD", "OPS-EVALS-LLM",
}


def _controles():
    with open(RUTA_CONTROLES, "rb") as f:
        return tomllib.load(f)["control"]


class TestCatalogoIntegridad(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controles = _controles()
        cls.por_id = {c["id"]: c for c in cls.controles}
        with open(RUTA_ALIAS, encoding="utf-8") as f:
            cls.alias_fuente = json.load(f)
        with open(RUTA_PERFIL_RIESGO, "rb") as f:
            cls.perfil_riesgo = tomllib.load(f)

    def test_tamano_razonable(self):
        self.assertGreaterEqual(len(self.controles), 100)
        self.assertLessEqual(len(self.controles), 200)

    # (b) 0 IDs canónicos duplicados
    def test_ids_canonicos_unicos(self):
        ids = [c["id"] for c in self.controles]
        duplicados = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual(duplicados, [], f"IDs duplicados: {duplicados}")

    # (c) campos requeridos y valores válidos
    def test_campos_y_valores(self):
        errores = []
        for c in self.controles:
            cid = c.get("id", "?")
            for campo, tipo in CAMPOS_REQUERIDOS.items():
                if campo not in c:
                    errores.append(f"{cid}: falta {campo}")
                elif not isinstance(c[campo], tipo):
                    errores.append(f"{cid}: {campo} no es {tipo.__name__}")
            if errores:
                continue
            if not re.fullmatch(r"(SEG|DAT|COD|UX|INF|ESC|OPS)-[A-Z0-9+]+(-[A-Z0-9+]+)*", cid):
                errores.append(f"{cid}: formato de ID inválido")
            if not cid.startswith(c["dominio"] + "-"):
                errores.append(f"{cid}: prefijo no coincide con dominio {c['dominio']}")
            for campo, validos in (("dominio", DOMINIOS), ("etapa", ETAPAS), ("gate", GATES),
                                   ("severidad_base", SEVERIDADES), ("metodo", METODOS),
                                   ("esfuerzo", ESFUERZOS)):
                if c[campo] not in validos:
                    errores.append(f"{cid}: {campo}={c[campo]!r} inválido")
            if not c["titulo"].strip() or not c["fuente"].strip():
                errores.append(f"{cid}: titulo/fuente vacío")
            if c["metodo"] in ("determinista", "mixto") and not c["herramientas"]:
                errores.append(f"{cid}: método {c['metodo']} sin herramientas")
            for patron in c["mapea_reglas"]:
                if not re.fullmatch(r"[a-z0-9_\-]+:.+", patron):
                    errores.append(f"{cid}: patrón mapea_reglas inválido {patron!r}")
            try:
                catalogo.validar_condicion(c["condicion"])
            except catalogo.ErrorCondicion as e:
                errores.append(f"{cid}: condición inválida: {e}")
        self.assertEqual(errores, [], "\n".join(errores))

    # (d) todo ID de la tabla §4.3 existe con su gate
    def test_tabla_43_completa(self):
        faltan, gate_mal = [], []
        for dominio, niveles in TABLA_43.items():
            for gate, nombres in niveles.items():
                for nombre in nombres:
                    cid = f"{dominio}-{nombre}"
                    if cid not in self.por_id:
                        faltan.append(cid)
                    elif self.por_id[cid]["gate"] != gate:
                        gate_mal.append(f"{cid}: {self.por_id[cid]['gate']} != {gate}")
        self.assertEqual(faltan, [], f"Faltan IDs de §4.3: {faltan}")
        self.assertEqual(gate_mal, [], "\n".join(gate_mal))

    def test_condicionales_43_no_son_siempre(self):
        malos = [cid for cid in CONDICIONALES_43 if self.por_id[cid]["condicion"].strip() == "siempre"]
        self.assertEqual(malos, [])

    # (a) 0 IDs de alias_fuente huérfanos
    def test_alias_fuente_sin_huerfanos(self):
        ids_fuente = set(self.alias_fuente["ids"])
        self.assertGreater(len(ids_fuente), 200)
        cubiertos = set(self.por_id)
        for c in self.controles:
            cubiertos.update(c["alias"])
        huerfanos = sorted(ids_fuente - cubiertos)
        self.assertEqual(huerfanos, [], f"IDs de origen huérfanos: {huerfanos}")

    def test_alias_existen_en_fuente(self):
        ids_fuente = set(self.alias_fuente["ids"])
        inventados = sorted({a for c in self.controles for a in c["alias"]} - ids_fuente)
        self.assertEqual(inventados, [], f"Alias que no están en alias_fuente.json: {inventados}")

    def test_alias_fuente_formato(self):
        for i, informe in self.alias_fuente["ids"].items():
            self.assertRegex(i, r"^(VC|SEC|DB|INF|UX|ING|ECO|GAP)-\d{2}$")
            self.assertRegex(informe, r"^0[1-8]$")

    def test_alias_fuente_incluye_ids_literales(self):
        # Todo ID con forma XX-nn presente literalmente en los informes 01-08 está en alias_fuente.
        patron = re.compile(r"\b(?:VC|SEC|DB|INF|UX|ING|ECO|GAP)-\d{2}\b")
        literales = set()
        for ruta in sorted((RAIZ / "investigacion").glob("0[1-8]-*.md")):
            literales.update(patron.findall(ruta.read_text(encoding="utf-8")))
        faltan = sorted(literales - set(self.alias_fuente["ids"]))
        self.assertEqual(faltan, [])

    # (e) ningún alias en dos controles
    def test_alias_unicos_entre_controles(self):
        visto, repetidos = {}, []
        for c in self.controles:
            for a in c["alias"]:
                if a in visto:
                    repetidos.append(f"{a}: {visto[a]} y {c['id']}")
                visto[a] = c["id"]
        self.assertEqual(repetidos, [], "\n".join(repetidos))

    def test_patrones_no_repetidos_entre_controles(self):
        visto, repetidos = {}, []
        for c in self.controles:
            for p in c["mapea_reglas"]:
                if p in visto and visto[p] != c["id"]:
                    repetidos.append(f"{p}: {visto[p]} y {c['id']}")
                visto[p] = c["id"]
        self.assertEqual(repetidos, [], "\n".join(repetidos))

    def test_ejemplo_plan_35(self):
        c = self.por_id["SEG-SECRETO-REPO"]
        self.assertEqual(c["gate"], "N1")
        self.assertTrue(c["bloquea_global"])
        self.assertIn("gitleaks:*", c["mapea_reglas"])
        self.assertTrue({"VC-04", "SEC-01", "ECO-02", "INF-03"} <= set(c["alias"]))

    def test_condiciones_usan_banderas_conocidas(self):
        banderas = {b["nombre"] for b in self.perfil_riesgo["bandera"]}
        errores = []
        for c in self.controles:
            for nombre in catalogo.nombres_en_condicion(c["condicion"]):
                if nombre not in banderas:
                    errores.append(f"{c['id']}: bandera desconocida {nombre}")
        self.assertEqual(errores, [], "\n".join(errores))

    def test_banderas_coinciden_con_plan_36(self):
        esperadas = {"baas", "ssr_serverless", "llm", "pagos", "emails", "docker", "iac", "k8s", "movil",
                     "pwa", "multi_idioma", "agente_ia", "datos_personales", "salud", "menores", "ue",
                     "datos_reales_cargados", "usuarios_3m", "usuarios_12m",
                     # Anexo C del brazo C (AUD-INF): servidor y bd, detectadas por archivos.
                     "servidor", "bd"}
        self.assertEqual({b["nombre"] for b in self.perfil_riesgo["bandera"]}, esperadas)

    def test_perfil_riesgo_referencias_validas(self):
        errores = []
        for b in self.perfil_riesgo["bandera"]:
            for patron in b.get("activa", []):
                if not catalogo.expandir_patron_ids(patron, self.por_id):
                    errores.append(f"bandera {b['nombre']}: {patron} no coincide con ningún control")
        for r in self.perfil_riesgo["regla_contextual"]:
            catalogo.validar_condicion(r["condicion"])
            for patron in r["controles"]:
                if not catalogo.expandir_patron_ids(patron, self.por_id):
                    errores.append(f"regla {r['id']}: {patron} no coincide con ningún control")
            if "gate" in r:
                self.assertIn(r["gate"], GATES)
            if "severidad_base" in r:
                self.assertIn(r["severidad_base"], SEVERIDADES)
        self.assertEqual(errores, [], "\n".join(errores))

    def test_regla_rls_on_datos_reales(self):
        # §4.3: DAT-RLS-ON es N1 si hay datos reales.
        reglas = [r for r in self.perfil_riesgo["regla_contextual"]
                  if "DAT-RLS-ON" in catalogo.expandir_patrones(r["controles"], self.por_id)
                  and r.get("gate") == "N1"]
        self.assertTrue(reglas)

    def test_legales_no_bloquean_global(self):
        # DECISIONES.md #4: lo legal no bloquea el nivel automáticamente.
        legales = ["OPS-PRIVACIDAD", "OPS-LEY-VIGENCIA", "OPS-LICITUD", "OPS-DERECHOS-TITULAR",
                   "OPS-TRANSFERENCIAS", "OPS-BRECHAS", "OPS-JURIDICO", "OPS-EIPD", "OPS-RETENCION"]
        for cid in legales:
            self.assertFalse(self.por_id[cid]["bloquea_global"], cid)


class TestControlPorRegla(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = catalogo.cargar_catalogo()

    def m(self, herramienta, regla, archivo=None):
        return catalogo.control_por_regla(herramienta, regla, catalogo=self.cat, archivo=archivo)

    def test_gitleaks_repo(self):
        self.assertEqual(self.m("gitleaks", "generic-api-key"), "SEG-SECRETO-REPO")

    def test_gitleaks_bundle_por_ruta(self):
        for ruta in ("dist/assets/index-abc.js", "build/static/js/main.js", ".next/static/chunks/a.js",
                     "out/index.html", "apps/web/dist/x.js"):
            self.assertEqual(self.m("gitleaks", "generic-api-key", archivo=ruta), "SEG-SECRETO-BUNDLE", ruta)
        self.assertEqual(self.m("gitleaks", "generic-api-key", archivo="src/distribucion.js"),
                         "SEG-SECRETO-REPO")

    def test_semgrep_github_actions_va_a_cicd(self):
        # Las reglas de workflows de semgrep (p/owasp-top-ten) son de CI/CD, no inyección de la app.
        for regla in ("yaml.github-actions.security.run-shell-injection.run-shell-injection",
                      "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
                      "yaml.github-actions.security.pull-request-target-code-checkout.pull-request-target-code-checkout"):
            self.assertEqual(self.m("semgrep", regla), "SEG-CICD", regla)

    def test_osv_por_severidad(self):
        self.assertEqual(self.m("osv", "critica/GHSA-xxxx-yyyy-zzzz"), "SEG-DEPS-CVE-CRIT")
        self.assertEqual(self.m("osv", "alta/GHSA-xxxx-yyyy-zzzz"), "SEG-DEPS-CVE-ALTO")

    def test_zizmor(self):
        self.assertEqual(self.m("zizmor", "unpinned-uses"), "SEG-CICD")

    def test_vibe_coding(self):
        esperado = {
            "vibe-coding.service-role-cliente": "SEG-AUTH-CLIENTE",  # D39 (tarea A2)
            "vibe-coding.auth-solo-cliente": "SEG-AUTH-CLIENTE",
            "vibe-coding.monto-desde-body": "SEG-PAGOS-SERVIDOR",
            "vibe-coding.findmany-sin-take": "DAT-PAGINACION",
            "vibe-coding.cors-comodin-credenciales": "SEG-CORS",
            "vibe-coding.eval-dinamico": "SEG-SAST-INY",
            "vibe-coding.sql-concatenado": "DAT-SQL-CONCATENADO",
            "vibe-coding.catch-vacio": "SEG-ERRORES",
        }
        for regla, control in esperado.items():
            self.assertEqual(self.m("semgrep", regla), control, regla)

    def test_vibe_coding_con_prefijo_de_ruta(self):
        # semgrep antepone la ruta del archivo de reglas al check_id.
        self.assertEqual(self.m("semgrep", "reglas.semgrep.vibe-coding.catch-vacio"), "SEG-ERRORES")

    def test_semgrep_owasp(self):
        self.assertEqual(
            self.m("semgrep", "javascript.express.security.injection.tainted-sql-string.tainted-sql-string"),
            "DAT-SQL-CONCATENADO")
        self.assertEqual(self.m("semgrep", "javascript.browser.security.insecure-document-method.xss"),
                         "SEG-SAST-INY")
        self.assertEqual(self.m("semgrep", "javascript.lang.security.audit.path-traversal.path-join"),
                         "SEG-SAST-INY")
        self.assertEqual(self.m("semgrep", "python.django.security.injection.ssrf.ssrf-requests"), "SEG-SSRF")
        self.assertEqual(self.m("semgrep", "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret"),
                         "SEG-JWT")
        # Cualquier otra regla de semgrep cae en el control SAST genérico.
        self.assertEqual(self.m("semgrep", "regla.desconocida.cualquiera"), "SEG-SAST-INY")

    def test_checks_propios(self):
        self.assertEqual(self.m("check", "env_publicas"), "SEG-ENV-PUBLICAS")
        self.assertEqual(self.m("check", "registro_deps.inexistente"), "SEG-DEPS-EXISTEN")
        self.assertEqual(self.m("check", "config_agentes.service_role"), "SEG-AGENTES-IA")
        esperado = {
            "archivos_clave.readme": "COD-REPRO",
            "archivos_clave.env_ejemplo": "SEG-ENV-EJEMPLO",
            "archivos_clave.lockfile": "SEG-LOCKFILE",
            "archivos_clave.ci": "COD-CI-BASICO",
            "archivos_clave.health": "OPS-HEALTH",
            "archivos_clave.migraciones": "DAT-ESQUEMA-VERSIONADO",
        }
        for regla, control in esperado.items():
            self.assertEqual(self.m("check", regla), control, regla)

    def test_sin_coincidencia(self):
        self.assertIsNone(self.m("herramienta-inexistente", "x"))

    def test_mas_especifico_gana(self):
        cat = [
            {"id": "A", "mapea_reglas": ["semgrep:*"]},
            {"id": "B", "mapea_reglas": ["semgrep:*sql*"]},
            {"id": "C", "mapea_reglas": ["semgrep:regla.sql.exacta"]},
        ]
        self.assertEqual(catalogo.control_por_regla("semgrep", "regla.sql.exacta", catalogo=cat), "C")
        self.assertEqual(catalogo.control_por_regla("semgrep", "otra.sql.x", catalogo=cat), "B")
        self.assertEqual(catalogo.control_por_regla("semgrep", "nada", catalogo=cat), "A")

    def test_empate_gana_orden_del_catalogo(self):
        cat = [{"id": "X", "mapea_reglas": ["t:a*"]}, {"id": "Y", "mapea_reglas": ["t:*a"]}]
        self.assertEqual(catalogo.control_por_regla("t", "aa", catalogo=cat), "X")

    def test_sensible_a_mayusculas(self):
        cat = [{"id": "X", "mapea_reglas": ["t:abc"]}]
        self.assertIsNone(catalogo.control_por_regla("t", "ABC", catalogo=cat))


class TestEvaluarCondicion(unittest.TestCase):
    P = {"baas": "supabase", "llm": True, "pagos": False, "salud": None, "usuarios_12m": 5000}

    def ev(self, cond, perfil=None):
        return catalogo.evaluar_condicion(cond, self.P if perfil is None else perfil)

    def test_siempre(self):
        self.assertIs(self.ev("siempre"), True)
        self.assertIs(self.ev("  siempre "), True)

    def test_comparaciones(self):
        self.assertIs(self.ev("baas == 'supabase'"), True)
        self.assertIs(self.ev('baas == "firebase"'), False)
        self.assertIs(self.ev("baas != 'ninguno'"), True)
        self.assertIs(self.ev("llm == true"), True)
        self.assertIs(self.ev("pagos == true"), False)
        self.assertIs(self.ev("usuarios_12m >= 1000"), True)
        self.assertIs(self.ev("usuarios_12m < 1000"), False)

    def test_bandera_sola(self):
        self.assertIs(self.ev("llm"), True)
        self.assertIs(self.ev("pagos"), False)

    def test_and_or_precedencia_y_parentesis(self):
        self.assertIs(self.ev("pagos == true or llm == true and baas == 'supabase'"), True)
        self.assertIs(self.ev("(pagos == true or llm == true) and baas == 'firebase'"), False)
        self.assertIs(self.ev("not pagos"), True)

    def test_desconocido_tri_estado(self):
        self.assertIsNone(self.ev("salud == true"))
        self.assertIsNone(self.ev("bandera_ausente == true"))
        self.assertIs(self.ev("salud == true or llm == true"), True)
        self.assertIs(self.ev("salud == true and pagos == true"), False)
        self.assertIsNone(self.ev("salud == true and llm == true"))
        self.assertIsNone(self.ev("not salud"))

    def test_perfil_con_banderas_anidadas(self):
        perfil = {"version_esquema": "1", "banderas": {"llm": True}}
        self.assertIs(catalogo.evaluar_condicion("llm == true", perfil), True)

    def test_rechaza_codigo_arbitrario(self):
        for cond in ("__import__('os').system('x')", "llm == true; rm", "baas.__class__", "",
                     "llm ==", "(llm == true", "llm == true)", "a == b", "1 == 1",
                     "llm == true and", "llm === true", "llm >= 'x'"):
            with self.assertRaises(catalogo.ErrorCondicion, msg=cond):
                catalogo.evaluar_condicion(cond, self.P)

    def test_nombres_en_condicion(self):
        self.assertEqual(catalogo.nombres_en_condicion("llm == true and (salud == true or ue)"),
                         {"llm", "salud", "ue"})
        self.assertEqual(catalogo.nombres_en_condicion("siempre"), set())


class TestControlesAplicables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = catalogo.cargar_catalogo()

    @staticmethod
    def perfil(**kw):
        base = {"baas": "ninguno", "ssr_serverless": False, "llm": False, "pagos": False, "emails": False,
                "docker": False, "iac": False, "k8s": False, "movil": False, "pwa": False,
                "multi_idioma": False, "agente_ia": False, "datos_personales": False, "salud": False,
                "menores": False, "ue": False, "datos_reales_cargados": False, "usuarios_3m": 10,
                "usuarios_12m": 100}
        base.update(kw)
        return {"version_esquema": "1", "banderas": base}

    def ids(self, perfil, gate_max="N5"):
        return {c["id"]: c for c in catalogo.controles_aplicables(perfil, gate_max, catalogo=self.cat)}

    def test_filtra_por_gate(self):
        res = self.ids(self.perfil(), "N1")
        self.assertIn("SEG-SECRETO-REPO", res)
        self.assertNotIn("SEG-DEPS-CVE-CRIT", res)
        self.assertTrue(all(c["gate"] == "N1" for c in res.values()))

    def test_condicionales(self):
        sin = self.ids(self.perfil())
        self.assertNotIn("SEG-LLM-CLAVE", sin)
        self.assertNotIn("DAT-RLS-ON", sin)
        self.assertNotIn("SEG-PAGOS-FIRMA", sin)
        con = self.ids(self.perfil(llm=True, baas="supabase", pagos=True))
        for cid in ("SEG-LLM-CLAVE", "DAT-RLS-ON", "SEG-PAGOS-FIRMA", "ESC-LLM-TOPE"):
            self.assertIn(cid, con)
            self.assertEqual(con[cid]["aplicabilidad"], "aplica")

    def test_condicion_desconocida_queda_aplicable_marcada(self):
        res = self.ids(self.perfil(llm=None))
        self.assertIn("SEG-LLM-CLAVE", res)
        self.assertEqual(res["SEG-LLM-CLAVE"]["aplicabilidad"], "desconocida")

    def test_severidad_contextual_salud_datos_reales(self):
        res = self.ids(self.perfil(baas="supabase", salud=True, datos_reales_cargados=True), "N1")
        for cid in ("DAT-RLS-ON", "DAT-RLS-PERMISIVA", "SEG-IDOR", "DAT-BUCKETS"):
            self.assertIn(cid, res, cid)
            self.assertEqual(res[cid]["gate"], "N1")
            self.assertEqual(res[cid]["severidad_base"], "critica")
            self.assertTrue(res[cid]["bloquea_global"])
            self.assertIn("reglas_contextuales", res[cid])

    def test_rls_on_n1_con_datos_reales_sin_salud(self):
        res = self.ids(self.perfil(baas="supabase", datos_reales_cargados=True), "N1")
        self.assertIn("DAT-RLS-ON", res)
        self.assertNotIn("SEG-IDOR", res)

    def test_auditoria_accesos_sube_a_n2_con_salud(self):
        self.assertNotIn("DAT-AUDITORIA-ACCESOS", self.ids(self.perfil(), "N2"))
        self.assertIn("DAT-AUDITORIA-ACCESOS", self.ids(self.perfil(salud=True), "N2"))

    def test_no_modifica_catalogo(self):
        antes = json.dumps(self.cat, sort_keys=True)
        self.ids(self.perfil(baas="supabase", salud=True, datos_reales_cargados=True))
        self.assertEqual(antes, json.dumps(self.cat, sort_keys=True))

    def test_gate_invalido(self):
        with self.assertRaises(ValueError):
            catalogo.controles_aplicables(self.perfil(), "N9", catalogo=self.cat)


if __name__ == "__main__":
    unittest.main()
