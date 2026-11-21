"""Tests de DECISIONES.md #4 (lo legal avisa, no bloquea), #5 (SUS en N4 sin condición) y de los
pendientes de integración de 10-f0-f1-resultados.md §6 (D39, fusión de hallazgos, CVE por severidad
real y zizmor --persona).
"""
import json
import re
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import catalogo  # noqa: E402
import estado  # noqa: E402
import gates  # noqa: E402
import render_informe  # noqa: E402
import utiles  # noqa: E402
from normalizar import comun  # noqa: E402
from normalizar import osv as n_osv  # noqa: E402
from normalizar import run as n_run  # noqa: E402

LEGALES = ("OPS-PRIVACIDAD", "OPS-LEY-VIGENCIA", "OPS-LLM-PII", "OPS-DERECHOS-TITULAR", "OPS-LICITUD",
           "OPS-TRANSFERENCIAS", "OPS-BRECHAS", "OPS-JURIDICO", "OPS-EIPD", "OPS-RETENCION")
TITULO_AVISO = "⚠ Aviso legal — verificación del creador"
BANDERAS_FALSAS = {b: False for b in utiles.BANDERAS_ARCHIVOS + utiles.BANDERAS_ENTREVISTA}
BANDERAS_FALSAS.update(baas="ninguno", usuarios_3m=0, usuarios_12m=0)


def perfil(**cambios):
    b = dict(BANDERAS_FALSAS)
    b.update(cambios)
    return {"version_esquema": "1", "banderas": b}


def por_id():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


def ctrl(id_, **kw):
    base = {"id": id_, "titulo": id_, "alias": [], "dominio": id_.split("-")[0], "etapa": "E5", "gate": "N2",
            "severidad_base": "alta", "metodo": "manual", "herramientas": [], "condicion": "siempre",
            "bloquea_global": False, "mapea_reglas": [], "esfuerzo": "S", "aplicabilidad": "aplica"}
    base.update(kw)
    return base


def calc_estado(controles, hallazgos=(), herr=None, modo="estandar", **kw):
    indice = {c["id"]: c for c in controles}
    res = estado.calcular(indice, list(hallazgos), herr or {}, set(), modo, "2026-11-18", **kw)
    return {r["control"]: r for r in res}


# ============================================================================ DECISIÓN 4

class TestCatalogoLegal(unittest.TestCase):
    def test_legales_con_aviso_y_sin_bloqueo(self):
        cat = por_id()
        for cid in LEGALES:
            self.assertIs(cat[cid].get("aviso_legal"), True, cid)
            self.assertIs(cat[cid]["bloquea_global"], False, cid)

    def test_no_legales_sin_aviso(self):
        cat = por_id()
        for cid in ("SEG-SECRETO-REPO", "OPS-HEALTH", "UX-SUS-68", "DAT-RLS-ON"):
            self.assertFalse(cat[cid].get("aviso_legal", False), cid)

    def test_regla_de_bloqueo_sin_ops_legal(self):
        fuente = (RAIZ / "scripts" / "gates.py").read_text(encoding="utf-8")
        self.assertNotIn("OPS-legal", fuente)


class TestEstadoLegal(unittest.TestCase):
    def test_manual_pendiente_aunque_una_herramienta_pase(self):
        c = ctrl("OPS-X", metodo="mixto", herramientas=["bearer"], aviso_legal=True)
        r = calc_estado([c], herr={"bearer": "ok"})
        self.assertEqual(r["OPS-X"]["estado"], "manual_pendiente")
        self.assertIn("creador", r["OPS-X"]["motivo"])

    def test_manual_pendiente_con_aplicabilidad_desconocida_y_fuera_de_modo(self):
        c = ctrl("OPS-X", metodo="llm", herramientas=["revisor-arquitectura"], gate="N4",
                 aplicabilidad="desconocida", aviso_legal=True)
        r = calc_estado([c], modo="rapido")
        self.assertEqual(r["OPS-X"]["estado"], "manual_pendiente")

    def test_declaracion_sin_datos_personales_no_aplica(self):
        c = ctrl("OPS-X", aplicabilidad="desconocida", aviso_legal=True)
        decl = {"fecha": "2026-11-18", "fuente": "perfil.json", "banderas": {"datos_personales": False}}
        r = calc_estado([c], declaracion=decl)
        self.assertEqual(r["OPS-X"]["estado"], "no_aplica")
        self.assertIn("el creador declaró que no usa datos personales", r["OPS-X"]["motivo"])
        self.assertIn("2026-11-18", r["OPS-X"]["motivo"])

    def test_declaracion_no_afecta_a_controles_no_legales(self):
        c = ctrl("OPS-Y")
        decl = {"fecha": "2026-11-18", "fuente": "perfil.json", "banderas": {"datos_personales": False}}
        r = calc_estado([c], declaracion=decl)
        self.assertEqual(r["OPS-Y"]["estado"], "manual_pendiente")

    def test_fail_legal_se_informa(self):
        c = ctrl("OPS-X", aviso_legal=True)
        h = {"id": "H-1", "control": "OPS-X", "severidad": "alta", "gate": "N2", "estado_hallazgo": "abierto"}
        r = calc_estado([c], [h])
        self.assertEqual(r["OPS-X"]["estado"], "fail")

    def test_generar_con_perfil_declarado(self):
        tmp = ap.tmp_dir()
        try:
            c = ap.preparar_corrida(tmp, perfil=perfil(datos_personales=False))
            n_run.main([str(c)])
            datos = estado.generar(c)
            r = {x["control"]: x for x in datos["controles"]}
            for cid in LEGALES:
                self.assertEqual(r[cid]["estado"], "no_aplica", cid)
                self.assertIn("el creador declaró que no usa datos personales", r[cid]["motivo"], cid)
                self.assertIn("2026-11-18", r[cid]["motivo"], cid)
        finally:
            ap.limpiar(tmp)

    def test_generar_sin_perfil_legales_manual_pendiente(self):
        tmp = ap.tmp_dir()
        try:
            c = ap.preparar_corrida(tmp)  # sin perfil.json: no se sabe si hay datos personales
            n_run.main([str(c)])
            r = {x["control"]: x for x in estado.generar(c)["controles"]}
            for cid in LEGALES:  # OPS-LLM-PII aplica: llm = true en el perfil técnico de prueba
                self.assertEqual(r[cid]["estado"], "manual_pendiente", cid)
        finally:
            ap.limpiar(tmp)

    def test_declaracion_contradictoria_no_se_aplica(self):
        tmp = ap.tmp_dir()
        try:
            c = ap.preparar_corrida(tmp, perfil=perfil(datos_personales=False, salud=True))
            n_run.main([str(c)])
            r = {x["control"]: x for x in estado.generar(c)["controles"]}
            self.assertEqual(r["OPS-PRIVACIDAD"]["estado"], "manual_pendiente")
        finally:
            ap.limpiar(tmp)


def _c(id_, gate, aviso=False):
    return {"id": id_, "titulo": id_, "dominio": id_.split("-")[0], "gate": gate, "severidad_base": "critica",
            "bloquea_global": False, "metodo": "manual", "esfuerzo": "S", "aviso_legal": aviso}


class TestGatesLegal(unittest.TestCase):
    def test_legal_no_baja_el_nivel(self):
        ind = {f"SEG-{n}": _c(f"SEG-{n}", n) for n in ("N1", "N2", "N3", "N4", "N5")}
        ind["OPS-CUENTAS"] = _c("OPS-CUENTAS", "N1")
        ind["OPS-PRIVACIDAD"] = _c("OPS-PRIVACIDAD", "N2", aviso=True)
        ind["OPS-JURIDICO"] = _c("OPS-JURIDICO", "N4", aviso=True)
        est = [{"control": k, "estado": "pass", "hallazgos": []} for k in ind]
        est[-2]["estado"] = "fail"
        est[-1]["estado"] = "manual_pendiente"
        g = gates.calcular(est, ind, [], {}, set())
        self.assertEqual(g["global"]["nivel_demostrado"], "N5")
        self.assertEqual(g["dominios"]["OPS"]["nivel_demostrado"], "N5")
        self.assertEqual(g["global"]["bloqueos"], [])
        avisos = {a["control"]: a["estado"] for a in g["global"]["avisos_legales"]}
        self.assertEqual(avisos, {"OPS-PRIVACIDAD": "fail", "OPS-JURIDICO": "manual_pendiente"})


class TestInformeLegal(unittest.TestCase):
    def _informe(self, perfil_json=None):
        tmp = ap.tmp_dir()
        self.addCleanup(ap.limpiar, tmp)
        c = ap.preparar_corrida(tmp, perfil=perfil_json)
        n_run.main([str(c)])
        render_informe.generar(c)
        return (c / "informe.md").read_text(encoding="utf-8")

    def _bloque(self, informe):
        ini = informe.index(TITULO_AVISO)
        fin = informe.index("## 1. Veredicto")
        return informe[ini:fin]

    def test_aviso_al_inicio_sin_perfil(self):
        inf = self._informe()
        self.assertIn(TITULO_AVISO, inf)
        self.assertLess(inf.index(TITULO_AVISO), inf.index("## 1. Veredicto"))
        b = self._bloque(inf)
        for texto in ("19.628", "21.719", "BCN", "manual_pendiente", "OPS-PRIVACIDAD", "revis"):
            self.assertIn(texto, b, texto)
        self.assertIn("20.584", b)  # salud desconocida: se menciona condicionada

    def test_no_afirma_cumplimiento(self):
        b = self._bloque(self._informe())
        self.assertNotRegex(b.lower(), r"\bcumplen?\b|en cumplimiento|cumplimiento verificado")
        self.assertIn("no afirma cumplimiento", b)

    def test_salud_cita_20584_y_sin_salud_no(self):
        b = self._bloque(self._informe(perfil(datos_personales=True, salud=True)))
        self.assertIn("20.584", b)
        b = self._bloque(self._informe(perfil(datos_personales=True, salud=False)))
        self.assertNotIn("20.584", b)

    def test_declaracion_registrada(self):
        inf = self._informe(perfil(datos_personales=False))
        self.assertIn("el creador declaró que no usa datos personales", inf)
        self.assertIn("2026-11-18", self._bloque(inf))


# ============================================================================ DECISIÓN 5

class TestSus68(unittest.TestCase):
    def test_catalogo_sin_condicion(self):
        c = por_id()["UX-SUS-68"]
        self.assertEqual(c["gate"], "N4")
        self.assertEqual(c["condicion"], "siempre")
        self.assertIs(c.get("exigido_sin_condicion"), True)
        ind = utiles.indice_controles({"banderas": BANDERAS_FALSAS})
        self.assertEqual(ind["UX-SUS-68"]["aplicabilidad"], "aplica")

    def test_sin_datos_sus_manual_pendiente_con_aviso(self):
        c = por_id()["UX-SUS-68"]
        c = dict(c, aplicabilidad="aplica")
        r = calc_estado([c])
        self.assertEqual(r["UX-SUS-68"]["estado"], "manual_pendiente")
        self.assertIn("SUS", r["UX-SUS-68"]["motivo"])
        self.assertIn("N4", r["UX-SUS-68"]["motivo"])

    def test_bloquea_n4_de_ux(self):
        ind = {f"UX-{n}": _c(f"UX-{n}", n) for n in ("N1", "N2", "N3")}
        ind["UX-SUS-68"] = _c("UX-SUS-68", "N4")
        est = [{"control": k, "estado": "pass", "hallazgos": []} for k in ind]
        est[-1]["estado"] = "manual_pendiente"
        g = gates.calcular(est, ind, [], {}, set())
        self.assertEqual(g["dominios"]["UX"]["nivel_demostrado"], "N3")

    def test_hoja_de_ruta_avisa(self):
        tmp = ap.tmp_dir()
        try:
            c = ap.preparar_corrida(tmp)
            n_run.main([str(c)])
            render_informe.generar(c)
            ruta = (c / "hoja-de-ruta.md").read_text(encoding="utf-8")
            self.assertIn("UX-SUS-68", ruta)
            self.assertIn("SUS", ruta)
        finally:
            ap.limpiar(tmp)


# ============================================================================ pendientes de integración

class TestD39ServiceRole(unittest.TestCase):
    def test_service_role_a_auth_cliente(self):
        self.assertEqual(catalogo.control_por_regla("semgrep", "vibe-coding.service-role-cliente"),
                         "SEG-AUTH-CLIENTE")
        self.assertEqual(por_id()["SEG-AUTH-CLIENTE"]["severidad_base"], "critica")

    def test_en_build_sigue_en_secreto_bundle(self):
        for archivo in ("dist/assets/a.js", "build/x.js", ".next/static/y.js", "out/z.js"):
            self.assertEqual(catalogo.control_por_regla("semgrep", "vibe-coding.service-role-cliente",
                                                        archivo=archivo), "SEG-SECRETO-BUNDLE", archivo)

    def test_metadata_de_la_regla(self):
        texto = (RAIZ / "reglas" / "semgrep" / "vibe-coding" / "service-role-cliente.yaml").read_text(encoding="utf-8")
        self.assertRegex(texto, r"control:\s*SEG-AUTH-CLIENTE")


def _h(herr, regla, linea=7, contenido="x = 1", archivo="src/a.js"):
    reg = {"herramienta": herr, "version": "1", "regla": regla, "archivo": archivo, "linea": linea,
           "snippet": contenido, "mensaje": regla, "evidencia": None, "severidad_herramienta": None,
           "confianza": "media", "referencias": [], "commit": None}
    return reg


class TestFusion(unittest.TestCase):
    def setUp(self):
        self.ind = utiles.indice_controles()

    def _construir(self, reg):
        return comun.construir(reg, self.ind, [])

    def test_misma_herramienta_reglas_distintas_no_se_fusionan(self):
        a = self._construir(_h("zizmor", "unpinned-uses", archivo=".github/workflows/a.yml"))
        b = self._construir(_h("zizmor", "artipacked", archivo=".github/workflows/a.yml"))
        self.assertEqual(a["control"], b["control"])
        self.assertEqual(len(comun.fusionar([a, b])), 2)

    def test_herramientas_distintas_mismo_contenido_se_fusionan(self):
        a = self._construir(_h("zizmor", "unpinned-uses", archivo=".github/workflows/a.yml", contenido="uses: x@v1"))
        b = self._construir(_h("semgrep", "yaml.github-actions.security.github-actions-mutable-action-tag.x",
                               archivo=".github/workflows/a.yml", contenido="uses: x@v1"))
        self.assertEqual(len(comun.fusionar([a, b])), 1)

    def test_herramientas_distintas_contenido_distinto_no_se_fusionan(self):
        a = self._construir(_h("zizmor", "unpinned-uses", archivo=".github/workflows/a.yml", contenido="uses: x@v1"))
        b = self._construir(_h("semgrep", "yaml.github-actions.security.github-actions-mutable-action-tag.x",
                               archivo=".github/workflows/a.yml", contenido="otra cosa"))
        self.assertEqual(len(comun.fusionar([a, b])), 2)

    def test_misma_regla_se_fusiona(self):
        a = self._construir(_h("gitleaks", "generic-api-key", contenido="KEY=1"))
        b = self._construir(_h("gitleaks", "generic-api-key", contenido="KEY = 1 "))
        self.assertEqual(len(comun.fusionar([a, b])), 1)

    def test_corrida_real_empareja_por_contenido_de_las_lineas(self):
        tmp = ap.tmp_dir()
        try:
            c = ap.preparar_corrida(tmp)
            _, todos, _ = n_run.normalizar(c)
            l13 = [h for h in todos if h["control"] == "SEG-CICD"
                   and h["ubicacion"]["archivo"] == ".github/workflows/preview.yml" and h["ubicacion"]["linea"] == 13]
            reglas = sorted(tuple(sorted(f["regla"].rsplit(".", 1)[-1] for f in h["fuente"])) for h in l13)
            self.assertEqual(reglas, [("artipacked", "pull-request-target-code-checkout"),
                                      ("github-actions-mutable-action-tag", "unpinned-uses")])
        finally:
            ap.limpiar(tmp)

    def test_informe_agrupa_instancias_por_control(self):
        tmp = ap.tmp_dir()
        try:
            c = ap.preparar_corrida(tmp)
            n_run.main([str(c)])
            inf = render_informe.generar(c)
            self.assertRegex(inf, r"### SEG-CICD — .*instancia")
        finally:
            ap.limpiar(tmp)


class TestOsvSeveridad(unittest.TestCase):
    def _datos(self, grupos, vulns):
        return {"results": [{"source": {"path": "package-lock.json"}, "packages": [
            {"package": {"name": "p", "version": "1.0.0", "ecosystem": "npm"},
             "groups": grupos, "vulnerabilities": vulns}]}]}

    def _leer(self, datos):
        tmp = ap.tmp_dir()
        self.addCleanup(ap.limpiar, tmp)
        ruta = tmp / "osv.json"
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        ind = utiles.indice_controles()
        return [comun.construir(r, ind, []) for r in n_osv.leer(ruta, {"proyecto": None, "metas": {}})]

    def test_catalogo_cve_medio(self):
        c = por_id()["SEG-DEPS-CVE-MEDIO"]
        self.assertEqual(c["gate"], "N4")
        self.assertEqual(c["severidad_base"], "media")
        self.assertFalse(c["bloquea_global"])
        self.assertEqual(catalogo.control_por_regla("osv", "media/GHSA-x"), "SEG-DEPS-CVE-MEDIO")
        self.assertEqual(catalogo.control_por_regla("osv", "baja/GHSA-x"), "SEG-DEPS-CVE-MEDIO")
        self.assertEqual(catalogo.control_por_regla("osv", "alta/GHSA-x"), "SEG-DEPS-CVE-ALTO")
        self.assertEqual(catalogo.control_por_regla("osv", "critica/GHSA-x"), "SEG-DEPS-CVE-CRIT")

    def test_ghsa_moderate_y_low_a_medio(self):
        vulns = [{"id": "GHSA-a", "database_specific": {"severity": "MODERATE"}},
                 {"id": "GHSA-b", "database_specific": {"severity": "LOW"}},
                 {"id": "GHSA-c", "database_specific": {"severity": "HIGH"}},
                 {"id": "GHSA-d", "database_specific": {"severity": "CRITICAL"}}]
        grupos = [{"ids": [v["id"]], "aliases": [], "max_severity": ""} for v in vulns]
        hs = self._leer(self._datos(grupos, vulns))
        por_control = {}
        for h in hs:
            por_control.setdefault(h["control"], []).append(h)
        self.assertEqual(sorted(por_control), ["SEG-DEPS-CVE-ALTO", "SEG-DEPS-CVE-CRIT", "SEG-DEPS-CVE-MEDIO"])
        self.assertEqual(len(por_control["SEG-DEPS-CVE-MEDIO"]), 1)
        self.assertEqual(por_control["SEG-DEPS-CVE-MEDIO"][0]["severidad"], "media")
        self.assertIn("GHSA-a", por_control["SEG-DEPS-CVE-MEDIO"][0]["evidencia"])

    def test_cvss_manda_sobre_texto(self):
        vulns = [{"id": "GHSA-e", "database_specific": {"severity": "LOW"}}]
        hs = self._leer(self._datos([{"ids": ["GHSA-e"], "aliases": [], "max_severity": "7.5"}], vulns))
        self.assertEqual([h["control"] for h in hs], ["SEG-DEPS-CVE-ALTO"])


class TestZizmorPersona(unittest.TestCase):
    def test_persona_regular_documentada(self):
        texto = (RAIZ / "scripts" / "adaptadores" / "zizmor.sh").read_text(encoding="utf-8")
        self.assertIn("--persona regular", texto)
        self.assertRegex(texto, r"(?s)persona.{0,400}(por defecto|default).{0,400}auditor")


if __name__ == "__main__":
    unittest.main()
