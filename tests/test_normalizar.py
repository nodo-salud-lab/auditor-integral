"""Tests de scripts/normalizar/{gitleaks,sarif,osv,checks,comun,run}.py: crudo → hallazgos.jsonl."""
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "normalizar"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import catalogo  # noqa: E402
import utiles  # noqa: E402
import validar_schema  # noqa: E402
from normalizar import checks as n_checks  # noqa: E402
from normalizar import comun  # noqa: E402
from normalizar import gitleaks as n_gitleaks  # noqa: E402
from normalizar import osv as n_osv  # noqa: E402
from normalizar import sarif as n_sarif  # noqa: E402
from normalizar import run as n_run  # noqa: E402

SCHEMA = json.loads((RAIZ / "schemas" / "hallazgo.schema.json").read_text(encoding="utf-8"))
CTX = {"proyecto": ap.APP, "metas": {}}


def indice():
    return utiles.indice_controles({"banderas": {}})


def crudo(**kw):
    base = {"herramienta": "semgrep", "version": "1.0", "regla": "javascript.x.eval", "archivo": "src/a.js",
            "linea": 3, "snippet": "eval(x)", "mensaje": "eval", "severidad_herramienta": None,
            "confianza": "media", "referencias": [], "commit": None}
    base.update(kw)
    return base


class TestGitleaks(unittest.TestCase):
    def setUp(self):
        self.reg = n_gitleaks.leer(ap.FIX_CRUDO / "gitleaks.json", CTX)

    def test_lee_todos(self):
        self.assertEqual(len(self.reg), 17)
        self.assertTrue(all(r["herramienta"] == "gitleaks" for r in self.reg))

    def test_bundle_vs_repo(self):
        hs = [comun.construir(r, indice(), n_gitleaks.secretos(ap.FIX_CRUDO / "gitleaks.json")) for r in self.reg]
        por_archivo = {}
        for h in hs:
            por_archivo.setdefault(h["ubicacion"]["archivo"], set()).add(h["control"])
        self.assertEqual(por_archivo["dist/assets/index-7c1e9a4b.js"], {"SEG-SECRETO-BUNDLE"})
        self.assertEqual(por_archivo[".env"], {"SEG-SECRETO-REPO"})

    def test_evidencia_sin_secreto(self):
        datos = json.loads((ap.FIX_CRUDO / "gitleaks.json").read_text(encoding="utf-8"))
        secretos = n_gitleaks.secretos(ap.FIX_CRUDO / "gitleaks.json")
        for r in self.reg:
            h = comun.construir(r, indice(), secretos)
            for d in datos:
                self.assertNotIn(d["Secret"], h["evidencia"])
            self.assertLessEqual(len(h["evidencia"]), 300)


class TestGitleaksHistorial(unittest.TestCase):
    def test_prefijo_git(self):
        tmp = ap.tmp_dir()
        try:
            ruta = tmp / "gitleaks-git.json"
            ruta.write_text(json.dumps([{"RuleID": "github-pat", "File": "sub/proy/src/viejo.js", "StartLine": 2,
                                         "Match": "x", "Secret": "ghp_" + "A" * 36, "Commit": "a" * 40}]))
            ctx = {"proyecto": None, "metas": {"gitleaks": {"prefijo_git": "sub/proy"}}}
            reg = n_gitleaks.leer(ruta, ctx)
            self.assertEqual(reg[0]["archivo"], "src/viejo.js")
            h = comun.construir(reg[0], indice(), n_gitleaks.secretos(ruta))
            self.assertEqual(h["ubicacion"]["commit"], "a" * 40)
            self.assertNotIn("A" * 36, json.dumps(h))
        finally:
            ap.limpiar(tmp)


class TestSarif(unittest.TestCase):
    def test_semgrep(self):
        reg = n_sarif.leer(ap.FIX_CRUDO / "semgrep.sarif", CTX)
        self.assertEqual(len(reg), 7)
        self.assertEqual({r["herramienta"] for r in reg}, {"semgrep"})
        eval_ = [r for r in reg if "code-string-concat" in r["regla"]][0]
        self.assertEqual(eval_["archivo"], "server/rutas/reportes.js")
        self.assertEqual(eval_["linea"], 15)
        h = comun.construir(eval_, indice(), [])
        self.assertEqual(h["control"], "SEG-SAST-INY")
        self.assertEqual(h["fuente"][0]["version"], "1.181.0")

    def test_regla_propia_sin_ruta_absoluta(self):
        # semgrep antepone al check_id la ruta del archivo de reglas (incluida la carpeta del usuario).
        # La regla guardada debe ser estable entre máquinas y no filtrar rutas locales al LLM.
        import tempfile
        sarif = {"runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": []}}, "results": [{
            "ruleId": "Users.alguien.Desktop.X.auditor-integral.reglas.semgrep.vibe-coding.service-role-cliente",
            "message": {"text": "m"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.js"},
                                                "region": {"startLine": 3}}}]}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "s.sarif"
            ruta.write_text(json.dumps(sarif), encoding="utf-8")
            reg = n_sarif.leer(ruta, CTX)
        self.assertEqual(reg[0]["regla"], "vibe-coding.service-role-cliente")
        # D39 (tarea A2): en el código fuente va a SEG-AUTH-CLIENTE; solo en dist/build/.next/out a SECRETO-BUNDLE.
        self.assertEqual(comun.construir(reg[0], indice(), [])["control"], "SEG-AUTH-CLIENTE")

    def test_zizmor_ruta_relativa_al_proyecto(self):
        reg = n_sarif.leer(ap.FIX_CRUDO / "zizmor.sarif", CTX)
        self.assertEqual(len(reg), 6)
        self.assertTrue(all(r["archivo"].startswith(".github/workflows/") for r in reg), [r["archivo"] for r in reg])
        self.assertIn("unpinned-uses", {r["regla"] for r in reg})
        h = comun.construir(reg[0], indice(), [])
        self.assertEqual(h["control"], "SEG-CICD")
        self.assertEqual(h["confianza"], "alta")

    def test_nivel_error_no_baja_severidad(self):
        reg = n_sarif.leer(ap.FIX_CRUDO / "zizmor.sarif", CTX)
        for r in reg:
            h = comun.construir(r, indice(), [])
            self.assertEqual(h["severidad"], "alta")  # base de SEG-CICD


class TestOsv(unittest.TestCase):
    def setUp(self):
        self.reg = n_osv.leer(ap.FIX_CRUDO / "osv.json", CTX)
        self.hs = [comun.construir(r, indice(), []) for r in self.reg]

    def test_un_registro_por_paquete_y_control(self):
        claves = [(h["control"], h["evidencia"].split(":")[0]) for h in self.hs]
        self.assertEqual(len(claves), len(set(claves)))
        paquetes = {h["evidencia"].split("@")[0] for h in self.hs}
        self.assertEqual(paquetes, {"axios", "ejs", "handlebars", "jsonwebtoken", "lodash", "minimist", "shell-quote"})

    def test_criticos_a_cve_crit(self):
        crit = {h["evidencia"].split("@")[0] for h in self.hs if h["control"] == "SEG-DEPS-CVE-CRIT"}
        self.assertEqual(crit, {"ejs", "handlebars", "lodash", "minimist", "shell-quote"})
        for h in self.hs:
            if h["control"] == "SEG-DEPS-CVE-CRIT":
                self.assertEqual(h["severidad"], "critica")
                self.assertTrue(h["fuente"][0]["regla"].startswith("critica/"))

    def test_axios_alto(self):
        ax = [h for h in self.hs if h["evidencia"].startswith("axios@")]
        # Tarea A2: los avisos medios de axios van ahora a SEG-DEPS-CVE-MEDIO (severidad real).
        self.assertEqual(sorted(h["control"] for h in ax), ["SEG-DEPS-CVE-ALTO", "SEG-DEPS-CVE-MEDIO"])
        ax = [h for h in ax if h["control"] == "SEG-DEPS-CVE-ALTO"]
        self.assertEqual(ax[0]["severidad"], "alta")
        self.assertIn("8.6", ax[0]["evidencia"])

    def test_archivo_relativo(self):
        self.assertEqual({h["ubicacion"]["archivo"] for h in self.hs}, {"package-lock.json"})

    def test_cvss_9_sube_severidad(self):
        r = crudo(herramienta="osv", regla="alta/GHSA-x", severidad_herramienta="critica")
        h = comun.construir(r, indice(), [])
        self.assertEqual(h["control"], "SEG-DEPS-CVE-ALTO")
        self.assertEqual(h["severidad"], "critica")

    def test_severidad_por_cvss(self):
        self.assertEqual(n_osv.severidad_cvss("9.8"), "critica")
        self.assertEqual(n_osv.severidad_cvss("7.0"), "alta")
        self.assertEqual(n_osv.severidad_cvss("4.0"), "media")
        self.assertEqual(n_osv.severidad_cvss("3.7"), "baja")
        self.assertIsNone(n_osv.severidad_cvss(""))


class TestChecks(unittest.TestCase):
    def test_env_publicas(self):
        reg, pasan = n_checks.leer(ap.FIX_CRUDO / "check_env_publicas.json", CTX)
        self.assertEqual(len(reg), 3)
        h = comun.construir(reg[0], indice(), [])
        self.assertEqual(h["control"], "SEG-ENV-PUBLICAS")
        self.assertEqual(h["severidad"], "critica")
        self.assertNotIn(ap.canario("C03")[:31], h["evidencia"])
        self.assertEqual(pasan, [])

    def test_checks_pass(self):
        reg, pasan = n_checks.leer(ap.FIX_CRUDO / "check_archivos_clave.json", CTX)
        self.assertIn("check:archivos_clave.lockfile", pasan)
        controles = {comun.construir(r, indice(), [])["control"] for r in reg}
        self.assertEqual(controles, {"SEG-ENV-EJEMPLO", "OPS-HEALTH"})

    def test_checks_pass_como_objetos(self):
        tmp = ap.tmp_dir()
        try:
            ruta = tmp / "check_archivos_clave.json"
            ruta.write_text(json.dumps({"estado": "ok", "motivo": None, "hallazgos": [], "checks_pass": [
                {"regla": "check:archivos_clave.lockfile", "archivo": "package-lock.json", "mensaje": "ok"},
                {"regla": "readme", "archivo": "README.md", "mensaje": "ok"}]}), encoding="utf-8")
            _, pasan = n_checks.leer(ruta, CTX)
            self.assertEqual(pasan, ["check:archivos_clave.lockfile", "check:archivos_clave.readme"])
            self.assertEqual(n_checks.estado_de(ruta), ("ok", None))
            ruta.write_text(json.dumps({"estado": "no_evaluado", "motivo": "sin red", "hallazgos": [],
                                        "checks_pass": []}), encoding="utf-8")
            self.assertEqual(n_checks.estado_de(ruta), ("no_evaluado", "sin red"))
        finally:
            ap.limpiar(tmp)

    def test_severidad_sugerida_no_baja(self):
        r = crudo(herramienta="check", regla="env_publicas.x", severidad_herramienta="baja")
        self.assertEqual(comun.construir(r, indice(), [])["severidad"], "critica")

    def test_severidad_sugerida_sube(self):
        r = crudo(herramienta="check", regla="archivos_clave.health_ausente", severidad_herramienta="alta")
        h = comun.construir(r, indice(), [])
        self.assertEqual(h["control"], "OPS-HEALTH")
        self.assertEqual(h["severidad"], "alta")


class TestComun(unittest.TestCase):
    def test_fingerprint_documentado(self):
        r = crudo(archivo="./src//a.js", snippet="  eval(  x )  ")
        h = comun.construir(r, indice(), [])
        esperado = hashlib.sha256("SEG-SAST-INY|src/a.js|javascript.x.eval|eval( x )".encode()).hexdigest()
        self.assertEqual(h["fingerprint"], esperado)
        self.assertEqual(h["id"], "H-" + esperado[:12])
        self.assertEqual(h["ubicacion"]["archivo"], "src/a.js")

    def test_sin_mapeo_devuelve_none(self):
        self.assertIsNone(comun.construir(crudo(herramienta="desconocida", regla="x"), indice(), []))

    def test_valida_schema(self):
        h = comun.construir(crudo(), indice(), [])
        self.assertEqual(validar_schema.validar(h, SCHEMA), [])

    def test_fusion_misma_ubicacion_dos_herramientas(self):
        a = comun.construir(crudo(herramienta="gitleaks", regla="generic-api-key", archivo="src/k.js",
                                  snippet="KEY=1", confianza="media"), indice(), [])
        b = comun.construir(crudo(herramienta="semgrep", regla="generic.secrets.security.x", archivo="src/k.js",
                                  snippet="KEY=1", confianza="media"), indice(), [])
        self.assertEqual(a["control"], b["control"])
        f = comun.fusionar([b, a])
        self.assertEqual(len(f), 1)
        self.assertEqual([x["herramienta"] for x in f[0]["fuente"]], ["gitleaks", "semgrep"])
        self.assertEqual(f[0]["confianza"], "alta")
        self.assertEqual(f[0]["fingerprint"], min(a["fingerprint"], b["fingerprint"]))

    def test_fusion_mismo_fingerprint(self):
        a = comun.construir(crudo(commit="a" * 40), indice(), [])
        b = comun.construir(crudo(), indice(), [])
        f = comun.fusionar([a, b])
        self.assertEqual(len(f), 1)
        self.assertEqual(len(f[0]["fuente"]), 1)

    def test_tope_cinco_por_control_archivo(self):
        hs = [comun.construir(crudo(linea=i, snippet=f"eval({i})"), indice(), []) for i in range(1, 9)]
        lim = comun.limitar(hs, 5)
        self.assertEqual(len(lim), 5)
        self.assertEqual(sum(h.get("instancias_extra", 0) for h in lim), 3)
        self.assertEqual([h["ubicacion"]["linea"] for h in lim], [1, 2, 3, 4, 5])

    def test_normalizar_archivo(self):
        self.assertEqual(comun.normalizar_archivo("file:///x/y/proj/src/a.js", Path("/x/y/proj")), "src/a.js")
        self.assertEqual(comun.normalizar_archivo(str(ap.APP / ".env"), ap.APP), ".env")
        self.assertEqual(comun.normalizar_archivo("validacion/app-sembrada/.env", ap.APP), ".env")
        self.assertEqual(comun.normalizar_archivo("./a\\b.js", None), "a/b.js")
        self.assertIsNone(comun.normalizar_archivo(None, None))


class TestRun(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.corrida = ap.preparar_corrida(self.tmp)

    def tearDown(self):
        ap.limpiar(self.tmp)

    def test_cli_escribe_y_valida(self):
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "normalizar" / "run.py"), str(self.corrida)],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        hs = utiles.leer_jsonl(self.corrida / "hallazgos.jsonl")
        self.assertGreater(len(hs), 20)
        for h in hs:
            self.assertEqual(validar_schema.validar(h, SCHEMA), [], h["id"])
        todos = utiles.leer_jsonl(self.corrida / "hallazgos_todos.jsonl")
        self.assertGreaterEqual(len(todos), len(hs))
        ids = [h["id"] for h in hs]
        self.assertEqual(len(ids), len(set(ids)))
        resumen = json.loads((self.corrida / "normalizacion.json").read_text(encoding="utf-8"))
        self.assertIn("por_herramienta", resumen)
        self.assertIn("sin_mapear", resumen)
        self.assertIn("checks_pass", resumen)
        self.assertIn("check:archivos_clave.lockfile", resumen["checks_pass"])

    def test_opcion_corrida(self):
        self.assertEqual(n_run.main(["--corrida", str(self.corrida)]), 0)
        self.assertTrue((self.corrida / "hallazgos.jsonl").is_file())

    def test_tope_y_resto_en_todos(self):
        n_run.main([str(self.corrida)])
        hs = utiles.leer_jsonl(self.corrida / "hallazgos.jsonl")
        todos = utiles.leer_jsonl(self.corrida / "hallazgos_todos.jsonl")
        conteo = {}
        for h in hs:
            if h["severidad"] == "critica" and h["gate"] == "N1":
                continue  # ronda 1: el tope nunca descarta críticos de N1 (se perdía D06)
            k = (h["control"], h["ubicacion"]["archivo"])
            conteo[k] = conteo.get(k, 0) + 1
        self.assertLessEqual(max(conteo.values()), 5)
        self.assertLess(len(hs), len(todos))  # el tope sigue actuando sobre lo que no es crítico de N1
        env = [h for h in hs if h["ubicacion"]["archivo"] == ".env" and h["control"] == "SEG-SECRETO-REPO"]
        env_todos = [h for h in todos if h["ubicacion"]["archivo"] == ".env" and h["control"] == "SEG-SECRETO-REPO"]
        criticos = [h for h in env_todos if h["severidad"] == "critica" and h["gate"] == "N1"]
        self.assertGreater(len(criticos), 5)
        self.assertEqual({h["fingerprint"] for h in criticos} - {h["fingerprint"] for h in env}, set())

    def test_sin_crudo(self):
        vacia = ap.preparar_corrida(self.tmp, crudo=None, nombre="vacia")
        self.assertEqual(n_run.main([str(vacia)]), 0)
        self.assertEqual(utiles.leer_jsonl(vacia / "hallazgos.jsonl"), [])

    def test_crudo_corrupto_no_rompe(self):
        (self.corrida / "crudo" / "semgrep.sarif").write_text("{no es json", encoding="utf-8")
        self.assertEqual(n_run.main([str(self.corrida)]), 0)
        resumen = json.loads((self.corrida / "normalizacion.json").read_text(encoding="utf-8"))
        self.assertIn("semgrep.sarif", " ".join(resumen["errores_lectura"]))

    def test_catalogo_sin_reglas_sin_mapear_gitleaks(self):
        n_run.main([str(self.corrida)])
        resumen = json.loads((self.corrida / "normalizacion.json").read_text(encoding="utf-8"))
        self.assertFalse([r for r in resumen["sin_mapear"] if r.startswith("gitleaks:")])
        self.assertTrue(catalogo.control_por_regla("gitleaks", "jwt"))


if __name__ == "__main__":
    unittest.main()
