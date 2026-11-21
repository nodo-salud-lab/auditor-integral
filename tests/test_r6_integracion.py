"""Ronda 6, integración (DECISIONES.md #12): coherencia entre los cuatro grupos (secretos, datos, stack, gates-cli).

1. Catálogo: los hallazgos que la ronda 6 dejó de tratar como bloqueo (JWT anon, secretos locales ignorados, PII en
   tests, rutas admin/entorno expuesto) tienen control propio y siguen visibles; los demás siguen donde estaban.
2. archivos_clave.secreto_en_env_local: .env ignorado y sin historial → SEG-SECRETO-LOCAL; cualquier otro caso sigue
   en SEG-SECRETO-REPO (fail-closed).
3. gates.tipo_proyecto lee detalle.tipo_proyecto de detectar_stack y lo traduce al vocabulario de la tabla de
   aplicabilidad; ambiguo o desconocido → None (no cambia nada).
4. roadmap.clase_secreto reconoce los prefijos de regla de normalizar/gitleaks.py.
5. estado.py cita el motivo con que un check en estado ok explica la falta de pase.
6. sbom lee requirements.lock.
Cada punto tiene casos positivos y negativos (los negativos comprueban que no se abre un pase falso).
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import archivos_clave  # noqa: E402
import catalogo  # noqa: E402
import estado  # noqa: E402
import gates  # noqa: E402
import roadmap  # noqa: E402
import sbom  # noqa: E402
import utiles  # noqa: E402
from tmp_tests import TMP_BASE  # noqa: E402

FECHA = "2026-11-20"


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


class TestCatalogo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogo = catalogo.cargar_catalogo()

    def ctl(self, herramienta, regla, archivo=None):
        return catalogo.control_por_regla(herramienta, regla, self.catalogo, archivo=archivo)

    def test_anon_y_local_van_a_secreto_local(self):
        self.assertEqual(self.ctl("gitleaks", "jwt-anon-publico:jwt", "src/cliente.js"), "SEG-SECRETO-LOCAL")
        self.assertEqual(self.ctl("gitleaks", "jwt-anon-publico:jwt", "dist/assets/index.js"), "SEG-SECRETO-LOCAL")
        self.assertEqual(self.ctl("gitleaks", "secreto-local-ignorado:generic-api-key", "datos/x.json"),
                         "SEG-SECRETO-LOCAL")
        self.assertEqual(self.ctl("check", "archivos_clave.secreto_en_env_local", ".env.local"), "SEG-SECRETO-LOCAL")

    def test_secretos_reales_siguen_en_repo_y_bundle(self):
        # negativos: sin prefijo (service_role, otro rol, ilegible, cualquier proveedor) nada cambia
        self.assertEqual(self.ctl("gitleaks", "jwt", "src/cliente.js"), "SEG-SECRETO-REPO")
        self.assertEqual(self.ctl("gitleaks", "stripe-access-token", "server/pago.js"), "SEG-SECRETO-REPO")
        self.assertEqual(self.ctl("gitleaks", "jwt", "dist/assets/index.js"), "SEG-SECRETO-BUNDLE")
        self.assertEqual(self.ctl("check", "archivos_clave.secreto_en_env", ".env"), "SEG-SECRETO-REPO")

    def test_controles_nuevos_no_bloquean_y_son_de_baja_o_media(self):
        c = cat()
        local, pii_test = c["SEG-SECRETO-LOCAL"], c["DAT-PII-TEST"]
        self.assertFalse(local["bloquea_global"])
        self.assertFalse(pii_test["bloquea_global"])
        self.assertEqual(local["severidad_base"], "baja")
        self.assertEqual(pii_test["severidad_base"], "media")
        self.assertNotIn("SEG-SECRETO-LOCAL", gates.CONTROLES_SECRETO)
        # siguen visibles: el control tiene reglas mapeadas y su fail cuenta en el nivel del dominio
        self.assertTrue(local["mapea_reglas"])
        self.assertEqual(local["evidencia_pass"], "ausencia_suficiente")
        self.assertEqual(pii_test["evidencia_pass"], "no_demostrable_estatico")

    def test_pii_en_test_no_es_dat_pii_repo(self):
        self.assertEqual(self.ctl("check", "datos_confidenciales.pii_en_test", "tests/fixtures/u.csv"), "DAT-PII-TEST")
        self.assertEqual(self.ctl("check", "datos_confidenciales.pii_tabular", "data/u.csv"), "DAT-PII-REPO")

    def test_rutas_inventario_mapeadas(self):
        self.assertEqual(self.ctl("check", "rutas_inventario.ruta_admin_sin_auth", "routes/admin.js"), "SEG-BFLA")
        self.assertEqual(self.ctl("check", "rutas_inventario.entorno_expuesto", "server/index.js"), "SEG-ERRORES")
        self.assertEqual(cat()["SEG-ERRORES"]["severidad_base"], "media")
        self.assertFalse(cat()["SEG-ERRORES"]["bloquea_global"])


def ctl_aplicable(cid):
    c = dict(cat()[cid])
    c["aplicabilidad"] = "aplica"
    return c


class TestEstadoSecretoLocal(unittest.TestCase):
    def calc(self, alcance, hallazgos=()):
        c = ctl_aplicable("SEG-SECRETO-LOCAL")
        herr = {"gitleaks": "ok", "archivos-clave": "ok", "archivos_clave": "ok"}
        return estado.calcular({c["id"]: c}, list(hallazgos), herr, set(), "profundo", FECHA, alcance=alcance)[0]

    def test_pasa_solo_si_no_quedaron_ignoradas_sin_escanear(self):
        r = self.calc({"gitleaks": {"arbol": 5, "ignoradas_pendientes": 0}})
        self.assertEqual(r["estado"], "pass", r)
        r = self.calc({"gitleaks": {"arbol": 5, "ignoradas_pendientes": 2}})
        self.assertEqual(r["estado"], "no_evaluado", r)
        self.assertIn("ignoradas", r["motivo"])
        r = self.calc({"gitleaks": {"arbol": 5}})  # meta anterior sin la clave: fail-closed
        self.assertEqual(r["estado"], "no_evaluado", r)

    def test_hallazgo_local_da_fail_sin_bloqueo(self):
        h = {"id": "H-1", "control": "SEG-SECRETO-LOCAL", "severidad": "baja", "confianza": "baja",
             "fuente": [{"herramienta": "gitleaks", "regla": "jwt-anon-publico:jwt"}],
             "ubicacion": {"archivo": "src/x.js", "linea": 3, "commit": None}}
        r = self.calc({"gitleaks": {"arbol": 5, "ignoradas_pendientes": 0}}, [h])
        self.assertEqual(r["estado"], "fail")
        indice = cat()
        g = gates.calcular([r], indice, [h], {}, set())
        self.assertEqual(g["global"]["bloqueos"], [])


class TestGatesSinBloqueoLocal(unittest.TestCase):
    def test_fail_en_local_no_bloquea_pero_en_repo_si(self):
        indice = cat()
        h_local = {"id": "H-1", "control": "SEG-SECRETO-LOCAL", "severidad": "baja", "confianza": "baja"}
        h_repo = {"id": "H-2", "control": "SEG-SECRETO-REPO", "severidad": "critica", "confianza": "alta"}
        est = [{"control": "SEG-SECRETO-LOCAL", "estado": "fail", "hallazgos": ["H-1"]},
               {"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-2"]}]
        r = gates.calcular(est, indice, [h_local, h_repo], {}, set())
        bloq = r["global"]["bloqueos"]
        self.assertEqual([b["control"] for b in bloq], ["SEG-SECRETO-REPO"])


class TestTipoProyectoDesdeStack(unittest.TestCase):
    def test_traduce_detalle(self):
        f = gates.tipo_proyecto
        self.assertEqual(f({"detalle": {"tipo_proyecto": ["cli-python"]}}), "cli_libreria")
        self.assertEqual(f({"detalle": {"tipo_proyecto": ["libreria-python"]}}), "cli_libreria")
        self.assertEqual(f({"detalle": {"tipo_proyecto": ["movil"]}}), "movil")
        self.assertEqual(f({"detalle": {"tipo_proyecto": "spa"}}), "spa")
        self.assertEqual(f({"detalle": {"tipo_proyecto": ["servidor-web"]}}), "web")

    def test_ambiguo_o_desconocido_no_cambia_nada(self):
        f = gates.tipo_proyecto
        for t in ({"detalle": {"tipo_proyecto": ["desconocido"]}}, {"detalle": {"tipo_proyecto": []}},
                  {"detalle": {"tipo_proyecto": ["movil", "cli-python"]}}, {"detalle": {"tipo_proyecto": ["otro"]}},
                  {"detalle": {"tipo_proyecto": [3]}}, {"detalle": None}):
            self.assertIsNone(f(t), t)

    def test_raiz_tiene_prioridad(self):
        self.assertEqual(gates.tipo_proyecto({"tipo_proyecto": "movil", "detalle": {"tipo_proyecto": ["cli-python"]}}),
                         "movil")

    def test_servidor_web_no_toca_controles(self):
        est = [{"control": "SEG-HEADERS", "estado": "no_evaluado", "hallazgos": [], "motivo": "x"}]
        self.assertEqual(gates.ajustar_tipo_proyecto(est, gates.tipo_proyecto(
            {"detalle": {"tipo_proyecto": ["servidor-web"]}})), [])
        self.assertEqual(est[0]["estado"], "no_evaluado")


class TestClaseSecretoPorPrefijo(unittest.TestCase):
    def h(self, *reglas, commit=None):
        return {"fuente": [{"herramienta": "gitleaks", "regla": r} for r in reglas],
                "ubicacion": {"archivo": "a", "linea": 1, "commit": commit}}

    def test_prefijos(self):
        self.assertEqual(roadmap.clase_secreto(self.h("jwt-anon-publico:jwt")), "publica")
        self.assertEqual(roadmap.clase_secreto(self.h("secreto-local-ignorado:private-key")), "no_versionado")

    def test_mezcla_o_historial_cuenta_como_versionado(self):
        self.assertEqual(roadmap.clase_secreto(self.h("jwt-anon-publico:jwt", "jwt")), "versionado")
        self.assertEqual(roadmap.clase_secreto(self.h("jwt-anon-publico:jwt", commit="abc")), "versionado")
        self.assertEqual(roadmap.clase_secreto(self.h("generic-api-key")), "versionado")
        self.assertEqual(roadmap.clase_secreto({"fuente": [], "ubicacion": {}}), "versionado")


class TestSecretoEnEnvLocal(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.d = Path(tempfile.mkdtemp(dir=TMP_BASE))

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.d), "-c", "user.email=t@example.test", "-c", "user.name=t",
                        "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)

    def escribir(self, rel, texto):
        p = self.d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")

    def subreglas(self):
        res = archivos_clave.analizar(self.d)
        return sorted((h["regla"].split(".", 1)[-1], h["severidad_sugerida"], h.get("archivo") or "")
                      for h in res["hallazgos"] if "secreto_en_env" in h["regla"])

    VALOR = "DB_PASSWORD=Zq8" + "rT2vLm9wKp4\n"

    def test_ignorado_sin_historial_es_local(self):
        self.git("init", "-q")
        self.escribir(".gitignore", ".env.local\n")
        self.escribir("README.md", "x\n")
        self.git("add", ".gitignore", "README.md")
        self.git("commit", "-q", "-m", "inicio")
        self.escribir(".env.local", self.VALOR)
        s = self.subreglas()
        self.assertEqual([x[0] for x in s], ["secreto_en_env_local"], s)
        self.assertEqual(s[0][1], "baja")

    def test_no_ignorado_sigue_en_repo(self):
        self.git("init", "-q")
        self.escribir(".env", self.VALOR)
        self.assertEqual([x[0] for x in self.subreglas()], ["secreto_en_env"])

    def test_ignorado_con_historial_sigue_en_repo(self):
        self.git("init", "-q")
        self.escribir(".env", self.VALOR)
        self.git("add", ".env")
        self.git("commit", "-q", "-m", "con secreto")
        self.git("rm", "-q", "--cached", ".env")
        self.escribir(".gitignore", ".env\n")
        self.git("add", ".gitignore")
        self.git("commit", "-q", "-m", "ignorar")
        self.assertEqual([x[0] for x in self.subreglas()], ["secreto_en_env"])

    def test_sin_git_sigue_en_repo(self):
        self.escribir(".gitignore", ".env\n")
        self.escribir(".env", self.VALOR)
        self.assertEqual([x[0] for x in self.subreglas()], ["secreto_en_env"])


class TestMotivoSinPase(unittest.TestCase):
    def test_cita_el_motivo_del_check(self):
        c = ctl_aplicable("DAT-PII-REPO")
        herr = {utiles.canon_herramienta("datos_confidenciales"): "ok"}
        r = estado.calcular({c["id"]: c}, [], herr, set(), "profundo", FECHA,
                            motivos_sin_pase={"datos_confidenciales": "3 archivo(s) de datos no inspeccionables"})[0]
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn("3 archivo(s) de datos no inspeccionables", r["motivo"])
        r = estado.calcular({c["id"]: c}, [], herr, set(), "profundo", FECHA)[0]
        self.assertEqual(r["estado"], "no_evaluado")
        # Ronda 9 (DECISIONES.md #13): DAT-PII-REPO es no_demostrable_estatico; el motivo lo declara.
        self.assertIn("no lo demuestra", r["motivo"])

    def test_motivos_checks_sin_pase_solo_estado_ok(self):
        res = estado.motivos_checks_sin_pase({"estado_checks": {
            "datos_confidenciales": {"estado": "ok", "motivo": "m1"},
            "tipos": {"estado": "no_evaluado", "motivo": "m2"},
            "sbom": {"estado": "ok", "motivo": None}}})
        self.assertEqual(res, {utiles.canon_herramienta("datos_confidenciales"): "m1"})


class TestSbomRequirementsLock(unittest.TestCase):
    def test_lector(self):
        lector = next((f for cond, f in sbom.LECTORES if cond("requirements.lock")), None)
        self.assertIsNotNone(lector)
        comps = lector("flask==3.0.3\n# comentario\nrequests==2.32.3 ; python_version >= '3.9'\n")
        self.assertEqual(sorted(c["nombre"] for c in comps), ["flask", "requests"])

    def test_otros_nombres_no(self):
        for n in ("requirements.lock.bak", "poetry.lockx", "requirements"):
            self.assertIsNone(next((f for cond, f in sbom.LECTORES if cond(n)), None), n)


if __name__ == "__main__":
    unittest.main()
