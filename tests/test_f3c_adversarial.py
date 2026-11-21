"""F3-C adversarial: intentos de romper las correcciones de F3-C (contrato, digest e informe).

Cada prueba reproduce un camino concreto. Las que fallaron antes de corregir (TDD) cubren:
1. Ubicaciones a través de una carpeta enlazada (symlink intermedio): veredictos.py contaba líneas de un archivo
   confidencial y digest.py leía su contenido como fragmento para el LLM.
2. Variantes de escritura de la misma ruta («./src/a.js», «src//a.js», mayúsculas): inflaban hallazgos de IA (un
   hallazgo por variante) y burlaban la deduplicación por línea.
3. falso_positivo con una línea inventada o lejana del hallazgo: quitaba el fail determinista (la cuota de triage
   amplió esta superficie a hallazgos medios/bajos).
4. «No corrieron»: el motivo se recortaba antes de enmascarar con los secretos de la corrida (medio secreto en el
   informe) y se escribía sin neutralizar Markdown/HTML del texto de la herramienta.
5. rutas_inventario: el motivo nombraba archivos dentro de carpetas confidenciales.
6. incierto_por_tope: la razón decía «tope anti-desborde de 25» aunque el corte fue el tope de tokens.
Las demás son de regresión (no reprodujeron un problema): cuota de candidatos a FP sin fugas, rutas fuera del
proyecto rechazadas.
"""
import json
import os
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import enmascarar  # noqa: E402
import render_informe  # noqa: E402
import rutas_inventario as ri  # noqa: E402
import veredictos  # noqa: E402
from test_f3a_veredictos import hallazgo, ver  # noqa: E402
from test_f3c_contrato import BaseC  # noqa: E402

CONFIDENCIAL = "PACIENTE-RUT-12345678"


class BaseAdv(BaseC):
    def enlazar_confidencial(self):
        dr = self.proyecto / "datos-reales"
        dr.mkdir()
        (dr / "notas.txt").write_text(f"{CONFIDENCIAL}\n" * 5, encoding="utf-8")
        os.symlink("../datos-reales", self.proyecto / "src" / "lnk")
        os.symlink(".", self.proyecto / "src" / "alias")

    def contexto(self):
        return veredictos.Contexto(self.corrida, {}, [])


class TestSymlinkIntermedio(BaseAdv):
    def test_ubicacion_por_carpeta_enlazada_no_vale(self):
        self.enlazar_confidencial()
        ctx = self.contexto()
        self.assertEqual(ctx.ubicacion_existe("src/api.js:3"), ("src/api.js", 3))
        for u in ("src/lnk/notas.txt:1", "src/alias/api.js:3", "../fuera.txt:1", "/etc/hosts:1",
                  "src/../../fuera.txt:1", "datos-reales/notas.txt:1"):
            with self.subTest(u=u):
                self.assertIsNone(ctx.ubicacion_existe(u))

    def test_fail_por_carpeta_enlazada_no_crea_hallazgo_en_confidencial(self):
        self.enlazar_confidencial()
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-IDOR", "fail", ubicaciones=["src/lnk/notas.txt:1"])])
        self.assertEqual(self.estado()["SEG-IDOR"]["estado"], "fail")
        archivos = [h["ubicacion"]["archivo"] for h in self.hallazgos_ia()]
        self.assertEqual(archivos, [None])

    def test_digest_no_lee_por_carpeta_enlazada(self):
        self.enlazar_confidencial()
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "media", "src/lnk/notas.txt", 2, conf="baja")
        self.poner_hallazgos([h])
        textos = "".join(p.read_text(encoding="utf-8") for p in sorted((self.corrida / "digest").glob("*.json")))
        self.assertNotIn(CONFIDENCIAL, textos)


class TestVariantesDeRuta(BaseAdv):
    def test_variantes_no_inflan_hallazgos(self):
        self.poner_veredictos([
            ver("revisor-autorizacion", "SEG-IDOR", "fail",
                ubicaciones=["src/api.js:10", "./src/api.js:10", "src//api.js:10", "src/./api.js:10",
                             "SRC/api.js:10"]),
            ver("revisor-autorizacion", "SEG-IDOR", "fail", razon="otra razón", ubicaciones=["./src/api.js:10"])])
        self.assertEqual(self.estado()["SEG-IDOR"]["estado"], "fail")
        ia = self.hallazgos_ia()
        self.assertEqual([(h["ubicacion"]["archivo"], h["ubicacion"]["linea"]) for h in ia], [("src/api.js", 10)])


class TestFalsoPositivoLinea(BaseAdv):
    def setUp(self):
        super().setUp()
        self.h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([self.h])

    def fp(self, ubic):
        self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "falso_positivo", hallazgo_id=self.h["id"],
                                   ubicaciones=[ubic])])
        return self.estado()["SEG-AUTH-CLIENTE"]

    def test_linea_inventada_o_lejana_no_quita_el_fail(self):
        for u in ("src/api.js:9999", "src/api.js:35", "src/api.js:0012x"):
            with self.subTest(u=u):
                self.assertEqual(self.fp(u)["estado"], "fail")
                self.assertNotIn(self.h["id"], {k for k, t in self.decisiones()["triage"].items()
                                                if t["veredicto"] == "falso_positivo"})

    def test_linea_en_la_ventana_del_hallazgo_si_aplica(self):
        self.assertNotEqual(self.fp("src/api.js:14")["estado"], "fail")
        self.assertEqual(self.decisiones()["triage"][self.h["id"]]["veredicto"], "falso_positivo")


class TestCuotaSinFugas(BaseAdv):
    """Regresión: los candidatos a FP de la cuota no traen contenido de .env*, lockfiles, crudo/ ni confidenciales,
    y la evidencia se enmascara con los secretos de la corrida."""

    def test_candidatos_no_filtran(self):
        secreto = "Qm7vT2xK" "9pL4wR8n" "Z3cY6bH1"
        (self.proyecto / ".env.local").write_text(f"VITE_X={secreto}\n", encoding="utf-8")
        (self.proyecto / "package-lock.json").write_text('{"x": "LOCKCONTENIDO"}\n', encoding="utf-8")
        (self.proyecto / "datos-reales").mkdir()
        (self.proyecto / "datos-reales" / "a.js").write_text(CONFIDENCIAL + "\n", encoding="utf-8")
        (self.corrida / "crudo" / "gitleaks.json").write_text(json.dumps([{"Secret": secreto}]), encoding="utf-8")
        env = hallazgo(1, "SEG-SECRETO-REPO", "baja", ".env.local", 1, conf="baja", herramienta="gitleaks")
        env["evidencia"] = f"VITE_X={secreto}"
        lock = hallazgo(2, "SEG-DEPS-VULN", "baja", "package-lock.json", 1, conf="baja")
        conf = hallazgo(3, "SEG-AUTH-CLIENTE", "baja", "datos-reales/a.js", 1, conf="baja")
        self.poner_hallazgos([env, lock, conf])
        t = (self.corrida / "digest" / "triage.json").read_text(encoding="utf-8")
        d = json.loads(t)
        ids = {x["id"]: x for x in d["hallazgos"]}
        self.assertIn(env["id"], ids, "el candidato de .env entra por la cuota")
        self.assertIsNone(ids[env["id"]]["fragmento"])
        self.assertIsNone(ids[lock["id"]]["fragmento"])
        self.assertNotIn(conf["id"], ids)
        for prohibido in (secreto, "LOCKCONTENIDO", CONFIDENCIAL):
            self.assertNotIn(prohibido, t)


class TestIncertidumbreVeraz(BaseAdv):
    def test_razon_de_incierto_por_tope_dice_el_corte_real(self):
        graves = [hallazgo(i, "SEG-AUTH-CLIENTE", "critica", "src/api.js", 10) for i in range(40)]
        for g in graves:
            g["evidencia"] = "g" * 280
        self.poner_hallazgos(graves)
        ind = json.loads((self.corrida / "digest" / "indice.json").read_text(encoding="utf-8"))["digests"]["triage"]
        dentro = ind["incluidos"]["criticos"] + ind["incluidos"]["altos"]
        self.assertLess(dentro, 25, "precondición: el corte fue por tokens, no por el anti-desborde de 25")
        self.poner_veredictos([])
        self.estado()
        auditor = [a for a in self.decisiones()["aplicadas"] if a["agente"] == "auditor"]
        self.assertTrue(auditor)
        # autoauditoría 2026-11-20: las entradas sintéticas del tope no se cuentan como juicios de la IA
        resumen = self.decisiones()["resumen"]
        self.assertEqual(resumen["sin_juzgar_por_tope"], len(auditor))
        self.assertEqual(resumen["aplicadas_ia"], resumen["aplicadas"] - len(auditor))
        triage = self.decisiones()["triage"]
        for a in auditor:
            self.assertNotRegex(a["razon"], r"anti-desborde")
            self.assertRegex(a["razon"], r"tokens")
            self.assertNotRegex(triage[a["hallazgo_id"]]["razon"], r"25")


class TestMotivoNoCorrieron(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        (self.tmp / "crudo").mkdir()

    def tearDown(self):
        ap.limpiar(self.tmp)

    def informe(self, error):
        (self.tmp / "crudo" / "tipos.meta.json").write_text(json.dumps({"estado": "error", "error": error}),
                                                             encoding="utf-8")
        texto = render_informe.seccion_que_hizo({"herramientas": {"tipos": {"estado": "error"}}}, [], {}, [], None,
                                                "estandar", motivos=render_informe.motivos_herramientas(self.tmp))
        # generar() enmascara el informe final con los secretos de la corrida: se reproduce aquí
        return enmascarar.enmascarar_texto(texto, enmascarar.secretos_de_corrida(self.tmp))

    def test_sin_medio_secreto(self):
        secreto = "Qm7vT2xK" "9pL4wR8n" "Z3cY6bH1"
        self.assertEqual(enmascarar.enmascarar_texto(secreto), secreto, "precondición: ningún patrón lo detecta")
        (self.tmp / "crudo" / "gitleaks.json").write_text(json.dumps([{"Secret": secreto}]), encoding="utf-8")
        texto = self.informe("x" * 185 + " " + secreto + " fin")
        self.assertNotIn(secreto[:10], texto)

    def test_sin_inyeccion_markdown_ni_html(self):
        texto = self.informe("tsc: ver [informe verificado](https://evil.example/x) <img src=x onerror=alert(1)>")
        self.assertNotIn("[informe verificado](", texto)
        self.assertNotIn("<img", texto)
        self.assertIn("evil.example", texto, "el texto se conserva, neutralizado")


class TestJuezOmitidoInforme(BaseAdv):
    def test_motivo_de_omision_neutralizado_en_el_informe(self):
        self.omitir("autorizacion", "falta inventario (archivo app/<img src=x onerror=alert(1)>/route.js) "
                                    "[ver](https://evil.example)")
        self.poner_veredictos([])
        self.estado()
        texto = veredictos.seccion_informe(self.corrida)
        self.assertIn("juez omitido", texto)
        self.assertNotIn("<img", texto)
        self.assertNotIn("[ver](", texto)


class TestSenalesConfidenciales(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_motivo_no_nombra_archivos_confidenciales(self):
        (self.dir / "package.json").write_text(json.dumps({"dependencies": {"react": "18.3.1"}}), encoding="utf-8")
        ruta = self.dir / "datos-reales" / "app" / "api" / "route.js"
        ruta.parent.mkdir(parents=True)
        ruta.write_text("export function GET() {}\n", encoding="utf-8")
        res = ri.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertNotIn("datos-reales", res["motivo"])


if __name__ == "__main__":
    unittest.main()
