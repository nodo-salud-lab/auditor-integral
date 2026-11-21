"""Tests de la verdad de terreno y la app sembrada del brazo A (§11.2, F1.5).

Verifican que validacion/verdad-terreno.toml es coherente con
validacion/app-sembrada/: cada archivo:línea existe y coincide con su patrón,
los tamaños mínimos se cumplen, el criterio de reserva es el documentado y
los canarios no son claves de ejemplo que gitleaks ignora.

La app sembrada no se versiona: se materializa desde validacion/plantilla-app-sembrada/
(validacion/sembrado.py) al importar este módulo. TestPlantillas verifica que la plantilla
no tiene forma de secreto ni configuración activa y que la materialización es exacta.
"""

import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
VALIDACION = RAIZ / "validacion"
APP = VALIDACION / "app-sembrada"
if str(VALIDACION) not in sys.path:
    sys.path.insert(0, str(VALIDACION))
import sembrado  # noqa: E402

sembrado.asegurar()
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)

VERDAD = VALIDACION / "verdad-terreno.toml"
CATALOGO = RAIZ / "catalogo" / "controles.toml"

GATES = {"N1", "N2", "N3", "N4", "N5"}
SEVERIDADES = {"critica", "alta", "media", "baja", "info"}


def _num(id_):
    return int(re.sub(r"\D", "", id_))


class TestVerdadTerreno(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VERDAD, "rb") as fh:
            cls.datos = tomllib.load(fh)
        cls.defectos = cls.datos["defecto"]
        cls.limpios = cls.datos["limpio"]

    def test_tamanos_minimos(self):
        self.assertGreaterEqual(len(self.defectos), 40)
        self.assertGreaterEqual(len(self.limpios), 40)

    def test_ids_unicos_y_con_formato(self):
        ids = [d["id"] for d in self.defectos] + [l["id"] for l in self.limpios]
        self.assertEqual(len(ids), len(set(ids)))
        for d in self.defectos:
            self.assertRegex(d["id"], r"^D\d{2,}$")
        for l in self.limpios:
            self.assertRegex(l["id"], r"^L\d{2,}$")

    def test_campos_de_defecto(self):
        for d in self.defectos:
            with self.subTest(d["id"]):
                for campo in ("control", "archivo", "gate", "severidad", "detectable_en_F1",
                              "razon_detectable", "deteccion_verificada", "reservado"):
                    self.assertIn(campo, d)
                self.assertIn(d["gate"], GATES)
                self.assertIn(d["severidad"], SEVERIDADES)
                self.assertIsInstance(d["detectable_en_F1"], bool)
                self.assertRegex(d["control"], r"^(SEG|DAT|COD|UX|INF|ESC|OPS)-[A-Z0-9-]+$")
                self.assertTrue(d["razon_detectable"].strip())

    def test_lineas_coinciden_con_patron(self):
        for entrada in self.defectos + self.limpios:
            with self.subTest(entrada["id"]):
                if entrada.get("falta_archivo"):
                    self.assertTrue(entrada.get("ausencia"))
                    self.assertFalse((APP / entrada["archivo"]).exists(),
                                     "el archivo declarado como faltante existe")
                    continue
                if entrada.get("ausencia") and "linea" not in entrada:
                    continue
                ruta = APP / entrada["archivo"]
                self.assertTrue(ruta.exists(), ruta)
                if "linea" in entrada:
                    lineas = ruta.read_text(encoding="utf-8").splitlines()
                    self.assertLessEqual(entrada["linea"], len(lineas))
                    self.assertRegex(lineas[entrada["linea"] - 1], entrada["patron"])

    def test_criterio_de_reserva_documentado(self):
        for entrada in self.defectos + self.limpios:
            with self.subTest(entrada["id"]):
                esperado = _num(entrada["id"]) % 10 in (3, 6, 9)
                self.assertEqual(entrada["reservado"], esperado)
        fraccion = sum(d["reservado"] for d in self.defectos) / len(self.defectos)
        self.assertGreaterEqual(fraccion, 0.25)
        self.assertLessEqual(fraccion, 0.35)

    def test_cobertura_de_controles_pedidos(self):
        controles = {d["control"] for d in self.defectos}
        for c in ("SEG-SECRETO-REPO", "SEG-SECRETO-BUNDLE", "SEG-ENV-PUBLICAS", "SEG-DEPS-EXISTEN",
                  "SEG-DEPS-CVE-CRIT", "SEG-SAST-INY", "SEG-AUTH-CLIENTE", "SEG-CORS", "SEG-ERRORES",
                  "SEG-CICD", "SEG-AGENTES-IA", "SEG-ENV-EJEMPLO", "COD-REPRO", "COD-TESTS-HUMO", "OPS-HEALTH"):
            self.assertIn(c, controles)

    def test_mayoria_detectable_en_f1(self):
        n1_seg = [d for d in self.defectos if d["gate"] == "N1" and d["control"].startswith("SEG-")]
        self.assertGreaterEqual(len(n1_seg), 20)
        detectables = sum(d["detectable_en_F1"] for d in n1_seg)
        self.assertGreaterEqual(detectables / len(n1_seg), 0.9)

    @unittest.skipUnless(CATALOGO.exists(), "catálogo F0 aún no generado")
    def test_controles_existen_en_catalogo(self):
        with open(CATALOGO, "rb") as fh:
            ids = {c["id"] for c in tomllib.load(fh).get("control", [])}
        if not ids:
            self.skipTest("catálogo vacío")
        usados = {e["control"] for e in self.defectos + self.limpios}
        self.assertEqual(sorted(usados - ids), [], "controles de la verdad de terreno ausentes del catálogo")


class TestAppSembrada(unittest.TestCase):
    def test_sin_git_anidado(self):
        self.assertFalse((APP / ".git").exists())

    def test_canarios_no_son_claves_de_ejemplo(self):
        # Claves de EJEMPLO públicas de la documentación de AWS y Stripe, partidas para que el árbol
        # versionado no tenga literales con forma de clave.
        prohibidos = ("AKIA" + "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI" + "/K7MDENG",
                      "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc")
        for ruta in APP.rglob("*"):
            if ruta.is_file():
                texto = ruta.read_text(encoding="utf-8", errors="ignore")
                for p in prohibidos:
                    self.assertNotIn(p, texto, ruta)

    def test_archivos_esperados(self):
        for rel in (".env", "package.json", "package-lock.json", "dist/assets/index-7c1e9a4b.js",
                    ".github/workflows/preview.yml", ".mcp.json", ".claude/settings.json", "README.md"):
            self.assertTrue((APP / rel).exists(), rel)
        for rel in (".env.example", "tests", "node_modules"):
            self.assertFalse((APP / rel).exists(), rel)

    def test_app_materializada_ignorada_y_plantillas_versionables(self):
        # La app materializada (con secretos y config activa) NO puede entrar a git; las plantillas sí.
        if not (RAIZ / ".git").exists():
            self.skipTest("la raíz no es repositorio git")
        crudo = RAIZ / "tests" / "fixtures" / "crudo"
        for ruta in (APP / ".env", APP / ".mcp.json", APP / ".claude" / "settings.json",
                     APP / ".github" / "workflows" / "preview.yml", APP / "dist" / "assets" / "index-7c1e9a4b.js",
                     crudo / "app_sembrada" / "gitleaks.json"):
            r = subprocess.run(["git", "-C", str(RAIZ), "check-ignore", "-q", "--no-index", str(ruta)],
                               capture_output=True)
            self.assertEqual(r.returncode, 0, f"{ruta.relative_to(RAIZ)} no está en .gitignore")
        for plantilla, _ in sembrado.CONJUNTOS.values():
            for ruta in sembrado._archivos(plantilla):
                r = subprocess.run(["git", "-C", str(RAIZ), "check-ignore", "-q", "--no-index", str(ruta)],
                                   capture_output=True)
                self.assertNotEqual(r.returncode, 0, f"{ruta.relative_to(RAIZ)} queda excluida por .gitignore")


class TestPlantillas(unittest.TestCase):
    """Plantillas versionadas de la app sembrada y de su crudo (validacion/sembrado.py)."""

    def test_materializado_identico_a_la_plantilla(self):
        for nombre, (plantilla, destino) in sembrado.CONJUNTOS.items():
            with self.subTest(nombre):
                self.assertEqual(sembrado.diferencias(plantilla, destino), [])

    def test_materializar_en_carpeta_nueva_es_reproducible(self):
        base = TMP_BASE
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as tmp:
            destino = Path(tmp) / "app-sembrada"
            n = sembrado.materializar(sembrado.CONJUNTOS["app"][0], destino)
            self.assertEqual(n, len(sembrado._archivos(sembrado.CONJUNTOS["app"][0])))
            self.assertEqual(sembrado.diferencias(sembrado.CONJUNTOS["app"][0], destino), [])
            with self.assertRaises(FileExistsError):
                sembrado.materializar(sembrado.CONJUNTOS["app"][0], destino)

    def test_ida_y_vuelta(self):
        base = TMP_BASE
        base.mkdir(parents=True, exist_ok=True)
        for nombre, (plantilla, destino) in sembrado.CONJUNTOS.items():
            with self.subTest(nombre), tempfile.TemporaryDirectory(dir=base) as tmp:
                nueva = Path(tmp) / "plantilla"
                sembrado.plantillar(destino, nueva)
                originales = {p.relative_to(plantilla): p.read_bytes() for p in sembrado._archivos(plantilla)}
                regeneradas = {p.relative_to(nueva): p.read_bytes() for p in sembrado._archivos(nueva)}
                self.assertEqual(originales, regeneradas)

    def test_plantillas_sin_forma_de_secreto(self):
        archivos = [VALIDACION / "sembrado.py"]
        for plantilla, _ in sembrado.CONJUNTOS.values():
            archivos += sembrado._archivos(plantilla)
        for ruta in archivos:
            with self.subTest(str(ruta.relative_to(RAIZ))):
                texto = ruta.read_text(encoding="utf-8", errors="ignore")
                self.assertEqual(sembrado.formas_en(texto), [])
                for valor in sembrado.canarios().values():
                    self.assertNotIn(valor.decode(), texto)

    def test_plantillas_sin_configuracion_activa(self):
        for plantilla, _ in sembrado.CONJUNTOS.values():
            for ruta in sembrado._archivos(plantilla):
                rel = ruta.relative_to(plantilla)
                with self.subTest(str(rel)):
                    self.assertTrue(rel.name.endswith(sembrado.SUFIJO))
                    self.assertFalse(set(rel.parts) & sembrado.NOMBRES_ACTIVOS)
                    self.assertFalse(any(p.startswith(".") for p in rel.parts))

    def test_materializacion_contiene_los_canarios(self):
        # Fail-closed: si un marcador no se resolviera, la app perdería sus secretos sembrados.
        texto = (APP / ".env").read_text(encoding="utf-8")
        self.assertNotIn("@@CANARIO:", texto)
        for p in sembrado._archivos(APP):
            if ".auditoria" in p.relative_to(APP).parts:
                continue
            self.assertNotIn(b"@@CANARIO:", p.read_bytes(), p)
        self.assertGreaterEqual(len(sembrado.formas_en(texto)), 4)


if __name__ == "__main__":
    unittest.main()
