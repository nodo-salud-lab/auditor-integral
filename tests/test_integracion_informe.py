"""Integración de las tareas A1/A2/A3 en el informe y en el resumen del escaneo.

- Los fallbacks (DECISIONES.md #6) se ven en el informe como cobertura parcial: en cada hallazgo que
  aportan y en la metodología (qué herramienta real reemplazan).
- El resumen del escaneo (tabla de ejecutar_scanners) incluye todos los chequeos de TAREAS.
- La sección 5 del informe usa la marca `aviso_legal` del catálogo (no una lista fija): antes omitía
  OPS-RETENCION, que el bloque inicial sí mostraba.
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import render_informe  # noqa: E402
import resumen_crudo  # noqa: E402


def escribir(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(datos), encoding="utf-8")


class TestFallbacksEnInforme(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.corrida = Path(self.tmp.name)
        crudo = self.corrida / "crudo"
        escribir(crudo / "check_rls_estatico.json", {"check": "rls_estatico", "estado": "ok", "hallazgos": [],
                                                      "reemplaza": "splinter", "cobertura": "parcial (fallback)"})
        escribir(crudo / "check_env_publicas.json", {"check": "env_publicas", "estado": "ok", "hallazgos": []})

    def tearDown(self):
        self.tmp.cleanup()

    def test_fallbacks_de_corrida(self):
        self.assertEqual(render_informe.fallbacks_de_corrida(self.corrida), {"rls_estatico": "splinter"})

    def test_hallazgo_de_fallback_marcado(self):
        h = {"control": "DAT-RLS-ON", "severidad": "critica", "gate": "N2", "estado_hallazgo": "abierto",
             "confianza": "alta", "metodo": "determinista", "evidencia": "x", "remediacion": "r",
             "ubicacion": {"archivo": "a.sql", "linea": 3},
             "fuente": [{"herramienta": "rls_estatico", "regla": "check:rls_estatico.rls_deshabilitado"}]}
        otro = dict(h, control="SEG-ENV-PUBLICAS",
                    fuente=[{"herramienta": "env_publicas", "regla": "check:env_publicas.nombre_sensible"}])
        texto = render_informe._seccion_hallazgos([h, otro], {}, {"rls_estatico": "splinter"})
        lineas = [l for l in texto.splitlines() if l.startswith("- ")]
        self.assertIn("cobertura parcial (fallback de splinter)", lineas[0])
        self.assertNotIn("fallback", lineas[1])

    def test_metodologia_marca_fallbacks(self):
        resumen = {"herramientas": {"rls_estatico": {"version": "1", "estado": "ok"},
                                    "gitleaks": {"version": "8.30.1", "estado": "ok"}}}
        texto = render_informe._herramientas(resumen, {"rls_estatico": "splinter"})
        self.assertIn("rls_estatico 1 (ok; fallback de splinter, cobertura parcial)", texto)
        self.assertIn("gitleaks 8.30.1 (ok)", texto)


class TestSeccionLegalDesdeCatalogo(unittest.TestCase):
    def test_incluye_todo_control_con_aviso_legal(self):
        indice = {"OPS-RETENCION": {"aviso_legal": True}, "OPS-PRIVACIDAD": {"aviso_legal": True},
                  "OPS-BACKUP": {}}
        estados = [{"control": k, "estado": "manual_pendiente", "motivo": None} for k in indice]
        texto = render_informe._seccion_legal(estados, indice)
        self.assertIn("OPS-RETENCION", texto)
        self.assertIn("OPS-PRIVACIDAD", texto)
        self.assertNotIn("OPS-BACKUP", texto)


class TestResumenEscaneo(unittest.TestCase):
    def test_incluye_todos_los_checks_de_tareas(self):
        texto = (RAIZ / "scripts" / "ejecutar_scanners.sh").read_text()
        m = re.search(r"^TAREAS='(.*?)'", texto, re.S | re.M)
        checks = [l.split("|")[4] for l in m.group(1).splitlines() if l.split("|")[1] == "check"]
        nombres = [h[0] for h in resumen_crudo.HERRAMIENTAS]
        for ch in checks:
            with self.subTest(check=ch):
                self.assertIn(ch, nombres)

    def test_fallback_marcado_en_detalle(self):
        with tempfile.TemporaryDirectory() as d:
            crudo = Path(d)
            escribir(crudo / "check_sbom.json", {"estado": "ok", "hallazgos": [{}], "checks_pass": [],
                                                 "reemplaza": "syft", "cobertura": "parcial (fallback)"})
            fila = next(f for f in resumen_crudo.resumir(crudo)["herramientas"] if f["herramienta"] == "check:sbom")
            self.assertEqual(fila["hallazgos"], 1)
            self.assertEqual(fila["detalle"].get("fallback_de"), "syft")


if __name__ == "__main__":
    unittest.main()
