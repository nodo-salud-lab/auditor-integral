"""Tests de scripts/comparar_corridas.py (auditar → corregir → re-auditar → ver el avance).

- Agrupa los cambios de estado por transición (fail → pass, pass → fail, X → no_evaluado).
- Hallazgos nuevos/resueltos por fingerprint mostrando solo control, severidad y archivo:línea: nunca la
  evidencia ni nada de crudo/.
- Aviso obligatorio de no comparabilidad si cambian modo, red («sin red») o versión del auditor.
- --proyecto toma las dos corridas propias más recientes; con menos de dos, rc 4. Solo lectura.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SCRIPT = RAIZ / "scripts" / "comparar_corridas.py"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
MARCA_EVIDENCIA = "EVIDENCIA-QUE-NO-DEBE-SALIR"
MARCA_CRUDO = "CRUDO-QUE-NO-DEBE-LEERSE"


def hallazgo(control, archivo, linea, sev="alta"):
    fp = hashlib.sha256(f"{control}|{archivo}|{linea}".encode()).hexdigest()
    return {"control": control, "severidad": sev, "fingerprint": fp, "evidencia": f"{MARCA_EVIDENCIA} {control}",
            "ubicacion": {"archivo": archivo, "linea": linea}}


class Base(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_BASE))
        self.proy = (self.tmp / "proy").resolve()
        (self.proy / ".auditoria").mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def corrida(self, nombre, estados, hallazgos=(), modo="rapido", version="0.1.0", nd="N0", sin_red=False):
        c = self.proy / ".auditoria" / nombre
        (c / "crudo").mkdir(parents=True)
        (c / "crudo" / "gitleaks.json").write_text(MARCA_CRUDO, encoding="utf-8")
        run = {"id": nombre, "modo": modo, "auditor_version": version, "proyecto": str(self.proy),
               "carpeta": str(c.resolve())}
        (c / "run.json").write_text(json.dumps(run), encoding="utf-8")
        motivo = "osv-scanner: no evaluado: sin red (AUDITOR_SIN_RED): x" if sin_red else None
        controles = [{"control": k, "estado": v, "motivo": motivo if v == "no_evaluado" else None}
                     for k, v in estados.items()]
        (c / "estado.json").write_text(json.dumps({"controles": controles}), encoding="utf-8")
        g = {"modo": modo, "global": {"nivel_demostrado": nd, "nivel_potencial": nd, "listo_datos_reales": "NO",
                                      "bloqueos": []},
             "dominios": {"SEG": {"activo": True, "nivel_demostrado": nd, "nivel_potencial": nd}}}
        (c / "gates.json").write_text(json.dumps(g), encoding="utf-8")
        (c / "hallazgos.jsonl").write_text("".join(json.dumps(h) + "\n" for h in hallazgos), encoding="utf-8")
        return c

    def comparar(self, *args):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, args)],
                              capture_output=True, text=True, timeout=60)


class TestComparar(Base):
    def test_transiciones_y_hallazgos(self):
        h_viejo, h_comun, h_nuevo = (hallazgo("SEG-A", "src/a.js", 3), hallazgo("COD-B", "x.py", 1, "media"),
                                     hallazgo("DAT-C", "db.sql", 9, "critica"))
        a = self.corrida("2026-01-01_1000-sin-git", {"SEG-A": "fail", "COD-B": "pass", "DAT-C": "no_evaluado",
                                                     "UX-D": "pass"}, [h_viejo, h_comun])
        b = self.corrida("2026-01-01_1100-sin-git", {"SEG-A": "pass", "COD-B": "fail", "DAT-C": "fail",
                                                     "UX-D": "no_evaluado"}, [h_comun, h_nuevo], nd="N1")
        r = self.comparar("--antes", a, "--despues", b)
        self.assertEqual(r.returncode, 0, r.stderr)
        t = r.stdout
        self.assertIn("### fail → pass (1)\n- SEG-A", t)
        self.assertIn("### pass → fail (1)\n- COD-B", t)
        self.assertIn("### no_evaluado → fail (1)\n- DAT-C", t)
        self.assertIn("### pass → no_evaluado (1)\n- UX-D", t)
        self.assertIn("## Controles que cambiaron de estado (4)", t)
        self.assertLess(t.index("fail → pass"), t.index("pass → fail"))
        self.assertIn("| Global | N0 (pot. N0) | N1 (pot. N1) |", t)
        self.assertIn("## Hallazgos nuevos (1)\n\n- DAT-C · critica · `db.sql:9`", t)
        self.assertIn("## Hallazgos que ya no aparecen (1)", t)
        self.assertIn("- SEG-A · alta · `src/a.js:3`", t)
        self.assertNotIn("COD-B · media", t)            # común a ambas: ni nuevo ni resuelto
        self.assertNotIn(MARCA_EVIDENCIA, t)
        self.assertNotIn(MARCA_CRUDO, t)
        self.assertNotIn("Aviso: corridas no comparables", t)

    def test_avisos_de_no_comparabilidad(self):
        a = self.corrida("2026-01-01_1000-sin-git", {"SEG-A": "no_evaluado"}, modo="rapido", sin_red=True)
        b = self.corrida("2026-01-01_1100-sin-git", {"SEG-A": "pass"}, modo="estandar", version="0.2.0")
        t = self.comparar("--antes", a, "--despues", b).stdout
        self.assertIn("Aviso: corridas no comparables", t)
        self.assertIn("cambió el modo (rapido → estandar)", t)
        self.assertIn("cambió la red", t)
        self.assertIn("cambió la versión del auditor (0.1.0 → 0.2.0)", t)

    def test_solo_lectura(self):
        a = self.corrida("2026-01-01_1000-sin-git", {"SEG-A": "fail"})
        b = self.corrida("2026-01-01_1100-sin-git", {"SEG-A": "pass"})
        antes = {p: p.read_bytes() for p in self.proy.rglob("*") if p.is_file()}
        self.comparar("--antes", a, "--despues", b)
        despues = {p: p.read_bytes() for p in self.proy.rglob("*") if p.is_file()}
        self.assertEqual(antes, despues)


class TestSeleccion(Base):
    def test_proyecto_toma_las_dos_mas_recientes(self):
        self.corrida("2026-01-01_0900-sin-git", {"SEG-A": "fail"})
        self.corrida("2026-01-01_1000-sin-git", {"SEG-A": "fail"})
        self.corrida("2026-01-01_1000-sin-git-2", {"SEG-A": "pass"})
        t = self.comparar("--proyecto", self.proy).stdout
        self.assertIn("| Corrida | 2026-01-01_1000-sin-git | 2026-01-01_1000-sin-git-2 |", t)
        self.assertIn("### fail → pass (1)", t)

    def test_menos_de_dos_corridas_rc4(self):
        self.corrida("2026-01-01_0900-sin-git", {"SEG-A": "fail"})
        r = self.comparar("--proyecto", self.proy)
        self.assertEqual(r.returncode, 4)
        self.assertIn("hacen falta 2", r.stderr)

    def test_uso_incorrecto(self):
        self.assertEqual(self.comparar().returncode, 2)
        self.assertEqual(self.comparar("--proyecto", self.proy, "--antes", self.proy).returncode, 2)
        r = self.comparar("--antes", self.proy, "--despues", self.proy)
        self.assertEqual(r.returncode, 4)
        self.assertIn("falta run.json", r.stderr)


if __name__ == "__main__":
    unittest.main()
