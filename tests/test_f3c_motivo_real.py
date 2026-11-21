"""F3-C: el motivo por control de una herramienta no_evaluado cita el motivo real del check (normalizacion.json →
estado_checks), no el texto genérico «(p. ej. sin red)». Solo cambia el texto: el estado sigue siendo no_evaluado."""
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import estado  # noqa: E402
from test_estado import ctrl  # noqa: E402

MOTIVO = "sin backend detectado (SPA): no hay dependencias de servidor conocidas"


def calcular(controles, herr, motivos=None):
    indice = {c["id"]: c for c in controles}
    res = estado.calcular(indice, [], herr, set(), "estandar", "2026-11-18", alcance={}, motivos=motivos)
    return {r["control"]: r for r in res}


class TestMotivoReal(unittest.TestCase):
    def test_no_evaluado_con_motivo_declarado(self):
        c = ctrl("SEG-IDOR", herramientas=["rutas_inventario", "nuclei"], evidencia_pass="checks_pass")
        r = calcular([c], {"rutas_inventario": "no_evaluado"}, {"rutas_inventario": MOTIVO})["SEG-IDOR"]
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertNotIn("p. ej. sin red", r["motivo"])
        self.assertIn("rutas_inventario: no evaluado: sin backend detectado (SPA)", r["motivo"])
        self.assertIn("nuclei: sin datos de la herramienta", r["motivo"])

    def test_no_evaluado_sin_motivo_conserva_texto_generico(self):
        c = ctrl("COD-TIPOS", herramientas=["tipos"], evidencia_pass="checks_pass")
        r = calcular([c], {"tipos": "no_evaluado"})["COD-TIPOS"]
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn("tipos: no evaluado por la herramienta", r["motivo"])

    def test_no_demostrable_estatico_cita_motivo(self):
        c = ctrl("DAT-GRANTS", herramientas=["rls_estatico"], evidencia_pass="no_demostrable_estatico")
        r = calcular([c], {"rls_estatico": "no_evaluado"}, {"rls_estatico": "no hay supabase/migrations/*.sql"})
        self.assertEqual(r["DAT-GRANTS"]["estado"], "no_evaluado")
        self.assertNotIn("p. ej. sin red", r["DAT-GRANTS"]["motivo"])
        self.assertIn("rls_estatico: no evaluado: no hay supabase/migrations", r["DAT-GRANTS"]["motivo"])

    def test_motivo_nunca_produce_pass(self):
        c = ctrl("SEG-A", herramientas=["gitleaks"])
        for est in ("no_evaluado", "error", "ausente", "timeout"):
            r = calcular([c], {"gitleaks": est}, {"gitleaks": "cualquier motivo"})["SEG-A"]
            self.assertNotEqual(r["estado"], "pass", est)


if __name__ == "__main__":
    unittest.main()
