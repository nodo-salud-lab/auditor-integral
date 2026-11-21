"""Ronda 7 (DECISIONES.md #12, adenda 2): sección 6d del informe.

La sección 6 solo lista críticos y altos; los hallazgos abiertos de severidad media, baja o info (RLS deny-all,
reconstrucción SQLite, PII no tabular, FK sin índice…) deben quedar visibles en informe.md (política fail-closed:
lo que se omite o rebaja queda a la vista)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import render_informe  # noqa: E402


def h(control, sev, archivo, linea, gate="N4", estado="abierto", evid="evidencia corta"):
    return {"id": f"H-{control}-{linea}", "control": control, "severidad": sev, "gate": gate,
            "estado_hallazgo": estado, "ubicacion": {"archivo": archivo, "linea": linea}, "evidencia": evid,
            "fuente": [{"herramienta": "x", "regla": "y"}], "confianza": "alta", "metodo": "determinista"}


INDICE = {"DAT-RLS-DENY-ALL": {"titulo": "RLS deny-all"}, "DAT-FK-INDICE": {"titulo": "FK con índice"},
          "SEG-X": {"titulo": "crítico"}}


class TestSeccionMenores(unittest.TestCase):
    def test_lista_media_baja_info_y_no_graves(self):
        hs = [h("DAT-RLS-DENY-ALL", "info", "supabase/migrations/001_init.sql", 13),
              h("DAT-FK-INDICE", "media", "db/schema.sql", 4, gate="N2"),
              h("SEG-X", "critica", "a.js", 1, gate="N1")]
        s = render_informe._seccion_menores(hs, INDICE)
        self.assertIn("DAT-RLS-DENY-ALL", s)
        self.assertIn("supabase/migrations/001_init.sql:13", s)
        self.assertIn("DAT-FK-INDICE", s)
        self.assertNotIn("SEG-X", s)
        self.assertLess(s.index("DAT-FK-INDICE"), s.index("DAT-RLS-DENY-ALL"))  # media antes que info
        self.assertNotIn("H-DAT", s)  # no imprime ids de hallazgo (la tabla 6b los cuenta)

    def test_no_abiertos_no_salen(self):
        s = render_informe._seccion_menores([h("DAT-FK-INDICE", "media", "x.sql", 1, estado="descartado")], INDICE)
        self.assertIn("No hay hallazgos abiertos", s)

    def test_tope_de_ubicaciones_y_evidencia(self):
        hs = [h("DAT-FK-INDICE", "media", f"m{i}.sql", i, evid="z" * 500) for i in range(8)]
        s = render_informe._seccion_menores(hs, INDICE)
        self.assertIn("y 3 más", s)
        self.assertIn("8 instancia(s)", s)
        self.assertNotIn("z" * 200, s)

    def test_plantilla_tiene_6d(self):
        tmpl = (Path(render_informe.PLANTILLAS) / "informe.md.tmpl").read_text(encoding="utf-8")
        self.assertIn("## 6d. Otros hallazgos abiertos", tmpl)
        self.assertIn("$hallazgos_menores", tmpl)
        self.assertLess(tmpl.index("## 6c."), tmpl.index("## 6d."))
        self.assertLess(tmpl.index("## 6d."), tmpl.index("## 7."))


if __name__ == "__main__":
    unittest.main()
