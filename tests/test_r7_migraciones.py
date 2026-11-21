"""Ronda 7 — grupo «migraciones» (DECISIONES.md #12, adenda 2).

Regresión de la ronda 6: migraciones_sql omitía el DROP TABLE de una reconstrucción de tabla de SQLite (CREATE nueva →
INSERT … SELECT → DROP vieja → RENAME) con el motivo «no se pierde información», aunque otra migración declarara una
tabla hija con REFERENCES vieja(id) ON DELETE CASCADE: con foreign_keys=ON el DROP borra en cascada las filas hijas
(caso real: usuarios → sesiones_acceso). Ahora:
  - con hijas CASCADE / SET NULL / SET DEFAULT (en cualquier migración del proyecto) → drop_table (alta), con la
    cascada y las hijas en el mensaje; fail-closed respecto de PRAGMA foreign_keys;
  - sin hijas → sigue omitida, pero visible: reconstruccion_sqlite (info) → DAT-MIGRACION-RECONSTRUCCION;
  - nunca hay pase con una reconstrucción presente.
"""
import secrets
import shutil
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402
TMP_BASE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "scripts"))

import catalogo  # noqa: E402
import migraciones_sql  # noqa: E402

PKG_SQLITE = '{"dependencies": {"better-sqlite3": "12"}}'
USUARIOS = ("CREATE TABLE usuarios (\n  id INTEGER PRIMARY KEY,\n  usuario TEXT NOT NULL UNIQUE\n);\n\n"
            "CREATE TABLE sesiones_acceso (\n  token_hash TEXT PRIMARY KEY,\n"
            "  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,\n  expira_en INTEGER NOT NULL\n);\n")
REBUILD_USUARIOS = ("CREATE TABLE usuarios_nueva (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT NOT NULL UNIQUE);\n"
                    "INSERT INTO usuarios_nueva (id, usuario) SELECT id, usuario FROM usuarios;\n"
                    "DROP TABLE usuarios;\nALTER TABLE usuarios_nueva RENAME TO usuarios;\n")
ALERTAS = ("CREATE TABLE pacientes (id INTEGER PRIMARY KEY);\n"
           "CREATE TABLE alertas (id INTEGER PRIMARY KEY, paciente_id INTEGER NOT NULL REFERENCES pacientes(id), "
           "nivel TEXT);\n")
REBUILD_ALERTAS = ("CREATE TABLE alertas_nueva (id INTEGER PRIMARY KEY, paciente_id INTEGER NOT NULL "
                   "REFERENCES pacientes(id), nivel TEXT CHECK (nivel IN ('a', 'r')));\n"
                   "INSERT INTO alertas_nueva (id, paciente_id, nivel) SELECT id, paciente_id, nivel FROM alertas;\n"
                   "DROP TABLE alertas;\nALTER TABLE alertas_nueva RENAME TO alertas;\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"r7m_{self.id().split('.')[-1]}_{secrets.token_hex(3)}"
        self.dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.escribir("package.json", PKG_SQLITE)

    def escribir(self, rel, texto):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p

    @staticmethod
    def por_sub(res, sub):
        return [h for h in res["hallazgos"] if h["regla"] == f"check:migraciones_sql.{sub}"]


class TestReconstruccionConHijas(Base):
    def test_cascada_en_otra_migracion_da_drop_table_alta(self):
        """Caso rehabilitaencasa: 003 declara la hija con ON DELETE CASCADE; 007 reconstruye usuarios."""
        self.escribir("server/src/migrations/003_usuarios.sql", USUARIOS)
        self.escribir("server/src/migrations/007_usuarios_autoincrement.sql", REBUILD_USUARIOS)
        res = migraciones_sql.analizar(self.dir)
        drops = self.por_sub(res, "drop_table")
        self.assertEqual(len(drops), 1)
        d = drops[0]
        self.assertEqual(d["severidad_sugerida"], "alta")
        self.assertEqual((d["archivo"], d["linea"]), ("server/src/migrations/007_usuarios_autoincrement.sql", 3))
        self.assertIn("sesiones_acceso", d["mensaje"])
        self.assertIn("ON DELETE CASCADE", d["mensaje"])
        self.assertIn("server/src/migrations/003_usuarios.sql:8", d["mensaje"])  # línea de la FK
        self.assertIn("se asume ON", d["mensaje"])
        self.assertEqual(self.por_sub(res, "reconstruccion_sqlite"), [])  # no se declara inocua
        self.assertNotIn("drop_table", [o["regla"].rsplit(".", 1)[1] for o in res.get("omitidos", [])])
        self.assertTrue(d["mensaje"].startswith("DROP TABLE usuarios borra o altera filas de tablas hijas: "
                                                "sesiones_acceso"))  # las hijas sobreviven al recorte de evidencia
        renombre = [o for o in res["omitidos"] if o["regla"].endswith(".rename")]
        self.assertEqual(len(renombre), 1)  # el RENAME no pierde datos, pero su motivo no declara la tabla inocua
        self.assertIn("se informó como drop_table", renombre[0]["motivo"])
        self.assertNotIn("ninguna migración declara", renombre[0]["motivo"])
        self.assertEqual(res["checks_pass"], [])
        self.assertEqual(catalogo.control_por_regla("check", d["regla"][len("check:"):]), "DAT-MIGRACIONES-SEGURAS")

    def test_cascada_en_la_misma_migracion(self):
        self.escribir("migrations/1.sql", USUARIOS + REBUILD_USUARIOS)
        self.assertEqual(len(self.por_sub(migraciones_sql.analizar(self.dir), "drop_table")), 1)

    def test_set_null_y_set_default_tambien(self):
        for accion in ("SET NULL", "SET DEFAULT"):
            with self.subTest(accion=accion):
                shutil.rmtree(self.dir / "migrations", ignore_errors=True)
                self.escribir("migrations/1.sql", "CREATE TABLE usuarios (id INTEGER PRIMARY KEY);\n"
                              f"CREATE TABLE notas (id INTEGER PRIMARY KEY, autor INTEGER DEFAULT 0 "
                              f"REFERENCES usuarios(id) ON UPDATE CASCADE ON DELETE {accion});\n")
                self.escribir("migrations/2.sql", REBUILD_USUARIOS)
                drops = self.por_sub(migraciones_sql.analizar(self.dir), "drop_table")
                self.assertEqual(len(drops), 1)
                self.assertIn(f"ON DELETE {accion}", drops[0]["mensaje"])

    def test_foreign_key_de_tabla_y_alter_add(self):
        self.escribir("migrations/1.sql", "CREATE TABLE usuarios (id INTEGER PRIMARY KEY);\n"
                      "CREATE TABLE a (id INTEGER, u INTEGER, FOREIGN KEY (u) REFERENCES \"usuarios\" (id) "
                      "ON DELETE CASCADE);\n"
                      "ALTER TABLE b ADD COLUMN u INTEGER REFERENCES usuarios(id) ON DELETE SET NULL;\n")
        self.escribir("migrations/2.sql", REBUILD_USUARIOS)
        d = self.por_sub(migraciones_sql.analizar(self.dir), "drop_table")[0]
        self.assertIn("a (ON DELETE CASCADE", d["mensaje"])
        self.assertIn("b (ON DELETE SET NULL", d["mensaje"])

    def test_pragma_off_no_descarta(self):
        """Fail-closed: PRAGMA foreign_keys = OFF no surte efecto dentro de una transacción; el DROP sigue saliendo."""
        self.escribir("migrations/1.sql", USUARIOS)
        self.escribir("migrations/2.sql", "PRAGMA foreign_keys = OFF;\n" + REBUILD_USUARIOS
                      + "PRAGMA foreign_keys = ON;\n")
        d = self.por_sub(migraciones_sql.analizar(self.dir), "drop_table")
        self.assertEqual(len(d), 1)
        self.assertIn("PRAGMA foreign_keys = OFF", d[0]["mensaje"])

    def test_hija_que_es_la_tabla_nueva_cuenta(self):
        """La tabla nueva con FK hacia el nombre viejo también pierde filas en el DROP (CASCADE)."""
        self.escribir("migrations/1.sql", "CREATE TABLE nodos (id INTEGER PRIMARY KEY, padre INTEGER);\n"
                      "CREATE TABLE nodos_nueva (id INTEGER PRIMARY KEY AUTOINCREMENT, padre INTEGER "
                      "REFERENCES nodos(id) ON DELETE CASCADE);\n"
                      "INSERT INTO nodos_nueva (id, padre) SELECT id, padre FROM nodos;\n"
                      "DROP TABLE nodos;\nALTER TABLE nodos_nueva RENAME TO nodos;\n")
        self.assertEqual(len(self.por_sub(migraciones_sql.analizar(self.dir), "drop_table")), 1)

    def test_hija_sin_accion_no_bloquea_la_omision(self):
        """REFERENCES sin ON DELETE (NO ACTION) no borra ni altera filas: la reconstrucción sigue omitida (info)."""
        self.escribir("migrations/1.sql", ALERTAS + "CREATE TABLE eventos (id INTEGER, alerta INTEGER "
                      "REFERENCES alertas(id) ON UPDATE CASCADE);\n")
        self.escribir("migrations/2.sql", REBUILD_ALERTAS)
        res = migraciones_sql.analizar(self.dir)
        self.assertEqual(self.por_sub(res, "drop_table"), [])
        self.assertEqual(len(self.por_sub(res, "reconstruccion_sqlite")), 1)


class TestReconstruccionSinHijasVisible(Base):
    def test_caso_006_omitida_pero_visible_como_info(self):
        """Caso 006 (alertas): sin hijas, sigue omitida y además sale como hallazgo info mapeado a un control."""
        self.escribir("server/src/migrations/001.sql", ALERTAS)
        self.escribir("server/src/migrations/006_cierre_reinicio.sql", REBUILD_ALERTAS)
        res = migraciones_sql.analizar(self.dir)
        self.assertEqual(self.por_sub(res, "drop_table"), [])
        self.assertEqual(self.por_sub(res, "rename"), [])
        info = self.por_sub(res, "reconstruccion_sqlite")
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0]["severidad_sugerida"], "info")
        self.assertEqual((info[0]["archivo"], info[0]["linea"]), ("server/src/migrations/006_cierre_reinicio.sql", 3))
        self.assertIn("alertas", info[0]["mensaje"])
        self.assertEqual(sorted(o["regla"].rsplit(".", 1)[1] for o in res["omitidos"]), ["drop_table", "rename"])
        self.assertEqual(res["checks_pass"], [])  # con una omisión no hay pase
        self.assertEqual(catalogo.control_por_regla("check", info[0]["regla"][len("check:"):]), "DAT-MIGRACION-RECONSTRUCCION")

    def test_control_info_no_bloquea_ni_pasa(self):
        c = next(x for x in catalogo.cargar_catalogo() if x["id"] == "DAT-MIGRACION-RECONSTRUCCION")
        self.assertEqual((c["severidad_base"], c["gate"], c["bloquea_global"]), ("info", "N5", False))
        self.assertEqual(c["evidencia_pass"], "no_demostrable_estatico")
        self.assertIn("migraciones_sql", c["herramientas_parciales"])

    def test_postgres_no_cambia(self):
        """Fuera de SQLite no hay omisión: el DROP sigue siendo drop_table aunque haya patrón de reconstrucción."""
        self.escribir("package.json", '{"dependencies": {"pg": "8"}}')
        self.escribir("migrations/1.sql", REBUILD_ALERTAS)
        res = migraciones_sql.analizar(self.dir)
        self.assertEqual(len(self.por_sub(res, "drop_table")), 1)
        self.assertEqual(self.por_sub(res, "reconstruccion_sqlite"), [])

    def test_analizar_archivo_sin_mapa_global_lee_el_propio(self):
        hs, om = [], []
        migraciones_sql.analizar_archivo("m.sql", USUARIOS + REBUILD_USUARIOS, hs, "sqlite", om)
        self.assertEqual([h["regla"].rsplit(".", 1)[1] for h in hs], ["drop_table"])


if __name__ == "__main__":
    unittest.main()
