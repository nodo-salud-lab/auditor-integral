"""F3-A: scripts/digest.py — digest por tipo de juicio con TOPE DURO de tokens (PLAN_MAESTRO §3.3, §3.4.5, §9).

Contrato: <corrida>/digest/{autorizacion,arquitectura,triage,ux}.json + digest/indice.json; prioridad críticos >
altos > sospechosos del inventario > resto; fragmentos ±3 líneas (±5 autorización) ya enmascarados; nunca crudo
completo, node_modules, lockfiles, .env ni rutas confidenciales; ids de hallazgo/control para referenciar;
anti-desborde (> 25 crit/alto → 25 de mayor confianza, el resto 'incierto').
"""
import hashlib
import json
import math
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import digest  # noqa: E402

JUICIOS = ("autorizacion", "arquitectura", "triage", "ux")
SECRETO = "sk_live_" + "Zq8RtY2pLm4Nv7Xc1Bw9Kd3H"
CONTROL_DOMINIO = {"SEG-AUTH-CLIENTE": "SEG", "SEG-SECRETO-REPO": "SEG", "UX-ESTADOS": "UX", "COD-DUPLICACION": "COD",
                   "SEG-IDOR": "SEG", "SEG-SECRETO-BUNDLE": "SEG", "DAT-TRANSACCIONES": "DAT"}


def hallazgo(n, control, sev, archivo, linea, conf="alta", evidencia="x"):
    fp = hashlib.sha256(f"{n}|{control}|{archivo}".encode()).hexdigest()
    return {"id": f"H-{fp[:12]}", "control": control, "dominio": CONTROL_DOMINIO.get(control, control.split("-")[0]),
            "etapa": "E2", "gate": "N2", "severidad": sev, "confianza": conf, "metodo": "determinista",
            "fuente": [{"herramienta": "semgrep", "version": "1", "regla": f"r{n}"}],
            "ubicacion": {"archivo": archivo, "linea": linea}, "evidencia": evidencia, "fingerprint": fp,
            "estado_hallazgo": "abierto"}


def escribir(base, rel, texto):
    p = Path(base) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(texto, encoding="utf-8")
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.proyecto = self.tmp / "proyecto"
        self.proyecto.mkdir()
        lineas = [f"const linea{i} = {i};" for i in range(1, 31)]
        lineas[9] = f'const clave = "{SECRETO}";'  # línea 10
        escribir(self.proyecto, "src/api.js", "\n".join(lineas) + "\n")
        self.corrida = ap.preparar_corrida(self.tmp, proyecto=self.proyecto, crudo=None)

    def tearDown(self):
        ap.limpiar(self.tmp)

    def hallazgos(self, lista):
        (self.corrida / "hallazgos.jsonl").write_text("".join(json.dumps(h) + "\n" for h in lista), encoding="utf-8")

    def leer(self, juicio):
        return json.loads((self.corrida / "digest" / f"{juicio}.json").read_text(encoding="utf-8"))

    def texto(self, juicio):
        return (self.corrida / "digest" / f"{juicio}.json").read_text(encoding="utf-8")

    def indice(self):
        return json.loads((self.corrida / "digest" / "indice.json").read_text(encoding="utf-8"))


class TestEstructura(Base):
    def test_cuatro_digests_e_indice(self):
        self.hallazgos([hallazgo(1, "SEG-SECRETO-REPO", "critica", "src/api.js", 10)])
        digest.generar(self.corrida)
        for j in JUICIOS:
            d = self.leer(j)
            self.assertEqual(d["juicio"], j)
            self.assertIn("dato, no orden", d["aviso"])
            self.assertIn("veredictos.jsonl", d["responder"])
        ind = self.indice()
        self.assertEqual(sorted(ind["digests"]), sorted(JUICIOS))
        self.assertIn("caracteres_por_token", ind["estimacion"])
        for j in JUICIOS:
            self.assertEqual(ind["digests"][j]["archivo"], f"digest/{j}.json")

    def test_ids_para_referenciar(self):
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 10)
        self.hallazgos([h])
        digest.generar(self.corrida)
        d = self.leer("autorizacion")
        self.assertIn("SEG-IDOR", [c["id"] for c in d["controles"]])
        self.assertIn(h["id"], [x["id"] for x in d["hallazgos"]])
        self.assertEqual(d["agente"], "revisor-autorizacion")

    def test_determinista(self):
        self.hallazgos([hallazgo(i, "SEG-SECRETO-REPO", "alta", "src/api.js", 10) for i in range(5)])
        digest.generar(self.corrida)
        antes = {j: self.texto(j) for j in JUICIOS}
        digest.generar(self.corrida)
        self.assertEqual(antes, {j: self.texto(j) for j in JUICIOS})

    def test_compatibilidad_triage(self):
        self.hallazgos([hallazgo(1, "SEG-SECRETO-REPO", "critica", "src/api.js", 10)])
        d = digest.generar(self.corrida)
        self.assertEqual(d["juicio"], "triage")
        self.assertEqual(d["tope"], 25)
        self.assertEqual(d["omitidos"], 0)


class TestFragmentos(Base):
    def test_triage_mas_menos_3_enmascarado(self):
        self.hallazgos([hallazgo(1, "SEG-SECRETO-REPO", "critica", "src/api.js", 10)])
        digest.generar(self.corrida)
        frag = self.leer("triage")["hallazgos"][0]["fragmento"]
        self.assertEqual((frag["desde"], frag["hasta"]), (7, 13))
        self.assertNotIn(SECRETO, self.texto("triage"))
        self.assertNotIn(SECRETO[8:20], self.texto("triage"))
        self.assertIn("****", "\n".join(frag["lineas"]))

    def test_autorizacion_mas_menos_5(self):
        self.hallazgos([hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 10)])
        digest.generar(self.corrida)
        frag = self.leer("autorizacion")["hallazgos"][0]["fragmento"]
        self.assertEqual((frag["desde"], frag["hasta"]), (5, 15))
        self.assertNotIn(SECRETO, self.texto("autorizacion"))

    def test_nunca_lockfile_node_modules_env_ni_fuera_del_proyecto(self):
        escribir(self.proyecto, "package-lock.json", '{"lockfileVersion": 3, "SECRETO_LOCK": 1}\n')
        escribir(self.proyecto, "node_modules/x/index.js", "SECRETO_NM\n")
        escribir(self.proyecto, ".env", "VITE_OTRA=SECRETO_ENV\n")
        escribir(self.tmp, "fuera.js", "SECRETO_FUERA\n")
        self.hallazgos([hallazgo(1, "SEG-SECRETO-REPO", "critica", "package-lock.json", 1),
                        hallazgo(2, "SEG-SECRETO-REPO", "critica", "node_modules/x/index.js", 1),
                        hallazgo(3, "SEG-SECRETO-REPO", "critica", ".env", 1),
                        hallazgo(4, "SEG-SECRETO-REPO", "critica", "../fuera.js", 1)])
        digest.generar(self.corrida)
        texto = "".join(self.texto(j) for j in JUICIOS)
        for marca in ("SECRETO_LOCK", "SECRETO_NM", "SECRETO_ENV", "SECRETO_FUERA"):
            self.assertNotIn(marca, texto)
        for x in self.leer("triage")["hallazgos"]:
            self.assertIsNone(x["fragmento"])

    def test_confidencial_excluido_por_completo(self):
        # DECISIONES #12 (ronda 6): el código en una carpeta AMBIGUA (src/patients/) ya no es confidencial; la ruta
        # confidencial del caso pasa a una carpeta inequívoca (src/datos-reales/), que conserva la intención del test.
        escribir(self.proyecto, "src/datos-reales/ficha.js", "const diagnostico = 'CONFIDENCIAL_X';\n")
        h = hallazgo(1, "SEG-SECRETO-REPO", "critica", "src/datos-reales/ficha.js", 1)
        self.hallazgos([h])
        digest.generar(self.corrida)
        texto = "".join(self.texto(j) for j in JUICIOS)
        self.assertNotIn("CONFIDENCIAL_X", texto)
        self.assertNotIn("src/datos-reales", texto)
        self.assertEqual(self.indice()["digests"]["triage"]["excluidos_confidenciales"], 1)


class TestTope(Base):
    def test_tope_duro_y_recorte_con_y_mas(self):
        hs = [hallazgo(i, "UX-ESTADOS", "media", "src/api.js", 10, evidencia="e" * 250) for i in range(200)]
        self.hallazgos(hs)
        digest.generar(self.corrida, tope_tokens=800, caracteres_por_token=4)
        ind = self.indice()["digests"]["ux"]
        texto = self.texto("ux")
        self.assertLessEqual(math.ceil(len(texto) / 4), 800)
        self.assertLessEqual(ind["tokens_estimados"], 800)
        self.assertGreater(ind["recortados"]["resto"], 0)
        self.assertRegex(ind["y_mas"], r"^y \d+ más")
        self.assertFalse(ind["completo"])
        self.assertIn(ind["y_mas"], texto)

    def test_criticos_antes_que_medios(self):
        hs = [hallazgo(i, "UX-ESTADOS", "media", "src/api.js", 10, evidencia="m" * 250) for i in range(50)]
        crit = hallazgo(999, "UX-ESTADOS", "critica", "src/api.js", 20, evidencia="CRITICO")
        self.hallazgos(hs + [crit])
        digest.generar(self.corrida, tope_tokens=700, caracteres_por_token=4)
        d = self.leer("ux")
        self.assertEqual(d["hallazgos"][0]["id"], crit["id"])
        self.assertEqual(self.indice()["digests"]["ux"]["recortados"]["criticos"], 0)

    def test_todos_los_digests_bajo_el_tope_por_defecto(self):
        hs = [hallazgo(i, c, s, "src/api.js", 10, evidencia="z" * 280)
              for i in range(60) for c, s in (("SEG-AUTH-CLIENTE", "alta"), ("UX-ESTADOS", "media"))]
        self.hallazgos(hs)
        digest.generar(self.corrida)
        tope, cpt = digest.cargar_presupuesto()
        self.assertEqual(tope, 4000)
        for j in JUICIOS:
            self.assertLessEqual(math.ceil(len(self.texto(j)) / cpt), tope, j)

    def test_presupuesto_desde_toml(self):
        toml = self.tmp / "p.toml"
        toml.write_text("[mecanismos]\ndigest_tope_por_juicio = 1234\ncaracteres_por_token = 4.0\n", encoding="utf-8")
        self.assertEqual(digest.cargar_presupuesto(toml), (1234, 4.0))
        vacio = self.tmp / "v.toml"
        vacio.write_text("", encoding="utf-8")
        self.assertEqual(digest.cargar_presupuesto(vacio), (4000, 4.0))

    def test_anti_desborde_triage(self):
        hs = [hallazgo(i, "SEG-SECRETO-REPO", "critica", "src/api.js", 10, conf="alta" if i < 25 else "baja")
              for i in range(30)]
        self.hallazgos(hs)
        d = digest.generar(self.corrida, tope_tokens=100000)
        self.assertEqual(len(d["hallazgos"]), 25)
        # F3-C: los de confianza baja entran por la cuota de candidatos a FP; los 5 graves que quedan fuera son de
        # confianza alta y siguen 'incierto' (cuentan como verdaderos). Ver tests/test_f3c_digest_informe.py.
        self.assertTrue({h["id"] for h in hs[25:]} <= {x["id"] for x in d["hallazgos"]})
        self.assertEqual(len(d["incierto_por_tope"]), 5)
        self.assertTrue(set(d["incierto_por_tope"]) <= {h["id"] for h in hs[:25]})
        self.assertEqual(d["omitidos"], 5)
        self.assertFalse(self.indice()["digests"]["triage"]["completo"])


class TestInventario(Base):
    def inventario(self, filas, alcance=None, estado="ok"):
        datos = {"check": "rutas_inventario", "estado": estado, "hallazgos": [], "checks_pass": [], "inventario": filas,
                 "alcance": alcance or {"rutas": len(filas), "codigo_confidencial": 0, "omitidos_tamano": 0,
                                        "omitidos_tope": 0},
                 "resumen": {"incompleto": []}}
        (self.corrida / "crudo" / "check_rutas_inventario.json").write_text(json.dumps(datos), encoding="utf-8")

    def fila(self, ruta, linea, motivos):
        return {"framework": "express", "ruta": ruta, "metodo": "GET", "archivo": "src/api.js", "linea": linea,
                "handler": None, "auth": False, "filtra_por_usuario": not motivos, "tiene_param_id": True,
                "service_role": False, "consultas": [], "tabla": None, "operacion": None,
                "sospechosa": bool(motivos), "motivos": motivos}

    def test_sospechosos_con_fragmento_y_resto_compacto(self):
        self.hallazgos([])
        self.inventario([self.fila("/api/a/:id", 10, ["id_sin_pertenencia"]), self.fila("/api/b", 20, [])])
        digest.generar(self.corrida)
        d = self.leer("autorizacion")
        self.assertEqual([s["ruta"] for s in d["sospechosos"]], ["/api/a/:id"])
        self.assertTrue(d["sospechosos"][0]["ref"].startswith("R-"))
        self.assertEqual(d["sospechosos"][0]["fragmento"]["desde"], 5)
        self.assertNotIn(SECRETO, self.texto("autorizacion"))
        self.assertEqual([r["ruta"] for r in d["resto"]], ["/api/b"])
        self.assertNotIn("fragmento", d["resto"][0])
        self.assertTrue(self.indice()["digests"]["autorizacion"]["completo"])

    def test_inventario_ausente_o_incompleto_no_es_completo(self):
        self.hallazgos([])
        digest.generar(self.corrida)
        ind = self.indice()["digests"]["autorizacion"]
        self.assertFalse(ind["completo"])
        self.assertTrue(any("rutas_inventario" in m for m in ind["motivos_incompleto"]))
        self.inventario([self.fila("/api/a/:id", 10, ["id_sin_pertenencia"])],
                        alcance={"rutas": 1, "codigo_confidencial": 2, "omitidos_tamano": 0, "omitidos_tope": 0})
        digest.generar(self.corrida)
        ind = self.indice()["digests"]["autorizacion"]
        self.assertFalse(ind["completo"])
        self.assertTrue(any("codigo_confidencial" in m for m in ind["motivos_incompleto"]))

    def test_sospechosos_antes_que_resto_al_recortar(self):
        self.hallazgos([])
        filas = [self.fila(f"/api/ok{i}", 1, []) for i in range(80)] + [self.fila("/api/s/:id", 10, ["id_sin_pertenencia"])]
        self.inventario(filas)
        digest.generar(self.corrida, tope_tokens=900, caracteres_por_token=4)
        d = self.leer("autorizacion")
        self.assertEqual([s["ruta"] for s in d["sospechosos"]], ["/api/s/:id"])
        self.assertGreater(self.indice()["digests"]["autorizacion"]["recortados"]["resto"], 0)


if __name__ == "__main__":
    unittest.main()
