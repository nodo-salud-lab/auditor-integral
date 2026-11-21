"""F3-C: contrato agente → script de veredictos.py (corrige pérdidas medidas en investigacion/17).

1. Un 'fail' con hallazgo_id de un hallazgo del digest del agente (mismo control) es una CONFIRMACIÓN (verdadero):
   no se descarta, no baja severidad, nunca produce pass; frente a un falso_positivo gana el fail. Si el hallazgo
   no es confirmable (otro control, no estaba en su digest, inexistente), el fail cuenta como indicio del control
   (hallazgo de IA), nunca se pierde. triage-fp no emite fail de control: ahí se descarta como antes.
2. hallazgos_ia.jsonl: un hallazgo por ubicación validada (máx. 5 por veredicto, se informa el truncado), con
   fingerprint estable por control+archivo+línea.
3. indice.json con omitir_juez=true y sin veredictos de ese agente: sus controles llm/mixto quedan no_evaluado con
   motivo «juez omitido: <motivo>» registrado en decisiones_ia.json (nunca pass).
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

from test_f3a_veredictos import Base, hallazgo, ver  # noqa: E402
import digest  # noqa: E402
import gates  # noqa: E402
import veredictos  # noqa: E402


def fp_ia(control, archivo, linea):
    return hashlib.sha256(f"ia|{control}|{archivo}|{linea}".encode("utf-8")).hexdigest()


class BaseC(Base):
    def poner_hallazgos(self, hs):
        # Desde F3-C digest.py marca omitir_juez por sí mismo (p. ej. triage/ux con 0 hallazgos). Estas pruebas
        # modelan la omisión de forma explícita con omitir(): se parte de un índice sin omisiones.
        super().poner_hallazgos(hs)
        ruta = self.corrida / "digest" / "indice.json"
        ind = json.loads(ruta.read_text(encoding="utf-8"))
        for m in ind["digests"].values():
            m["omitir_juez"], m["motivo_omision"] = False, None
            m["lanzar"] = True  # integración F3-C: lanzar=false también registra el juez (no lanzado)
        ruta.write_text(json.dumps(ind), encoding="utf-8")

    def hallazgos_ia(self):
        ruta = self.corrida / "hallazgos_ia.jsonl"
        return [json.loads(l) for l in ruta.read_text(encoding="utf-8").splitlines() if l.strip()]

    def omitir(self, juicio, motivo, quitar_controles=False):
        ruta = self.corrida / "digest" / "indice.json"
        ind = json.loads(ruta.read_text(encoding="utf-8"))
        ind["digests"][juicio]["omitir_juez"] = True
        ind["digests"][juicio]["motivo_omision"] = motivo
        ind["digests"][juicio]["lanzar"] = False
        if quitar_controles:
            ind["digests"][juicio].pop("controles", None)  # la lista del índice manda sobre la del digest
        ruta.write_text(json.dumps(ind), encoding="utf-8")
        if quitar_controles:
            rd = self.corrida / "digest" / f"{juicio}.json"
            d = json.loads(rd.read_text(encoding="utf-8"))
            d.pop("controles", None)
            rd.write_text(json.dumps(d), encoding="utf-8")


class TestFailComoConfirmacion(BaseC):
    def setUp(self):
        super().setUp()
        self.h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([self.h])

    def test_fail_con_hallazgo_id_confirma(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-AUTH-CLIENTE", "fail", hallazgo_id=self.h["id"],
                                   severidad_propuesta="baja", ubicaciones=["src/api.js:12", "src/api.js:20"])])
        e = self.estado()["SEG-AUTH-CLIENTE"]
        self.assertEqual(e["estado"], "fail")
        self.assertIn(self.h["id"], e["hallazgos"])
        d = self.decisiones()
        self.assertEqual(d["descartadas"], [])
        self.assertEqual(d["triage"][self.h["id"]]["veredicto"], "verdadero")
        self.assertRegex(d["aplicadas"][0]["efecto"], r"confirma")
        self.assertEqual(self.hallazgos_ia(), [], "una confirmación no duplica el hallazgo")
        hs = gates.veredictos.hallazgos_para_gates(self.corrida, [dict(self.h)])
        self.assertEqual(hs[0]["severidad"], "alta", "la IA nunca baja la severidad")
        self.assertEqual(hs[0]["triage"]["veredicto"], "verdadero")

    def test_fail_gana_a_falso_positivo(self):
        self.poner_veredictos([
            ver("triage-fp", "SEG-AUTH-CLIENTE", "falso_positivo", hallazgo_id=self.h["id"],
                ubicaciones=["src/api.js:12"]),
            ver("revisor-autorizacion", "SEG-AUTH-CLIENTE", "fail", hallazgo_id=self.h["id"],
                ubicaciones=["src/api.js:12"])])
        self.assertEqual(self.estado()["SEG-AUTH-CLIENTE"]["estado"], "fail")
        d = self.decisiones()
        self.assertEqual(d["triage"][self.h["id"]]["veredicto"], "verdadero")
        self.assertEqual([x["veredicto"] for x in d["descartadas"]], ["falso_positivo"])

    def test_fail_sobre_hallazgo_de_otro_control_es_indicio(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-IDOR", "fail", hallazgo_id=self.h["id"],
                                   ubicaciones=["src/api.js:10"])])
        e = self.estado()
        self.assertEqual(e["SEG-IDOR"]["estado"], "fail")
        ia = self.hallazgos_ia()
        self.assertEqual([(x["control"], x["ubicacion"]["linea"]) for x in ia], [("SEG-IDOR", 10)])
        self.assertEqual(self.decisiones()["descartadas"], [])
        self.assertNotIn(self.h["id"], self.decisiones()["triage"])

    def test_fail_con_hallazgo_inexistente_es_indicio(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-IDOR", "fail", hallazgo_id="H-abcdef123456",
                                   ubicaciones=["src/api.js:10"])])
        self.assertEqual(self.estado()["SEG-IDOR"]["estado"], "fail")
        self.assertEqual(len(self.hallazgos_ia()), 1)

    def test_fail_de_triage_fp_no_confirmable_se_descarta(self):
        self.poner_veredictos([ver("triage-fp", "SEG-IDOR", "fail", hallazgo_id=self.h["id"],
                                   ubicaciones=["src/api.js:10"])])
        e = self.estado()["SEG-IDOR"]
        self.assertNotEqual(e["estado"], "pass")
        self.assertEqual(len(self.decisiones()["descartadas"]), 1)
        self.assertEqual(self.hallazgos_ia(), [])

    def test_fail_de_triage_fp_confirma(self):
        self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "fail", hallazgo_id=self.h["id"])])
        self.estado()
        self.assertEqual(self.decisiones()["triage"][self.h["id"]]["veredicto"], "verdadero")

    def test_falso_positivo_critico_sigue_sin_pass(self):
        h = hallazgo(2, "SEG-AUTH-CLIENTE", "critica", "src/api.js", 5)
        self.poner_hallazgos([h])
        self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "falso_positivo", hallazgo_id=h["id"],
                                   ubicaciones=["src/api.js:5"])])
        self.assertNotEqual(self.estado()["SEG-AUTH-CLIENTE"]["estado"], "pass")


class TestUnHallazgoPorUbicacion(BaseC):
    def test_tres_ubicaciones_tres_hallazgos(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail",
                                   ubicaciones=["src/api.js:7", "src/api.js:13", "src/api.js:23"])])
        e = self.estado()["SEG-BFLA"]
        ia = self.hallazgos_ia()
        self.assertEqual(sorted(x["ubicacion"]["linea"] for x in ia), [7, 13, 23])
        for x in ia:
            fp = fp_ia("SEG-BFLA", "src/api.js", x["ubicacion"]["linea"])
            self.assertEqual(x["fingerprint"], fp)
            self.assertEqual(x["id"], f"H-{fp[:16]}")
            self.assertIn(x["id"], e["hallazgos"])
        a = self.decisiones()["aplicadas"][0]
        self.assertEqual(sorted(a["hallazgos_ia"]), sorted(x["id"] for x in ia))
        self.assertNotIn("ubicaciones_truncadas", a)

    def test_fingerprint_estable_entre_razones(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail", razon="uno",
                                   ubicaciones=["src/api.js:7"])])
        self.estado()
        a = self.hallazgos_ia()
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "incierto", razon="otra razón",
                                   ubicaciones=["src/api.js:7"])])
        self.estado()
        self.assertEqual([x["fingerprint"] for x in a], [x["fingerprint"] for x in self.hallazgos_ia()])

    def test_ubicaciones_invalidas_se_omiten(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail",
                                   ubicaciones=["src/no_existe.js:3", "src/api.js:9999", "src/api.js:8",
                                                "node_modules/a/index.js:1"])])
        self.estado()
        self.assertEqual([x["ubicacion"]["linea"] for x in self.hallazgos_ia()], [8])

    def test_sin_ubicacion_valida_un_hallazgo_sin_archivo(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail", ubicaciones=["src/no_existe.js:3"])])
        self.assertEqual(self.estado()["SEG-BFLA"]["estado"], "fail")
        ia = self.hallazgos_ia()
        self.assertEqual(len(ia), 1)
        self.assertIsNone(ia[0]["ubicacion"]["archivo"])

    def test_tope_de_cinco_e_informe_de_truncado(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail",
                                   ubicaciones=[f"src/api.js:{i}" for i in range(1, 9)])])
        self.estado()
        self.assertEqual(len(self.hallazgos_ia()), 5)
        a = self.decisiones()["aplicadas"][0]
        self.assertEqual(a["ubicaciones_truncadas"], 3)
        self.assertRegex(a["efecto"], r"trunc")

    def test_misma_linea_de_dos_veredictos_no_duplica(self):
        self.poner_veredictos([
            ver("revisor-autorizacion", "SEG-BFLA", "fail", razon="a", ubicaciones=["src/api.js:7"]),
            ver("revisor-autorizacion", "SEG-BFLA", "incierto", razon="b", ubicaciones=["src/api.js:7",
                                                                                        "src/api.js:9"])])
        self.estado()
        ia = self.hallazgos_ia()
        self.assertEqual(sorted(x["ubicacion"]["linea"] for x in ia), [7, 9])
        self.assertEqual(len({x["id"] for x in ia}), 2)

    def test_determinista(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail",
                                   ubicaciones=["src/api.js:23", "src/api.js:7", "src/api.js:13"])])
        gates.generar(self.corrida)
        a = (self.corrida / "hallazgos_ia.jsonl").read_bytes()
        gates.generar(self.corrida)
        self.assertEqual(a, (self.corrida / "hallazgos_ia.jsonl").read_bytes())


class TestJuezOmitido(BaseC):
    def test_juez_omitido_registra_no_evaluado(self):
        self.omitir("ux", "0 hallazgos, 0 sospechosos, 0 resto")
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail", ubicaciones=["src/api.js:7"])])
        e = self.estado()
        d = self.decisiones()
        om = d["jueces_omitidos"]
        self.assertEqual([x["juicio"] for x in om], ["ux"])
        self.assertEqual(om[0]["agente"], "revisor-ux")
        ctrls = {x["control"] for x in om[0]["controles"]}
        self.assertIn("UX-HEURISTICA", ctrls)
        for x in om[0]["controles"]:
            self.assertEqual(x["veredicto"], "no_evaluado")
            self.assertEqual(x["motivo"], "juez omitido: 0 hallazgos, 0 sospechosos, 0 resto")
            self.assertNotEqual(x["estado_final"], "pass")
            self.assertNotEqual(e[x["control"]]["estado"], "pass")
        self.assertEqual(e["UX-HEURISTICA"]["estado"], "no_evaluado")
        self.assertIn("juez omitido", e["UX-HEURISTICA"]["motivo"])
        self.assertEqual(d["resumen"]["jueces_omitidos"], ["ux"])
        # no son juicios de la IA: no cuentan como aplicados
        self.assertFalse(any(a["control"] == "UX-HEURISTICA" for a in d["aplicadas"]))

    def test_sin_lista_de_controles_usa_el_catalogo(self):
        self.omitir("ux", "entrada esencial ausente", quitar_controles=True)
        self.poner_veredictos([])
        self.estado()
        om = self.decisiones()["jueces_omitidos"]
        indice = estado_indice(self.corrida)
        esperados = {c["id"] for c in digest.controles_de("revisor-ux", indice) if c["metodo"] in ("llm", "mixto")}
        self.assertEqual({x["control"] for x in om[0]["controles"]}, esperados)
        self.assertTrue(esperados)

    def test_con_veredictos_del_agente_no_se_omite(self):
        self.omitir("ux", "0 hallazgos")
        self.poner_veredictos([ver("revisor-ux", "UX-HEURISTICA", "fail", ubicaciones=["src/api.js:3"])])
        e = self.estado()
        self.assertEqual(self.decisiones()["jueces_omitidos"], [])
        self.assertEqual(e["UX-HEURISTICA"]["estado"], "fail")

    def test_pass_de_juez_omitido_no_se_aplica(self):
        self.omitir("arquitectura", "0 hallazgos")
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "pass", ubicaciones=["src/api.js:3"],
                                   metodo="STRIDE")])
        e = self.estado()["SEG-STRIDE"]
        self.assertEqual(e["estado"], "no_evaluado")

    def test_ajustar_degrada_pass_de_controles_omitidos(self):
        res = {"pases": {}, "forzar": {"UX-HEURISTICA": "juez omitido: x"}, "fp_criticos": {}}
        controles = [{"control": "UX-HEURISTICA", "estado": "pass", "motivo": None, "herramienta": "revisor-ux"}]
        veredictos.ajustar(controles, res)
        self.assertEqual(controles[0]["estado"], "no_evaluado")

    def test_omitido_no_toca_fail_determinista(self):
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([h])
        self.omitir("autorizacion", "0 sospechosos")
        self.poner_veredictos([])
        self.assertEqual(self.estado()["SEG-AUTH-CLIENTE"]["estado"], "fail")

    def test_sin_omision_no_hay_registro(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-BFLA", "fail", ubicaciones=["src/api.js:7"])])
        self.estado()
        self.assertEqual(self.decisiones()["jueces_omitidos"], [])


def estado_indice(corrida):
    import utiles
    return utiles.indice_controles(utiles.cargar_perfil(Path(corrida)))


if __name__ == "__main__":
    unittest.main()
