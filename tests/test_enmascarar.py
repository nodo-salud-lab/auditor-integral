"""Tests de scripts/enmascarar.py: secretos (prefijo + **** + últimos 4) y PII por nombre de columna.

Todos los secretos de este archivo son CANARIOS FALSOS generados al azar (no son válidos).
"""
import random
import string
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import enmascarar as em  # noqa: E402

_RNG = random.Random(20261118)
_ALNUM = string.ascii_letters + string.digits


def _al(n, alfabeto=_ALNUM):
    return "".join(_RNG.choice(alfabeto) for _ in range(n))


def canarios():
    """20 secretos canario con formatos conocidos y desconocidos (deterministas)."""
    return [
        "sk_live_" + _al(24),
        "rk_live_" + _al(24),
        "whsec_" + _al(32),
        "AKIA" + _al(16, string.ascii_uppercase + string.digits),
        "ghp_" + _al(36),
        "github_pat_" + _al(22) + "_" + _al(40),
        "sk-proj-" + _al(40),
        "sk-ant-api03-" + _al(40),
        "SG." + _al(22) + "." + _al(43),
        "xoxb-" + _al(11, string.digits) + "-" + _al(24),
        "AIza" + _al(35),
        "eyJ" + _al(30) + "." + "eyJ" + _al(40) + "." + _al(43),
        "glpat-" + _al(20),
        "npm_" + _al(36),
        "SK" + _al(32, "0123456789abcdef"),
        "postgres://admin:" + _al(18) + "@db.ejemplo.invalid:5432/app",
        _al(40, "0123456789abcdef"),            # hex genérico (solo lo detecta el contexto)
        _al(28),                                # aleatorio sin formato (solo vía gitleaks Secret)
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE" + _al(60) + "\n-----END RSA PRIVATE KEY-----",
        "Zz9" + _al(25),                        # aleatorio sin formato (solo vía gitleaks Secret)
    ]


def nucleo(secreto):
    """Fragmento central del secreto: nunca debe aparecer enmascarado."""
    s = secreto
    if "://" in s:
        s = s.split(":", 2)[2].split("@")[0]
    if "PRIVATE KEY" in s:
        s = s.split("\n")[1]
    m = len(s) // 2
    return s[m - 4:m + 4]


class TestEnmascararValor(unittest.TestCase):
    def test_prefijo_conocido_y_ultimos_4(self):
        s = "sk_live_" + "A1b2C3d4E5f6G7h8J9k0"
        r = em.enmascarar_valor(s)
        self.assertTrue(r.startswith("sk_live_"))
        self.assertTrue(r.endswith(s[-4:]))
        self.assertIn("****", r)
        self.assertNotIn(s, r)

    def test_prefijo_generico_4(self):
        s = "Qw7Er8Ty9Ui0Op1As2Df3"
        r = em.enmascarar_valor(s)
        self.assertEqual(r, s[:4] + "****" + s[-4:])

    def test_prefijo_maximo_8(self):
        s = "github_pat_" + "x" * 30 + "ABCD"
        r = em.enmascarar_valor(s)
        self.assertLessEqual(len(r.split("****")[0]), 8)

    def test_secreto_corto(self):
        self.assertEqual(em.enmascarar_valor("abc123"), "****")
        r = em.enmascarar_valor("abcdef123456")
        self.assertNotIn("abcdef123456", r)
        self.assertIn("****", r)

    def test_idempotente(self):
        s = "texto KEY=sk_live_" + "Z" * 20 + "a9F2 fin"
        una = em.enmascarar_texto(s)
        self.assertEqual(una, em.enmascarar_texto(una))


class TestEnmascararTexto(unittest.TestCase):
    def test_canarios_con_secretos_conocidos(self):
        cs = canarios()
        texto = "\n".join(f"linea {i}: valor={c}" for i, c in enumerate(cs))
        r = em.enmascarar_texto(texto, secretos=cs)
        for c in cs:
            self.assertNotIn(c, r)
            self.assertNotIn(nucleo(c), r, c[:12])

    def test_canarios_por_patron_sin_lista(self):
        # Solo los que tienen formato reconocible o contexto (clave = valor).
        cs = canarios()
        formateados = cs[:16] + [cs[18]]
        texto = "\n".join(f'const k{i} = "{c}"' for i, c in enumerate(formateados))
        texto += f'\napi_secret = "{cs[16]}"'
        r = em.enmascarar_texto(texto)
        for c in formateados + [cs[16]]:
            self.assertNotIn(nucleo(c), r, c[:14])

    def test_password_en_url(self):
        r = em.enmascarar_texto("DATABASE_URL=postgres://yo:SuperClave123@host:5432/db")
        self.assertNotIn("SuperClave123", r)
        self.assertIn("postgres://yo:", r)
        self.assertIn("@host:5432/db", r)

    def test_no_enmascara_codigo_comun(self):
        texto = "const password = req.body.password; if (token === undefined) return"
        self.assertEqual(em.enmascarar_texto(texto), texto)

    def test_pii_por_nombre_de_columna(self):
        texto = '{"email": "ana.perez@correo.cl", "rut": "12.345.678-5", "telefono": "+56912345678", "nombre": "Ana"}'
        r = em.enmascarar_texto(texto)
        for v in ("ana.perez@correo.cl", "12.345.678-5", "+56912345678"):
            self.assertNotIn(v, r)
        self.assertIn('"email"', r)

    def test_pii_email_y_rut_sueltos(self):
        r = em.enmascarar_texto("contacto juan@dominio.cl rut 9.876.543-K")
        self.assertNotIn("juan@dominio.cl", r)
        self.assertNotIn("9.876.543-K", r)

    def test_pii_asignacion(self):
        r = em.enmascarar_texto("insert into pacientes (rut, correo) values ('11111111-1', 'x@y.cl'); telefono=987654321")
        self.assertNotIn("x@y.cl", r)
        self.assertNotIn("987654321", r)

    def test_vacio_y_none(self):
        self.assertEqual(em.enmascarar_texto(""), "")
        self.assertIsNone(em.enmascarar_texto(None))

    def test_recortar(self):
        s = "a" * 500
        r = em.recortar(s, 300)
        self.assertLessEqual(len(r), 300)
        self.assertTrue(r.endswith("…"))

    def test_cli_stdin(self):
        c = canarios()[0]
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "enmascarar.py")],
                           input=f"clave {c}\n", capture_output=True, text=True, check=True)
        self.assertNotIn(c, p.stdout)
        self.assertIn("****", p.stdout)


if __name__ == "__main__":
    unittest.main()
