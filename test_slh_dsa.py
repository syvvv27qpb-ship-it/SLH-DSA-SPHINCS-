"""
Automatisierte Tests fuer die SLH-DSA / SPHINCS+ - Implementierung (FIPS 205).

Laeuft mit dem eingebauten unittest-Modul, damit man keine zusaetzliche
Bibliothek installieren muss:

    python3 -m unittest test_slh_dsa.py -v

Die eigentliche Korrektheitspruefung (TestNistParametersaetze) laeuft mit
den 6 offiziellen NIST-Parametersaetzen aus FIPS 205, Tabelle 2 -- nicht mit
frei erfundenen Werten. Nur damit ist gezeigt, dass die Implementierung auch
bei den tatsaechlich zugesicherten Sicherheitsstufen (128/192/256 Bit)
korrekt arbeitet. Fuer jeden Parametersatz gibt es eine eigene Testmethode,
damit man in der Ausgabe sofort sieht, welcher Satz ggf. fehlschlaegt.

Das dauert insgesamt einige Minuten (siehe Benchmark-Tabelle in der
Projektdokumentation, v. a. die "f"-Varianten mit hohem d brauchen laenger).

Zusaetzlich gibt es TestRandfaelle: kleine, selbstgewaehlte Parameter fuer
Verhaltens-Details, die nichts mit der Sicherheitsstufe zu tun haben (leere
Nachricht, zu langer Kontextstring, falscher Public Key) -- diese dienen nur
der schnellen Funktionspruefung, nicht dem Sicherheitsnachweis.
"""

import unittest

from sphincs_hilfsfunktionen import Params, NIST_PARAMETERSAETZE
from slh_dsa import slh_keygen, slh_sign, slh_verify, hash_slh_sign, hash_slh_verify
from serialisierung import (
    sk_to_hex, sk_from_hex, pk_to_hex, pk_from_hex, sig_to_hex, sig_from_hex,
)


def _roundtrip(P: Params, testcase: unittest.TestCase):
    """Ein voller Durchlauf fuer einen gegebenen Parametersatz: Keygen, Pure-
    und Hash-Signatur, Hex-Rundlauf und die Ablehnung einer manipulierten
    Nachricht. Wird von allen Testklassen genutzt, damit die eigentliche
    Pruefung nicht mehrfach gepflegt werden muss."""
    M = b"Hallo, ich bin Alice."
    ctx = b""

    SK, PK = slh_keygen(P)
    testcase.assertIsNotNone(SK)
    testcase.assertIsNotNone(PK)

    # Pure SLH-DSA (Alg. 22 / 24)
    SIG = slh_sign(M, ctx, SK, P)
    testcase.assertTrue(slh_verify(M, SIG, ctx, PK, P))
    testcase.assertFalse(slh_verify(b"andere Nachricht", SIG, ctx, PK, P))

    # HashSLH-DSA (Alg. 23 / 25)
    SIG_H = hash_slh_sign(M, ctx, "SHAKE256", SK, P)
    testcase.assertTrue(hash_slh_verify(M, SIG_H, ctx, "SHAKE256", PK, P))
    testcase.assertFalse(hash_slh_verify(b"andere Nachricht", SIG_H, ctx, "SHAKE256", PK, P))

    # Hex-Serialisierung (Figuren 15-17): Rundlauf muss dieselben Bytes liefern
    SK2 = sk_from_hex(sk_to_hex(SK, P), P)
    PK2 = pk_from_hex(pk_to_hex(PK, P), P)
    SIG2 = sig_from_hex(sig_to_hex(SIG, P), P)
    testcase.assertEqual(SK, SK2)
    testcase.assertEqual(PK, PK2)
    testcase.assertTrue(slh_verify(M, SIG2, ctx, PK2, P))


class TestNistParametersaetze(unittest.TestCase):
    """Primaerer Korrektheitsnachweis: voller Rundlauf mit jedem der 6
    offiziellen NIST-Parametersaetze aus FIPS 205, Tabelle 2 (siehe
    NIST_PARAMETERSAETZE in sphincs_hilfsfunktionen.py)."""


def _nist_test_erzeugen(name, werte):
    def test(self):
        P = Params(
            n=werte["n"], lgw=werte["lgw"], hp=werte["hp"],
            d=werte["d"], k=werte["k"], a=werte["a"],
        )
        _roundtrip(P, self)
    test.__doc__ = f"Rundlauf mit dem offiziellen Parametersatz {name}."
    return test


# Pro NIST-Parametersatz eine eigene Testmethode registrieren (statt einer
# Schleife mit subTest), damit z. B. "python3 -m unittest -v" wirklich jeden
# Satz einzeln mit Namen auflistet.
for _name, _werte in NIST_PARAMETERSAETZE.items():
    _testname = "test_" + _name.lower().replace("-", "_")
    setattr(TestNistParametersaetze, _testname, _nist_test_erzeugen(_name, _werte))


class TestRandfaelle(unittest.TestCase):
    """Schnelle Tests fuer einzelne Verhaltensdetails mit klein gewaehlten
    Parametern -- kein Ersatz fuer TestNistParametersaetze, nur zur
    schnellen Kontrolle waehrend der Entwicklung."""

    def test_verschiedene_pre_hash_funktionen(self):
        P = Params(n=4, lgw=4, hp=3, d=2, k=4, a=3)
        SK, PK = slh_keygen(P)
        M, ctx = b"Testnachricht", b""
        for PH in ("SHA-256", "SHA-512", "SHAKE128", "SHAKE256"):
            with self.subTest(PH=PH):
                SIG = hash_slh_sign(M, ctx, PH, SK, P)
                self.assertTrue(hash_slh_verify(M, SIG, ctx, PH, PK, P))

    def test_leere_nachricht(self):
        P = Params(n=4, lgw=4, hp=3, d=2, k=4, a=3)
        SK, PK = slh_keygen(P)
        SIG = slh_sign(b"", b"", SK, P)
        self.assertTrue(slh_verify(b"", SIG, b"", PK, P))

    def test_kontextstring_zu_lang_wird_abgelehnt(self):
        P = Params(n=4, lgw=4, hp=3, d=2, k=4, a=3)
        SK, PK = slh_keygen(P)
        zu_langer_ctx = b"x" * 256
        self.assertIsNone(slh_sign(b"M", zu_langer_ctx, SK, P))
        self.assertFalse(slh_verify(b"M", (b"", [], []), zu_langer_ctx, PK, P))

    def test_falscher_public_key_wird_abgelehnt(self):
        P = Params(n=4, lgw=4, hp=3, d=2, k=4, a=3)
        SK, _PK = slh_keygen(P)
        _, fremder_PK = slh_keygen(P)
        M, ctx = b"Testnachricht", b""
        SIG = slh_sign(M, ctx, SK, P)
        self.assertFalse(slh_verify(M, SIG, ctx, fremder_PK, P))


if __name__ == "__main__":
    unittest.main()
