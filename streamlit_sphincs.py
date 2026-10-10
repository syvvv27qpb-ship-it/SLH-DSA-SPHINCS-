import time

import streamlit as st

from sphincs_hilfsfunktionen import Params, NIST_PARAMETERSAETZE
from slh_dsa import slh_keygen, slh_sign, slh_verify, hash_slh_sign, hash_slh_verify
from serialisierung import sk_to_hex, sk_from_hex, pk_to_hex, pk_from_hex, sig_to_hex, sig_from_hex

st.title(":blue[SLH-DSA / SPHINCS+ – Stateless Hash-Based Digital Signature (FIPS 205)]")


# Kleiner Helfer fuer die Anzeige: Seeds/Wurzeln sind n Byte lang und als
# volle Hex-Zeile in der Kurzuebersicht eher unuebersichtlich, deshalb hier
# nur eine gekuerzte Vorschau -- der vollstaendige Wert steht ohnehin unten
# im Hex-Textfeld.
def hex_kurz(b: bytes, max_bytes=16):
    return b[:max_bytes].hex() + "..." if len(b) > max_bytes else b.hex()


# Die Parameter müssen bei jeder Operation neu angegeben werden, weil SK/PK/SIG
# als reine Bytes keine Parameter-Info enthalten — genau wie bei echten
# SLH-DSA-Implementierungen, wo der Parametersatz z. B. über eine
# Schlüssel-/Signatur-OID mitgeteilt werden muss.
st.subheader("Parameter")

voreinstellung = st.selectbox(
    "Vordefinierter Parametersatz",
    ["Benutzerdefiniert"] + list(NIST_PARAMETERSAETZE.keys()),
)

if voreinstellung == "Benutzerdefiniert":
    n = st.number_input("n – Sicherheitsparameter (Byte)", min_value=1, value=4, step=1)
    hp = st.number_input("h' – Höhe eines XMSS-Baumes", min_value=1, value=3, step=1)
    d = st.number_input("d – Anzahl Schichten des Hypertree", min_value=1, value=2, step=1)
    k = st.number_input("k – Anzahl FORS-Bäume", min_value=1, value=4, step=1)
    a = st.number_input("a – Höhe eines FORS-Baumes (t = 2^a)", min_value=1, value=3, step=1)
    lgw = st.number_input("lgw – Bits pro Hashkette (Standard 4)", min_value=1, max_value=8, value=4, step=1)
else:
    ref = NIST_PARAMETERSAETZE[voreinstellung]
    st.info(
        f"Offizielle NIST-Werte von {voreinstellung}: n={ref['n']}, h'={ref['hp']}, "
        f"d={ref['d']}, k={ref['k']}, a={ref['a']}. Schlüsselerzeugung dauert damit "
        f"ca. 1-2 Sekunden, Signieren je nach Parametersatz ca. 5-30 Sekunden "
        f"(reine, nicht optimierte Python-Implementierung)."
    )
    n = st.number_input("n – Sicherheitsparameter (Byte)", min_value=1, value=ref["n"], step=1)
    hp = st.number_input("h' – Höhe eines XMSS-Baumes", min_value=1, value=ref["hp"], step=1)
    d = st.number_input("d – Anzahl Schichten des Hypertree", min_value=1, value=ref["d"], step=1)
    k = st.number_input("k – Anzahl FORS-Bäume", min_value=1, value=ref["k"], step=1)
    a = st.number_input("a – Höhe eines FORS-Baumes (t = 2^a)", min_value=1, value=ref["a"], step=1)
    lgw = ref["lgw"]

    # Die Felder oben bleiben trotz Preset-Auswahl editierbar (bewusst, siehe
    # "Benutzerdefiniert" weiter oben) -- deshalb hier pruefen, ob der Nutzer
    # zwischenzeitlich einen Wert manuell veraendert hat. Sobald ein Wert vom
    # offiziellen Preset abweicht, gelten die von NIST zugesicherten
    # Sicherheitsstufen fuer diesen Parametersatz nicht mehr, auch wenn im
    # Dropdown noch der Name des Presets steht.
    abweichungen = []
    for bezeichnung, wert, ref_wert in [
        ("n", int(n), ref["n"]),
        ("h'", int(hp), ref["hp"]),
        ("d", int(d), ref["d"]),
        ("k", int(k), ref["k"]),
        ("a", int(a), ref["a"]),
    ]:
        if wert != ref_wert:
            abweichungen.append(f"{bezeichnung}={wert} (Standard: {ref_wert})")
    if abweichungen:
        st.warning(
            f"⚠️ Sie haben {', '.join(abweichungen)} manuell verändert. Das ist "
            f"kein offizieller NIST-Parametersatz mehr — die für {voreinstellung} "
            f"zugesicherte Sicherheitsstufe gilt für diese Kombination nicht."
        )

P = Params(n=int(n), lgw=int(lgw), hp=int(hp), d=int(d), k=int(k), a=int(a))

operation = st.selectbox("Operation auswählen", ["Schlüsselerzeugung", "Signieren", "Verifizieren"])

if operation == "Schlüsselerzeugung":
    st.caption("Erzeugt SK = (SK.seed, SK.prf, PK.seed, PK.root) und PK = (PK.seed, PK.root) — Algorithmus 21.")

elif operation == "Signieren":
    sk_hex_str = st.text_area(
        "Privater Schlüssel SK (Hex)",
        value=st.session_state.get("SK_hex", ""),
        help="Hex-String des SK, z. B. aus 'Schlüsselerzeugung' kopiert (auch aus einer anderen Sitzung/Browser).",
    )
    M_str = st.text_input("Nachricht M", value="Hallo, ich bin Alice.")
    ctx_str = st.text_input("Kontextstring ctx (max. 255 Byte, meist leer)", value="")
    variante = st.selectbox("Signaturvariante", ["Pure SLH-DSA (Algorithmus 22)", "HashSLH-DSA (Algorithmus 23)"])
    if variante.startswith("HashSLH"):
        PH = st.selectbox("Pre-Hash-Funktion PH", ["SHA-256", "SHA-512", "SHAKE128", "SHAKE256"])
    st.caption("Benötigt nur SK — kein Zugriff auf frühere Sitzungen nötig, solange SK bekannt ist.")

elif operation == "Verifizieren":
    pk_hex_str = st.text_area(
        "Öffentlicher Schlüssel PK (Hex)",
        value=st.session_state.get("PK_hex", ""),
        help="Hex-String des PK, z. B. aus 'Schlüsselerzeugung' kopiert.",
    )
    sig_hex_str = st.text_area(
        "Signatur SIG (Hex)",
        value=st.session_state.get("SIG_hex", ""),
        help="Hex-String der Signatur, z. B. aus 'Signieren' kopiert.",
    )
    M_str = st.text_input("Nachricht M (zur Prüfung, ggf. absichtlich verändert)", value="Hallo, ich bin Alice.")
    ctx_str = st.text_input("Kontextstring ctx", value="")
    variante = st.selectbox("Signaturvariante", ["Pure SLH-DSA (Algorithmus 24)", "HashSLH-DSA (Algorithmus 25)"])
    if variante.startswith("HashSLH"):
        PH = st.selectbox("Pre-Hash-Funktion PH", ["SHA-256", "SHA-512", "SHAKE128", "SHAKE256"])
    st.caption("Benötigt nur PK und SIG — kein privater Schlüssel nötig.")

# ---- eigentliche Berechnung, erst nach Klick auf den Button -------------
if st.button("Berechnen"):

    # d*2^h' + k*2^a ist proportional zur Anzahl der Baumknoten, die fuer
    # diese Operation berechnet werden muessen -- als grobe Kostenschaetzung,
    # bevor tatsaechlich losgerechnet wird.
    kosten = P.d * (2 ** P.hp) + P.k * (2 ** P.a)
    if kosten > 3_000_000:
        st.error(
            "Diese Parameterkombination (v.a. h' oder a) ist zu groß für eine "
            "interaktive Live-Berechnung in reinem Python. Bitte kleinere Werte wählen."
        )
        st.stop()
    elif kosten > 50_000:
        st.warning(
            "Diese Parameterkombination kann – je nach Operation – mehrere Sekunden "
            "bis etwa eine Minute dauern (reine, nicht optimierte Python-Implementierung)."
        )

    st.subheader("Ergebnis")

    if operation == "Schlüsselerzeugung":
        with st.spinner("Schlüssel wird erzeugt..."):
            t0 = time.perf_counter()
            SK, PK = slh_keygen(P)
            dauer = time.perf_counter() - t0
        SK_seed, SK_prf, PK_seed, PK_root = SK
        sk_hex = sk_to_hex(SK, P)
        pk_hex = pk_to_hex(PK, P)
        st.session_state["SK_hex"] = sk_hex
        st.session_state["PK_hex"] = pk_hex
        st.caption(f"⏱ Rechenzeit (Algorithmus 21): {dauer:.3f} s")
        st.markdown(f"- **SK.seed =** `{hex_kurz(SK_seed)}`")
        st.markdown(f"- **SK.prf  =** `{hex_kurz(SK_prf)}`")
        st.markdown(f"- **PK.seed =** `{hex_kurz(PK_seed)}`")
        st.markdown(f"- **PK.root =** `{hex_kurz(PK_root)}`")
        st.markdown("**SK (Hex) — zum Signieren, ggf. woanders einfügen:**")
        st.code(sk_hex, language=None)
        st.markdown("**PK (Hex) — zum Verifizieren, ggf. woanders einfügen:**")
        st.code(pk_hex, language=None)

    elif operation == "Signieren":
        if not sk_hex_str.strip():
            st.error("Bitte einen SK-Hex-String eingeben (z. B. aus 'Schlüsselerzeugung' kopiert).")
            st.stop()
        try:
            SK = sk_from_hex(sk_hex_str, P)
        except ValueError as e:
            st.error(f"SK ungültig für die gewählten Parameter: {e}")
            st.stop()
        M = M_str.encode()
        ctx = ctx_str.encode()
        with st.spinner("Signatur wird berechnet..."):
            t0 = time.perf_counter()
            if variante.startswith("HashSLH"):
                SIG = hash_slh_sign(M, ctx, PH, SK, P)
            else:
                SIG = slh_sign(M, ctx, SK, P)
            dauer = time.perf_counter() - t0
        sig_hex = sig_to_hex(SIG, P)
        st.session_state["SIG_hex"] = sig_hex
        R, SIG_FORS, SIG_HT = SIG
        st.caption(f"⏱ Rechenzeit ({variante.split('(')[-1].rstrip(')')}): {dauer:.3f} s")
        st.markdown(f"- **R (Randomizer) =** `{hex_kurz(R)}`")
        st.markdown(f"- **|SIG_FORS| =** {len(SIG_FORS)} Elemente (k={P.k} Werte + Authentifizierungspfade)")
        st.markdown(f"- **|SIG_HT| =** {len(SIG_HT)} XMSS-Signaturen (d={P.d} Schichten)")
        st.markdown("**SIG (Hex) — zum Verifizieren, zusammen mit PK weitergeben:**")
        st.code(sig_hex, language=None)

    elif operation == "Verifizieren":
        if not pk_hex_str.strip() or not sig_hex_str.strip():
            st.error("Bitte sowohl PK- als auch SIG-Hex-String eingeben.")
            st.stop()
        try:
            PK = pk_from_hex(pk_hex_str, P)
            SIG = sig_from_hex(sig_hex_str, P)
        except ValueError as e:
            st.error(f"PK oder SIG ungültig für die gewählten Parameter: {e}")
            st.stop()
        M = M_str.encode()
        ctx = ctx_str.encode()
        with st.spinner("Signatur wird geprüft..."):
            t0 = time.perf_counter()
            if variante.startswith("HashSLH"):
                ergebnis = hash_slh_verify(M, SIG, ctx, PH, PK, P)
            else:
                ergebnis = slh_verify(M, SIG, ctx, PK, P)
            dauer = time.perf_counter() - t0
        st.caption(f"⏱ Rechenzeit ({variante.split('(')[-1].rstrip(')')}): {dauer:.3f} s")
        if ergebnis:
            st.markdown("- **Verifikationsergebnis =** ✅ gültig")
        else:
            st.markdown("- **Verifikationsergebnis =** ❌ ungültig")
