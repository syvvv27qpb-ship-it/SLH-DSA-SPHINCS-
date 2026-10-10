"""
SK/PK/SIG als Byte-Strings (bzw. Hex) speichern und wieder einlesen.

Kein eigener FIPS-205-Algorithmus -- die Datenformate sind dort nur
beschrieben (Figuren 15-17), nicht als Pseudocode ausformuliert:

  Figur 15: SLH-DSA private key  = SK.seed || SK.prf || PK.seed || PK.root
  Figur 16: SLH-DSA public key   = PK.seed || PK.root
  Figur 17: SLH-DSA signature    = R || SIG_FORS || SIG_HT

Der Grund, warum es diese Datei ueberhaupt braucht: intern sind SK/PK/SIG
Python-Tupel aus bytes-Objekten (praktisch fuer die Algorithmen), aber wenn
man sie z.B. in einem Textfeld der Streamlit-App eingeben oder in eine andere
Sitzung mitnehmen will, muss daraus ein einziger zusammenhaengender String
werden. Das passt auch inhaltlich: Alg. 22 (slh_sign) braucht wirklich nur
M, ctx, SK, und Alg. 24 (slh_verify) nur M, SIG, ctx, PK -- die beiden
Operationen sind bewusst voneinander unabhaengig.
"""

from sphincs_hilfsfunktionen import Params


# ---- SK (Figur 15) ------------------------------------------------------
def sk_to_bytes(SK, P: Params) -> bytes:
    SK_seed, SK_prf, PK_seed, PK_root = SK
    return SK_seed + SK_prf + PK_seed + PK_root


def sk_from_bytes(data: bytes, P: Params):
    n = P.n
    if len(data) != 4 * n:
        raise ValueError(f"SK muss {4 * n} Byte lang sein (n={n}), war aber {len(data)} Byte.")
    SK_seed = data[0 * n:1 * n]
    SK_prf = data[1 * n:2 * n]
    PK_seed = data[2 * n:3 * n]
    PK_root = data[3 * n:4 * n]
    return (SK_seed, SK_prf, PK_seed, PK_root)


# ---- PK (Figur 16) ------------------------------------------------------
def pk_to_bytes(PK, P: Params) -> bytes:
    PK_seed, PK_root = PK
    return PK_seed + PK_root


def pk_from_bytes(data: bytes, P: Params):
    n = P.n
    if len(data) != 2 * n:
        raise ValueError(f"PK muss {2 * n} Byte lang sein (n={n}), war aber {len(data)} Byte.")
    PK_seed = data[0 * n:1 * n]
    PK_root = data[1 * n:2 * n]
    return (PK_seed, PK_root)


# ---- SIG (Figur 17) ------------------------------------------------------
def sig_to_bytes(SIG, P: Params) -> bytes:
    R, SIG_FORS, SIG_HT = SIG
    out = bytearray(R)
    for i in range(P.k):
        sk = SIG_FORS[2 * i]
        auth = SIG_FORS[2 * i + 1]
        out += sk
        for a_elem in auth:
            out += a_elem
    for j in range(P.d):
        sig, auth = SIG_HT[j]
        for s_elem in sig:
            out += s_elem
        for a_elem in auth:
            out += a_elem
    return bytes(out)


def sig_from_bytes(data: bytes, P: Params):
    # Laenge vorher ausrechnen (statt einfach draufloszulesen), damit man bei
    # einem falsch eingefuegten Hex-String sofort eine klare Fehlermeldung
    # bekommt statt eines wirren IndexError mittendrin.
    n = P.n
    erwartete_laenge = n * (1 + P.k * (1 + P.a) + P.h + P.d * P.len_)
    if len(data) != erwartete_laenge:
        raise ValueError(
            f"SIG muss {erwartete_laenge} Byte lang sein "
            f"(n={n}, k={P.k}, a={P.a}, h={P.h}, d={P.d}, len={P.len_}), "
            f"war aber {len(data)} Byte."
        )
    pos = 0
    R = data[pos:pos + n]; pos += n

    SIG_FORS = []
    for i in range(P.k):
        sk = data[pos:pos + n]; pos += n
        AUTH = [data[pos + j * n: pos + (j + 1) * n] for j in range(P.a)]
        pos += P.a * n
        SIG_FORS.append(sk)
        SIG_FORS.append(AUTH)

    SIG_HT = []
    for j in range(P.d):
        sig = [data[pos + i * n: pos + (i + 1) * n] for i in range(P.len_)]
        pos += P.len_ * n
        AUTH = [data[pos + i * n: pos + (i + 1) * n] for i in range(P.hp)]
        pos += P.hp * n
        SIG_HT.append((sig, AUTH))

    return (R, SIG_FORS, SIG_HT)


# ---- Hex-Wrapper fuer die Textfelder in der Streamlit-Oberflaeche --------
def sk_to_hex(SK, P: Params) -> str:
    return sk_to_bytes(SK, P).hex()


def sk_from_hex(hexstr: str, P: Params):
    return sk_from_bytes(bytes.fromhex(hexstr.strip()), P)


def pk_to_hex(PK, P: Params) -> str:
    return pk_to_bytes(PK, P).hex()


def pk_from_hex(hexstr: str, P: Params):
    return pk_from_bytes(bytes.fromhex(hexstr.strip()), P)


def sig_to_hex(SIG, P: Params) -> str:
    return sig_to_bytes(SIG, P).hex()


def sig_from_hex(hexstr: str, P: Params):
    return sig_from_bytes(bytes.fromhex(hexstr.strip()), P)
