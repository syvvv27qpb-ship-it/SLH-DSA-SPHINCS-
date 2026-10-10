"""
SLH-DSA -- die eigentliche Signaturschnittstelle (FIPS 205, Abschnitt 9 & 10).

Hier laufen wots.py, xmss.py, hypertree.py und fors.py zusammen:

  Alg. 18 slh_keygen_internal    (nutzt xmss_node)
  Alg. 19 slh_sign_internal      (nutzt fors_sign, fors_pkFromSig, ht_sign)
  Alg. 20 slh_verify_internal    (nutzt fors_pkFromSig, ht_verify)
  Alg. 21 slh_keygen
  Alg. 22 slh_sign               -- "Pure"-Variante
  Alg. 23 hash_slh_sign          -- "PreHash"-Variante
  Alg. 24 slh_verify
  Alg. 25 hash_slh_verify
"""

import hashlib
import os

from sphincs_hilfsfunktionen import Params, ADRS_zero, PRF_msg, H_msg, toInt, toByte, FORS_TREE
from xmss import xmss_node
from hypertree import ht_sign, ht_verify
from fors import fors_sign, fors_pkFromSig


def slh_keygen_internal(SK_seed: bytes, SK_prf: bytes, PK_seed: bytes, P: Params):
    """Alg. 18. PK_root ist schlicht die Wurzel des obersten XMSS-Baumes
    (Schicht d-1) -- danach ist SK/PK schon fertig zusammengesetzt."""
    ADRS = ADRS_zero()
    ADRS.setLayerAddress(P.d - 1)
    PK_root = xmss_node(SK_seed, 0, P.hp, PK_seed, ADRS, P)
    SK = (SK_seed, SK_prf, PK_seed, PK_root)
    PK = (PK_seed, PK_root)
    return SK, PK


def _digest_aufteilen(digest: bytes, P: Params):
    """slh_sign_internal und slh_verify_internal brauchen beide genau diesen
    Schritt (Digest in md / idx_tree / idx_leaf zerlegen), deshalb einmal
    hier zusammengefasst statt doppelt zu pflegen."""
    ka_bytes = -(-(P.k * P.a) // 8)
    hhp_bytes = -(-(P.h - P.hp) // 8)
    hp_bytes = -(-P.hp // 8)

    md = digest[0:ka_bytes]
    tmp_idx_tree = digest[ka_bytes: ka_bytes + hhp_bytes]
    tmp_idx_leaf = digest[ka_bytes + hhp_bytes: ka_bytes + hhp_bytes + hp_bytes]

    idx_tree = toInt(tmp_idx_tree, hhp_bytes) % (2 ** (P.h - P.hp))
    idx_leaf = toInt(tmp_idx_leaf, hp_bytes) % (2 ** P.hp)
    return md, idx_tree, idx_leaf


def slh_sign_internal(M: bytes, SK, P: Params, addrnd: bytes = None):
    """Alg. 19. Ablauf: Randomizer R erzeugen, daraus den Nachrichtendigest
    berechnen, den Digest in md/idx_tree/idx_leaf aufteilen, md mit FORS
    signieren und den daraus rekonstruierten FORS-Public-Key vom Hypertree
    signieren lassen."""
    SK_seed, SK_prf, PK_seed, PK_root = SK
    ADRS = ADRS_zero()
    opt_rand = addrnd if addrnd is not None else PK_seed   # deterministische Variante: opt_rand = PK.seed
    R = PRF_msg(SK_prf, opt_rand, M, P.n)

    digest = H_msg(R, PK_seed, PK_root, M, P.m)
    md, idx_tree, idx_leaf = _digest_aufteilen(digest, P)

    ADRS.setTreeAddress(idx_tree)
    ADRS.setTypeAndClear(FORS_TREE)
    ADRS.setKeyPairAddress(idx_leaf)

    SIG_FORS = fors_sign(md, SK_seed, PK_seed, ADRS, P)

    PK_FORS = fors_pkFromSig(SIG_FORS, md, PK_seed, ADRS, P)
    SIG_HT = ht_sign(PK_FORS, SK_seed, PK_seed, idx_tree, idx_leaf, P)

    SIG = (R, SIG_FORS, SIG_HT)
    return SIG


def slh_verify_internal(M: bytes, SIG, PK, P: Params) -> bool:
    """Alg. 20. Derselbe Weg wie beim Signieren, nur ohne SK_seed: Digest aus
    dem mitgelieferten R nachbauen, FORS-Public-Key aus SIG_FORS rekonstruieren
    und pruefen, ob der Hypertree-Teil dazu passt."""
    PK_seed, PK_root = PK
    R, SIG_FORS, SIG_HT = SIG
    ADRS = ADRS_zero()

    digest = H_msg(R, PK_seed, PK_root, M, P.m)
    md, idx_tree, idx_leaf = _digest_aufteilen(digest, P)

    ADRS.setTreeAddress(idx_tree)
    ADRS.setTypeAndClear(FORS_TREE)
    ADRS.setKeyPairAddress(idx_leaf)

    PK_FORS = fors_pkFromSig(SIG_FORS, md, PK_seed, ADRS, P)

    return ht_verify(PK_FORS, SIG_HT, PK_seed, idx_tree, idx_leaf, PK_root, P)


def slh_keygen(P: Params):
    """Alg. 21. Zieht die drei Zufalls-Seeds und delegiert den Rest an
    slh_keygen_internal."""
    SK_seed = os.urandom(P.n)
    SK_prf = os.urandom(P.n)
    PK_seed = os.urandom(P.n)
    if SK_seed is None or SK_prf is None or PK_seed is None:
        return None
    return slh_keygen_internal(SK_seed, SK_prf, PK_seed, P)


def slh_sign(M: bytes, ctx: bytes, SK, P: Params, addrnd: bytes = None):
    """Alg. 22, "Pure SLH-DSA". Bettet nur ein Praefix-Byte (0x00) und den
    Kontextstring vor M ein -- M selbst wird nicht vorher gehasht."""
    if len(ctx) > 255:
        return None
    if addrnd is None:
        addrnd = os.urandom(P.n)
    if addrnd is None:
        return None
    M_strich = toByte(0, 1) + toByte(len(ctx), 1) + ctx + M
    SIG = slh_sign_internal(M_strich, SK, P, addrnd)
    return SIG


# Alg. 23 (hash_slh_sign) und Alg. 25 (hash_slh_verify) brauchen eine
# OID pro Pre-Hash-Funktion, damit spaeter nachvollziehbar ist, mit welcher
# Funktion extern vorgehasht wurde. Die Werte hier sind die DER-kodierten
# Objekt-Identifikatoren aus FIPS 205.
_OID = {
    "SHA-256": bytes.fromhex("0609608648016503040201"),
    "SHA-512": bytes.fromhex("0609608648016503040203"),
    "SHAKE128": bytes.fromhex("060960864801650304020B"),
    "SHAKE256": bytes.fromhex("060960864801650304020C"),
}


def _pre_hash(PH: str, M: bytes) -> bytes:
    if PH == "SHA-256":
        return hashlib.sha256(M).digest()
    elif PH == "SHA-512":
        return hashlib.sha512(M).digest()
    elif PH == "SHAKE128":
        return hashlib.shake_128(M).digest(32)      # SHAKE128(M, 256)
    elif PH == "SHAKE256":
        return hashlib.shake_256(M).digest(64)      # SHAKE256(M, 512)
    else:
        raise ValueError("Unbekannte Pre-Hash-Funktion PH")


def hash_slh_sign(M: bytes, ctx: bytes, PH: str, SK, P: Params, addrnd: bytes = None):
    """Alg. 23, "HashSLH-DSA". Fuer lange Nachrichten: M wird vorab extern
    gehasht (PH waehlbar), und statt M selbst wandert 0x01 || Kontext ||
    OID(PH) || PH(M) in slh_sign_internal."""
    if len(ctx) > 255:
        return None
    if addrnd is None:
        addrnd = os.urandom(P.n)
    if addrnd is None:
        return None
    OID = _OID[PH]
    PH_M = _pre_hash(PH, M)
    M_strich = toByte(1, 1) + toByte(len(ctx), 1) + ctx + OID + PH_M
    SIG = slh_sign_internal(M_strich, SK, P, addrnd)
    return SIG


def slh_verify(M: bytes, SIG, ctx: bytes, PK, P: Params) -> bool:
    """Alg. 24, Gegenstueck zu slh_sign."""
    if len(ctx) > 255:
        return False
    M_strich = toByte(0, 1) + toByte(len(ctx), 1) + ctx + M
    return slh_verify_internal(M_strich, SIG, PK, P)


def hash_slh_verify(M: bytes, SIG, ctx: bytes, PH: str, PK, P: Params) -> bool:
    """Alg. 25, Gegenstueck zu hash_slh_sign."""
    if len(ctx) > 255:
        return False
    OID = _OID[PH]
    PH_M = _pre_hash(PH, M)
    M_strich = toByte(1, 1) + toByte(len(ctx), 1) + ctx + OID + PH_M
    return slh_verify_internal(M_strich, SIG, PK, P)
