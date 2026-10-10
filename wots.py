"""
WOTS+ -- Winternitz One-Time Signature Plus (FIPS 205, Abschnitt 5).

Alg. 6 (wots_pkGen), Alg. 7 (wots_sign), Alg. 8 (wots_pkFromSig). Jedes
XMSS-Blatt ist letztlich ein WOTS+-Schluesselpaar, deshalb bildet dieses
Modul die unterste Ebene des Signatur-Stacks.
"""

from sphincs_hilfsfunktionen import (
    Params, ADRS, PRF, chain, T, base_2b, toByte,
    WOTS_HASH, WOTS_PK, WOTS_PRF,
)


def wots_pkGen(SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    """Alg. 6. Fuer jede der len_ Ketten: Geheimwert per PRF, Kette komplett
    bis w-1 durchlaufen, alle Kettenenden mit T zu einem Public Key mischen."""
    skADRS = ADRS.copy()                       # eigene Adresse fuer die Geheimwert-Erzeugung
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    tmp = [None] * P.len_
    for i in range(P.len_):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS, P.n)                # Geheimwert fuer Kette i
        ADRS.setChainAddress(i)
        tmp[i] = chain(sk, 0, P.w - 1, PK_seed, ADRS, P.n)     # oeffentlicher Wert der Kette i
    wotspkADRS = ADRS.copy()                   # eigene Adresse fuer den WOTS+-Public-Key
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    pk = T(PK_seed, wotspkADRS, b"".join(tmp), P.n)
    return pk


def _msg_und_checksumme(M: bytes, P: Params):
    """Alg. 7 und Alg. 8 fangen beide mit denselben ersten Zeilen an
    (Nachricht in Basis-w-Ziffern zerlegen, Pruefsumme dranhaengen) -- daher
    hier einmal ausgelagert statt zweimal denselben Code zu pflegen."""
    csum = 0
    msg = base_2b(M, P.lgw, P.len1)
    for i in range(P.len1):
        csum += P.w - 1 - msg[i]
    csum = csum << ((8 - ((P.len2 * P.lgw) % 8)) % 8)
    msg = msg + base_2b(toByte(csum, -(-(P.len2 * P.lgw) // 8)), P.lgw, P.len2)
    return msg


def wots_sign(M: bytes, SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params):
    """Alg. 7. Jede Kette wird nur bis zu der Stelle durchlaufen, die die
    jeweilige Nachrichten-/Pruefsummenziffer vorgibt -- nicht bis zum Ende."""
    msg = _msg_und_checksumme(M, P)
    skADRS = ADRS.copy()
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sig = [None] * P.len_
    for i in range(P.len_):
        skADRS.setChainAddress(i)
        sk = PRF(PK_seed, SK_seed, skADRS, P.n)
        ADRS.setChainAddress(i)
        sig[i] = chain(sk, 0, msg[i], PK_seed, ADRS, P.n)
    return sig


def wots_pkFromSig(sig, M: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    """Alg. 8. Rekonstruiert den Public Key aus einer Signatur, indem jede
    Kette vom Signaturwert aus bis zum Ende (w-1) weitergefuehrt wird. Das
    ist der Trick, der spaeter Verifikation ohne separate Pruef-Logik erlaubt:
    man rechnet einfach nach, was wots_pkGen ergeben haette."""
    msg = _msg_und_checksumme(M, P)
    tmp = [None] * P.len_
    for i in range(P.len_):
        ADRS.setChainAddress(i)
        tmp[i] = chain(sig[i], msg[i], P.w - 1 - msg[i], PK_seed, ADRS, P.n)
    wotspkADRS = ADRS.copy()
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    pksig = T(PK_seed, wotspkADRS, b"".join(tmp), P.n)
    return pksig
