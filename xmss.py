"""
XMSS -- Merkle-Baum aus WOTS+-Schluesselpaaren (FIPS 205, Abschnitt 6).

Alg. 9 (xmss_node), Alg. 10 (xmss_sign), Alg. 11 (xmss_pkFromSig). Ein
XMSS-Baum "sammelt" viele WOTS+-Einmalschluessel unter einer Wurzel, so
muss man nach aussen nur noch die Wurzel als Public Key vorzeigen.
"""

from sphincs_hilfsfunktionen import Params, ADRS, H, WOTS_HASH, TREE
from wots import wots_pkGen, wots_sign, wots_pkFromSig


def xmss_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    """Alg. 9, rekursiv: z=0 -> Blatt = WOTS+-Public-Key an Index i,
    z>0 -> innerer Knoten = H(linkes Kind || rechtes Kind)."""
    if z == 0:
        ADRS.setTypeAndClear(WOTS_HASH)
        ADRS.setKeyPairAddress(i)
        node = wots_pkGen(SK_seed, PK_seed, ADRS, P)
    else:
        lnode = xmss_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS, P)
        rnode = xmss_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS, P)
        ADRS.setTypeAndClear(TREE)
        ADRS.setTreeHeight(z)
        ADRS.setTreeIndex(i)
        node = H(PK_seed, ADRS, lnode + rnode, P.n)
    return node


def xmss_sign(M: bytes, SK_seed: bytes, idx: int, PK_seed: bytes, ADRS: "ADRS", P: Params):
    """Alg. 10. Authentifizierungspfad = die hp "Geschwisterknoten" auf dem
    Weg vom Blatt idx zur Wurzel, plus die eigentliche WOTS+-Signatur des
    Blatts."""
    AUTH = [None] * P.hp
    for j in range(P.hp):
        k = (idx // (2 ** j)) ^ 1                              # Geschwister-Index auf Ebene j
        AUTH[j] = xmss_node(SK_seed, k, j, PK_seed, ADRS, P)
    ADRS.setTypeAndClear(WOTS_HASH)
    ADRS.setKeyPairAddress(idx)
    sig = wots_sign(M, SK_seed, PK_seed, ADRS, P)
    SIG_XMSS = (sig, AUTH)
    return SIG_XMSS


def xmss_pkFromSig(idx: int, SIG_XMSS, M: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    """Alg. 11. Erst den WOTS+-Public-Key aus der WOTS+-Signatur rekonstruieren,
    dann mit dem Authentifizierungspfad Schritt fuer Schritt bis zur Wurzel
    hochrechnen -- je nachdem ob idx an der jeweiligen Stelle 0 oder 1 ist,
    kommt der AUTH-Knoten links oder rechts dazu."""
    ADRS.setTypeAndClear(WOTS_HASH)
    ADRS.setKeyPairAddress(idx)
    sig = SIG_XMSS[0]
    AUTH = SIG_XMSS[1]
    node = [None, None]
    node[0] = wots_pkFromSig(sig, M, PK_seed, ADRS, P)

    ADRS.setTypeAndClear(TREE)
    ADRS.setTreeIndex(idx)
    for k in range(P.hp):
        ADRS.setTreeHeight(k + 1)
        if (idx // (2 ** k)) % 2 == 0:
            ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
            node[1] = H(PK_seed, ADRS, node[0] + AUTH[k], P.n)
        else:
            ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
            node[1] = H(PK_seed, ADRS, AUTH[k] + node[0], P.n)
        node[0] = node[1]
    return node[0]
