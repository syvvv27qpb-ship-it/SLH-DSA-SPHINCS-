"""
FORS -- Forest of Random Subsets (FIPS 205, Abschnitt 8).

Alg. 14 (fors_skGen), Alg. 15 (fors_node), Alg. 16 (fors_sign),
Alg. 17 (fors_pkFromSig). FORS ist das, was die eigentliche Nachricht
signiert -- k kleine Baeume statt eines einzelnen WOTS+-Blatts, damit ein
Blatt auch ein paar Mal (nicht nur einmal) sicher verwendet werden kann.
"""

from sphincs_hilfsfunktionen import Params, ADRS, PRF, F, H, T, base_2b, FORS_PRF, FORS_ROOTS


def fors_skGen(SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", idx: int, P: Params) -> bytes:
    """Alg. 14. Geheimwert per PRF, genau wie bei WOTS+ -- nur eben pro
    FORS-Blattindex statt pro Kette."""
    skADRS = ADRS.copy()
    skADRS.setTypeAndClear(FORS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    skADRS.setTreeIndex(idx)
    return PRF(PK_seed, SK_seed, skADRS, P.n)


def fors_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    """Alg. 15, rekursiv -- vom Aufbau her wie xmss_node, nur dass hier ein
    einzelner Baum von potenziell k FORS-Baeumen gemeint ist (welcher, steckt
    im Indexbereich von i)."""
    if z == 0:
        sk = fors_skGen(SK_seed, PK_seed, ADRS, i, P)
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i)
        node = F(PK_seed, ADRS, sk, P.n)
    else:
        lnode = fors_node(SK_seed, 2 * i, z - 1, PK_seed, ADRS, P)
        rnode = fors_node(SK_seed, 2 * i + 1, z - 1, PK_seed, ADRS, P)
        ADRS.setTreeHeight(z)
        ADRS.setTreeIndex(i)
        node = H(PK_seed, ADRS, lnode + rnode, P.n)
    return node


def fors_sign(md: bytes, SK_seed: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params):
    """Alg. 16. md liefert (via base_2b) fuer jeden der k Baeume einen Index;
    fuer jeden dieser Indizes werden Geheimwert + Authentifizierungspfad in
    die Signatur gepackt -- mehr wird nicht preisgegeben."""
    SIG_FORS = []
    indices = base_2b(md, P.a, P.k)
    for i in range(P.k):
        SIG_FORS.append(fors_skGen(SK_seed, PK_seed, ADRS, i * (2 ** P.a) + indices[i], P))
        AUTH = [None] * P.a
        for j in range(P.a):
            s = (indices[i] // (2 ** j)) ^ 1                   # Geschwister-Index auf Ebene j
            AUTH[j] = fors_node(SK_seed, i * (2 ** (P.a - j)) + s, j, PK_seed, ADRS, P)
        SIG_FORS.append(AUTH)
    return SIG_FORS


def fors_pkFromSig(SIG_FORS, md: bytes, PK_seed: bytes, ADRS: "ADRS", P: Params) -> bytes:
    """Alg. 17. Aus der Signatur alle k Baumwurzeln rekonstruieren und mit T
    zu einem einzigen FORS-Public-Key zusammenfassen -- der wird gleich
    danach in slh_dsa.py selbst wie eine Nachricht vom Hypertree signiert."""
    indices = base_2b(md, P.a, P.k)
    root = [None] * P.k
    for i in range(P.k):
        sk = SIG_FORS[2 * i]
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i * (2 ** P.a) + indices[i])
        node = [None, None]
        node[0] = F(PK_seed, ADRS, sk, P.n)
        auth = SIG_FORS[2 * i + 1]
        for j in range(P.a):
            ADRS.setTreeHeight(j + 1)
            if (indices[i] // (2 ** j)) % 2 == 0:
                ADRS.setTreeIndex(ADRS.getTreeIndex() // 2)
                node[1] = H(PK_seed, ADRS, node[0] + auth[j], P.n)
            else:
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) // 2)
                node[1] = H(PK_seed, ADRS, auth[j] + node[0], P.n)
            node[0] = node[1]
        root[i] = node[0]
    forspkADRS = ADRS.copy()
    forspkADRS.setTypeAndClear(FORS_ROOTS)
    forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    pk = T(PK_seed, forspkADRS, b"".join(root), P.n)
    return pk
