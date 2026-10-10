"""
Hypertree -- mehrere XMSS-Baeume uebereinander gestapelt (FIPS 205, Abschnitt 7).

Alg. 12 (ht_sign), Alg. 13 (ht_verify). Ein einzelner XMSS-Baum waere zu
klein, um alle jemals benoetigten Signaturen abzudecken; der Hypertree
verkettet deshalb d Baeume, wobei jede Schicht die Wurzel der Schicht
darunter signiert.
"""

from sphincs_hilfsfunktionen import Params, ADRS_zero
from xmss import xmss_sign, xmss_pkFromSig


def ht_sign(M: bytes, SK_seed: bytes, PK_seed: bytes, idx_tree: int, idx_leaf: int, P: Params):
    """Alg. 12. Start bei Schicht 0, dort wird M direkt signiert. Danach wird
    fuer jede weitere Schicht die Wurzel der vorherigen Schicht signiert --
    idx_tree/idx_leaf werden dabei per Bit-Shift um hp Stellen heruntergebrochen,
    damit jede Schicht ihren eigenen (kleineren) Baumindex bekommt."""
    ADRS = ADRS_zero()
    ADRS.setTreeAddress(idx_tree)
    SIG_tmp = xmss_sign(M, SK_seed, idx_leaf, PK_seed, ADRS, P)
    SIG_HT = [SIG_tmp]
    root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS, P)
    for j in range(1, P.d):
        idx_leaf = idx_tree % (2 ** P.hp)                      # untere hp Bits von idx_tree
        idx_tree = idx_tree >> P.hp                            # ... und wieder abschneiden
        ADRS.setLayerAddress(j)
        ADRS.setTreeAddress(idx_tree)
        SIG_tmp = xmss_sign(root, SK_seed, idx_leaf, PK_seed, ADRS, P)
        SIG_HT.append(SIG_tmp)
        if j < P.d - 1:
            root = xmss_pkFromSig(idx_leaf, SIG_tmp, root, PK_seed, ADRS, P)
    return SIG_HT


def ht_verify(M: bytes, SIG_HT, PK_seed: bytes, idx_tree: int, idx_leaf: int, PK_root: bytes, P: Params) -> bool:
    """Alg. 13. Spiegelt ht_sign: denselben Weg von Schicht 0 bis d-1 nochmal
    laufen, aber diesmal die Wurzel jeweils *rekonstruieren* statt neu zu
    signieren, und am Ende mit PK_root vergleichen."""
    ADRS = ADRS_zero()
    ADRS.setTreeAddress(idx_tree)
    SIG_tmp = SIG_HT[0]
    node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK_seed, ADRS, P)
    for j in range(1, P.d):
        idx_leaf = idx_tree % (2 ** P.hp)
        idx_tree = idx_tree >> P.hp
        ADRS.setLayerAddress(j)
        ADRS.setTreeAddress(idx_tree)
        SIG_tmp = SIG_HT[j]
        node = xmss_pkFromSig(idx_leaf, SIG_tmp, node, PK_seed, ADRS, P)
    if node == PK_root:
        return True
    else:
        return False
