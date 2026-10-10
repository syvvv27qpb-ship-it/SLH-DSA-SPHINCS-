# SLH-DSA / SPHINCS+ — Python Reference Implementation according to NIST FIPS 205

> **Language note:** The code comments and the full project documentation (`SLH-DSA_Projektdokumentation_v9.pdf`) are written in **German**. This README is in English for accessibility.

A complete implementation of SLH-DSA (Stateless Hash-Based Digital Signature
Algorithm, better known as SPHINCS+) in pure Python, following Algorithms 1–25 of
[FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf) exactly,
including an interactive Streamlit interface for trying out key generation,
signing and verification.

Details on the architecture, security rationale and design decisions can be found
in the project documentation (`SLH-DSA_Projektdokumentation_v9.pdf`).

## Requirements

- Python 3
- [Streamlit](https://streamlit.io/) — the only external dependency, needed only for the interface:

  ```
  pip install streamlit
  ```

The cryptography itself (hash functions, tree construction, signature logic) uses
only the Python standard library (`hashlib`, `dataclasses`, `os`).

## Structure

| File | Responsibility | FIPS 205 Algorithms |
|---|---|---|
| `sphincs_hilfsfunktionen.py` | Bit/byte conversion, ADRS addressing, hash functions, parameters | 1–5 |
| `wots.py` | One-time signature WOTS+ | 6–8 |
| `xmss.py` | Merkle tree built from WOTS+ key pairs | 9–11 |
| `hypertree.py` | Chaining of multiple XMSS trees | 12–13 |
| `fors.py` | Few-time signature for the message digest | 14–17 |
| `slh_dsa.py` | Assembly into the complete signature interface | 18–25 |
| `serialisierung.py` | Byte/hex encoding of SK, PK, SIG (FIPS 205, Figures 15–17) | — |
| `sphincs_algorithmen.py` | Compatibility shim (re-exports all names) | — |
| `streamlit_sphincs.py` | Interactive web interface (entry point) | — |
| `test_slh_dsa.py` | Automated tests (see below) | — |

The dependency direction is strictly one-way and follows the construction order
of SPHINCS+: `streamlit_sphincs.py` → `slh_dsa.py` → `hypertree.py` / `fors.py` /
`xmss.py` → `wots.py` → `sphincs_hilfsfunktionen.py`.

## Running the App

```
streamlit run streamlit_sphincs.py
```

Workflow in the interface: choose a parameter set (one of the 6 official NIST
parameter sets, or freely selectable values for n, h', d, k, a) → choose an
operation (key generation, signing, verification) → compute. SK, PK and SIG are
entered and displayed as hex strings, since signing and verification are
independent operations according to FIPS 205. Each operation also shows its
computation time. If a parameter of a NIST preset is changed manually, the app
warns that the guaranteed security level no longer applies.

## Running the Tests

```
python3 -m unittest test_slh_dsa.py -v
```

The primary proof of correctness (`TestNistParametersaetze`) runs with all 6
official NIST parameter sets (not with arbitrary values) and takes a few minutes
in total. `TestRandfaelle` additionally checks individual behavioural details
(empty message, context string too long, wrong public key, all four pre-hash
functions) with small parameters in under a second.

## The 6 Official NIST Parameter Sets

| Parameter set | n (bytes) | h' | d | k | a | Security |
|---|---|---|---|---|---|---|
| SLH-DSA-SHAKE-128s | 16 | 9 | 7 | 14 | 12 | ~128 bit |
| SLH-DSA-SHAKE-128f | 16 | 3 | 22 | 33 | 6 | ~128 bit |
| SLH-DSA-SHAKE-192s | 24 | 9 | 7 | 17 | 14 | ~192 bit |
| SLH-DSA-SHAKE-192f | 24 | 3 | 22 | 33 | 8 | ~192 bit |
| SLH-DSA-SHAKE-256s | 32 | 8 | 8 | 22 | 14 | ~256 bit |
| SLH-DSA-SHAKE-256f | 32 | 4 | 17 | 35 | 9 | ~256 bit |

`s` (small signature) vs. `f` (fast signing) does not change the security level,
only the size/speed trade-off for the same n. All six sets were successfully
tested in the Streamlit app and in `test_slh_dsa.py`.

## Known Limitations

- Not constant-time / not side-channel resistant — intended for demonstration and
  learning purposes, not for production use with real secrets.
- Only SHAKE256 is implemented as the hash instantiation (FIPS 205 also allows SHA-2).
- No caching between tree nodes — `xmss_node`/`fors_node` recompute the entire
  subtree on every call.

For details, see the chapters "Bekannte Einschränkungen" (Known Limitations) and
"Fazit und Ausblick" (Conclusion and Outlook) in the project documentation.
