# SLH-DSA / SPHINCS+ — Python-Referenzimplementierung nach NIST FIPS 205

Vollständige Implementierung von SLH-DSA (Stateless Hash-Based Digital Signature
Algorithm, besser bekannt als SPHINCS+) in reinem Python, exakt nach den
Algorithmen 1–25 aus [FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf),
inklusive einer interaktiven Streamlit-Oberfläche zum Ausprobieren von
Schlüsselerzeugung, Signieren und Verifizieren.

Details zu Architektur, Sicherheitsbegründung und Entwurfsentscheidungen stehen
in der Projektdokumentation (`SLH-DSA_Projektdokumentation_v9.pdf`).

## Voraussetzungen

- Python 3
- [Streamlit](https://streamlit.io/) — einzige externe Abhängigkeit, nur für die Oberfläche:

  ```
  pip install streamlit
  ```

Die eigentliche Kryptographie (Hashfunktionen, Baumaufbau, Signaturlogik) nutzt
ausschließlich die Python-Standardbibliothek (`hashlib`, `dataclasses`, `os`).

## Struktur

| Datei | Verantwortlichkeit | FIPS-205-Algorithmen |
|---|---|---|
| `sphincs_hilfsfunktionen.py` | Bit-/Byte-Konvertierung, ADRS-Adressierung, Hashfunktionen, Parameter | 1–5 |
| `wots.py` | Einmal-Signatur WOTS+ | 6–8 |
| `xmss.py` | Merkle-Baum aus WOTS+-Schlüsselpaaren | 9–11 |
| `hypertree.py` | Verkettung mehrerer XMSS-Bäume | 12–13 |
| `fors.py` | Few-Time-Signatur für den Nachrichten-Digest | 14–17 |
| `slh_dsa.py` | Zusammenführung zur vollständigen Signaturschnittstelle | 18–25 |
| `serialisierung.py` | Byte-/Hex-Kodierung von SK, PK, SIG (FIPS 205, Figuren 15–17) | — |
| `sphincs_algorithmen.py` | Kompatibilitäts-Shim (Re-Export aller Namen) | — |
| `streamlit_sphincs.py` | Interaktive Weboberfläche (Einstiegspunkt) | — |
| `test_slh_dsa.py` | Automatisierte Tests (siehe unten) | — |

Die Abhängigkeitsrichtung ist strikt einseitig und folgt der Konstruktionsreihenfolge
von SPHINCS+: `streamlit_sphincs.py` → `slh_dsa.py` → `hypertree.py` / `fors.py` /
`xmss.py` → `wots.py` → `sphincs_hilfsfunktionen.py`.

## App starten

```
streamlit run streamlit_sphincs.py
```

Ablauf in der Oberfläche: Parametersatz wählen (einer der 6 offiziellen
NIST-Parametersätze oder frei wählbare Werte für n, h', d, k, a) → Operation wählen
(Schlüsselerzeugung, Signieren, Verifizieren) → Berechnen. SK, PK und SIG werden als
Hex-String ein-/ausgegeben, da Signieren und Verifizieren laut FIPS 205 unabhängige
Operationen sind. Jede Operation zeigt zusätzlich ihre Rechenzeit an. Wird bei einem
NIST-Preset ein Parameter manuell verändert, warnt die App, dass die zugesicherte
Sicherheitsstufe nicht mehr gilt.

## Tests ausführen

```
python3 -m unittest test_slh_dsa.py -v
```

Der primäre Korrektheitsnachweis (`TestNistParametersaetze`) läuft mit allen 6
offiziellen NIST-Parametersätzen (nicht mit frei erfundenen Werten) und dauert
insgesamt einige Minuten. `TestRandfaelle` prüft zusätzlich einzelne
Verhaltensdetails (leere Nachricht, zu langer Kontextstring, falscher Public Key,
alle vier Pre-Hash-Funktionen) mit kleinen Parametern in unter einer Sekunde.

## Die 6 offiziellen NIST-Parametersätze

| Parametersatz | n (Byte) | h' | d | k | a | Sicherheit |
|---|---|---|---|---|---|---|
| SLH-DSA-SHAKE-128s | 16 | 9 | 7 | 14 | 12 | ~128 Bit |
| SLH-DSA-SHAKE-128f | 16 | 3 | 22 | 33 | 6 | ~128 Bit |
| SLH-DSA-SHAKE-192s | 24 | 9 | 7 | 17 | 14 | ~192 Bit |
| SLH-DSA-SHAKE-192f | 24 | 3 | 22 | 33 | 8 | ~192 Bit |
| SLH-DSA-SHAKE-256s | 32 | 8 | 8 | 22 | 14 | ~256 Bit |
| SLH-DSA-SHAKE-256f | 32 | 4 | 17 | 35 | 9 | ~256 Bit |

`s` (small signature) vs. `f` (fast signing) ändert nicht die Sicherheitsstufe,
nur den Größen-/Geschwindigkeits-Kompromiss bei gleichem n. Alle sechs Sätze wurden
in der Streamlit-App und in `test_slh_dsa.py` erfolgreich getestet.

## Bekannte Einschränkungen

- Nicht constant-time / nicht seitenkanalresistent — dient Demonstrations- und
  Lernzwecken, nicht dem produktiven Einsatz mit echten Geheimnissen.
- Nur SHAKE256 als Hash-Instanziierung implementiert (FIPS 205 erlaubt auch SHA-2).
- Kein Caching zwischen Baumknoten — `xmss_node`/`fors_node` berechnen bei jedem
  Aufruf den vollständigen Teilbaum neu.

Details siehe Kapitel "Bekannte Einschränkungen" und "Fazit und Ausblick" in der
Projektdokumentation.
