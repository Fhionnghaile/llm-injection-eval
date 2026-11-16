"""The layered defence pipeline. Each layer is a real, inspectable transform or gate.

Layers (composable, each independently toggleable):
  1. sanitize     — undo obfuscation: strip zero-width, normalise homoglyphs, decode
                    inline base64, fold leetspeak, un-hide HTML comments. Transforms
                    text so the detector sees through encoding (but not novel phrasing).
  2. detect       — signature match for injection patterns -> BLOCK. Has real misses
                    (novel phrasings) and real false positives (benign look-alikes).
  3. isolate      — structural: untrusted content cannot change the control plane, so the
                    `override` intent is neutralised regardless of wording.
  4. gate         — capability isolation: a protected tool needs an out-of-band token that
                    untrusted content cannot supply, so `tool` intent is blocked by
                    construction — the principled, obfuscation-proof defence.
  5. output_filter— scans the agent's would-be output for the secret and redacts it,
                    blocking verbatim `exfil` (but not a semantically-encoded leak).

A layer returns a decision for a given item; the pipeline composes them.
"""
from __future__ import annotations
import base64, re, unicodedata
from dataclasses import dataclass
from .corpus import SECRET, FORBIDDEN_TOOL

_HOMO_INV = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
             "і": "i", "ѕ": "s"}
_LEET_INV = str.maketrans({"@": "a", "3": "e", "1": "i", "0": "o", "5": "s"})


def sanitize(text: str) -> str:
    t = text.replace("​", "")                       # zero-width
    t = "".join(_HOMO_INV.get(ch, ch) for ch in t)       # homoglyph -> ascii
    t = unicodedata.normalize("NFKC", t)
    t = re.sub(r"<!--(.*?)-->", r" \1 ", t, flags=re.S)  # un-hide comments
    # decode any base64-looking blobs and append their plaintext for inspection
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", t):
        try:
            dec = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
            if dec.isprintable():
                t += " " + dec
        except Exception:
            pass
    t = t.translate(_LEET_INV)
    return t


# signatures the detector knows (deliberately NOT exhaustive -> honest misses)
_SIGS = [
    r"ignore (all |your )?previous instructions",
    r"disregard (your )?system prompt",
    r"developer mode",
    r"print the api key",
    r"reveal (the )?(secret|api key|credentials)",
    rf"call {re.escape(FORBIDDEN_TOOL)}",
]
_SIG_RE = re.compile("|".join(_SIGS), re.I)


def detect(text: str) -> bool:
    """True = flagged as an injection (would be BLOCKED)."""
    return bool(_SIG_RE.search(text))


@dataclass
class Pipeline:
    sanitize: bool = False
    detect: bool = False
    isolate: bool = False
    gate: bool = False
    output_filter: bool = False

    def layers(self):
        return [n for n in ("sanitize", "detect", "isolate", "gate", "output_filter")
                if getattr(self, n)]


# canonical configurations, from nothing to defence-in-depth
def configs():
    return {
        "none":              Pipeline(),
        "detect_only":       Pipeline(sanitize=True, detect=True),
        "isolate+gate":      Pipeline(isolate=True, gate=True),
        "detect+isolate+gate": Pipeline(sanitize=True, detect=True, isolate=True, gate=True),
        "full_defense_in_depth": Pipeline(sanitize=True, detect=True, isolate=True,
                                          gate=True, output_filter=True),
    }
