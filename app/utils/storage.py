import json
import os
import unicodedata
from pathlib import Path

from filelock import FileLock

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
LOCK_PATH = DATA_DIR / ".data.lock"


def _strip_accents(txt: str) -> str:
    """Remove accents (é -> e) to make comparisons and filtering robust."""
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", txt) if not unicodedata.combining(ch)
    )


def normalize_segment(seg) -> str:
    """Normalize segment values coming from PDFs/Word (SOUS-PREFECTURE, Sous Préfecture...)."""
    s = _strip_accents(str(seg or "COMMUNE")).upper().strip()
    s = s.replace("-", "_").replace(" ", "_")
    while "__" in s:
        s = s.replace("__", "_")
    return s


def canonicalize_voting_center(c: dict) -> dict:
    if not isinstance(c, dict):
        return {}
    out = dict(c)
    # Handle alternate keys
    if "nom" in out and "name" not in out:
        out["name"] = out.get("nom")
    if "segment" in out:
        out["segment"] = normalize_segment(out.get("segment"))
    return out


def canonicalize_polling_station(s: dict) -> dict:
    if not isinstance(s, dict):
        return {}
    out = dict(s)

    # Normalize segment (critical for counting + scoping)
    out["segment"] = normalize_segment(out.get("segment"))

    # Key mapping: some imports used French column names
    if "centre_nom" in out and "centre_name" not in out:
        out["centre_name"] = out.get("centre_nom")
    if "bureau_nom" in out and "name" not in out:
        out["name"] = out.get("bureau_nom")
    if "nom" in out and "name" not in out:
        out["name"] = out.get("nom")
    if "inscrits" in out and "registered" not in out:
        out["registered"] = out.get("inscrits")

    # Derive bureau_code if missing (ex: BONOUA-001-BV01 -> BV01)
    if not out.get("bureau_code"):
        code = out.get("code", "")
        if isinstance(code, str) and "-" in code:
            out["bureau_code"] = code.split("-")[-1]

    # Derive a safe default name if still missing
    if not out.get("name"):
        centre_code = out.get("centre_code", "")
        centre_name = out.get("centre_name", "")
        bureau_code = out.get("bureau_code", "")
        out["name"] = f"{centre_code} - {centre_name} / {bureau_code}".strip()

    return out

def _lock() -> FileLock:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return FileLock(str(LOCK_PATH))

def load_json(filename: str, default):
    path = DATA_DIR / filename
    if not path.exists():
        return default
    with _lock():
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

    # Backward/forward compatible normalization
    if filename == "voting_centers.json" and isinstance(data, list):
        data = [canonicalize_voting_center(x) for x in data]
    if filename == "polling_stations.json" and isinstance(data, list):
        data = [canonicalize_polling_station(x) for x in data]

    return data

def save_json(filename: str, data) -> None:
    path = DATA_DIR / filename
    tmp = DATA_DIR / (filename + ".tmp")
    with _lock():
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

def touch_last_update() -> None:
    meta = load_json("meta.json", default={})
    meta["last_update_utc"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
    save_json("meta.json", meta)
