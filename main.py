"""
CryptoLink - Exchange file import and cataloging tool
Run with: python main.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, send_file
import pandas as pd
import uuid
import io
import os
import traceback
from datetime import datetime
from docx import Document
from docx.shared import Pt, RGBColor
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False  # keep UTF-8 (Hebrew, etc.) readable in JSON responses

# The Graph tab's vis-network library is embedded directly into the page (see index()
# below) instead of loaded from a CDN or a separate /static request - this used to pull
# from unpkg.com at runtime, which silently breaks the whole tab on any offline/restricted
# network (common for forensic workstations). Vendored file, read once at startup.
# Missing file (e.g. main.py was copied without its static/ folder) degrades to a disabled
# Graph tab instead of crashing the whole app on startup.
try:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "vis-network.min.js"), encoding="utf-8") as _f:
        VIS_NETWORK_JS = _f.read()
except FileNotFoundError:
    print("WARNING: static/vis-network.min.js not found - the Graph tab will be disabled. "
          "Copy the whole project (including the static/ folder) to fix this.")
    VIS_NETWORK_JS = "console.error('vis-network.min.js missing - copy the static/ folder from the project.');"

# In-memory storage (no database yet)
SUSPECTS = {}   # suspect_id -> {"name": str}
CATALOG = {}    # file_id -> {..., "suspect_id": str, "dataframe": DataFrame}
# lower(address) -> original-case address, manually marked as noise (e.g. a known exchange
# hot wallet touched by unrelated users) and excluded from address-based cross-referencing
# (Wallets/Transfers/Graph). Individual transactions through it still show in Amounts.
EXCLUDED_ADDRESSES = {}

# ---------------------------------------------------------------------------
# DETECTION
# ---------------------------------------------------------------------------

EXCHANGE_KEYWORDS = {
    "binance": ["binance"],
    "okx": ["okx", "okex"],
    "bybit": ["bybit"],
    "redotpay": ["redot", "redotpay", "redot pay"],
    "matrix": ["matrix"],
}

NORMALIZATION_SCHEMAS = {
    ("binance", "deposit"): {
        "date": "Create Time", "currency": "Currency", "amount": "Amount",
        "amount_usd": "USDT",
        "network": "Network", "txid": "TXID",
        "external_address": "Source Address", "exchange_address": "Deposit Address",
        "user_id": "User ID", "status": "Status",
    },
    ("binance", "withdrawal"): {
        "date": "Apply Time", "currency": "Currency", "amount": "Amount",
        "amount_usd": "USDT",
        "network": "Network", "txid": "txId",
        "external_address": "Destination Address", "exchange_address": None,
        "user_id": "User ID", "status": "Status",
    },
    ("okx", "deposit"): {
        "date": "creation time", "currency": "currency", "amount": "amount",
        "network": None, "txid": "txid",
        "external_address": None, "exchange_address": "address",
        "user_id": "uuid", "status": None,
    },
    ("okx", "withdrawal"): {
        "date": "creation time", "currency": "currency", "amount": "amount",
        "network": None, "txid": "txid",
        "external_address": "address", "exchange_address": None,
        "user_id": "uuid", "status": None,
    },
    ("bybit", "deposit"): {
        "date": "deposit_coin_time", "currency": "coin", "amount": "change_amount",
        "amount_usd": "change_amount_usd",
        "network": None, "txid": "tx_id",
        "external_address": "from_address", "exchange_address": "to_address",
        "user_id": "user_id", "status": None,
    },
    ("bybit", "withdrawal"): {
        "date": "submitted_time", "currency": "coin", "amount": "amount",
        "amount_usd": "amount_usd",
        "network": None, "txid": "tx_id",
        "external_address": "to_address", "exchange_address": "from_address",
        "user_id": "user_id", "status": None,
    },
    ("matrix", "deposit"): {
        "date": "Time", "currency": "Currency", "amount": "Amount",
        "network": "Coin", "txid": "Transaction hash",
        "external_address": "Originating Address", "exchange_address": "Recharge address",
        "user_id": None, "status": None,
    },
    ("matrix", "withdrawal"): {
        "date": "Time", "currency": "Currency", "amount": "Amount",
        "network": "Blockchain", "txid": "Transaction hash",
        "external_address": "Withdrawal address", "exchange_address": None,
        "user_id": None, "status": None,
    },
    ("redotpay", "deposit"): {
        "date": "Time", "currency": "Currency", "amount": "Amount",
        "network": "Blockchain", "txid": "Hash",
        "external_address": "Originating Address", "exchange_address": "Deposit Address",
        "user_id": None, "status": None,
    },
    ("redotpay", "withdrawal"): {
        "date": "Time", "currency": "Currency", "amount": "Amount",
        "network": "Blockchain", "txid": "Hash",
        "external_address": "Withdrawal Address", "exchange_address": None,
        "user_id": None, "status": None,
    },
}


def normalize_dataframe(df, exchange, file_type):
    schema = NORMALIZATION_SCHEMAS.get((exchange, file_type))
    if not schema:
        return None, ["no_schema_for_this_exchange"]

    col_lookup = {str(c).strip().lower(): c for c in df.columns}
    normalized = pd.DataFrame(index=df.index)
    missing = []

    for field, source_col in schema.items():
        if source_col is None:
            normalized[field] = None
            continue
        actual_col = col_lookup.get(source_col.strip().lower())
        if actual_col is None:
            normalized[field] = None
            missing.append(field)
        else:
            normalized[field] = df[actual_col]

    return normalized, missing


DEPOSIT_KEYWORDS = ["deposit", "depot", "recu", "receive", "top up", "topup"]
WITHDRAWAL_KEYWORDS = ["withdraw", "retrait", "send", "payout"]


_ALL_KNOWN_COLUMNS = {
    v.strip().lower()
    for schema in NORMALIZATION_SCHEMAS.values()
    for v in schema.values() if v
}


def find_header_row(raw_df, max_scan_rows=15):
    """Some exchange exports have metadata/KYC rows above the real column
    titles (e.g. case info, account holder name) before the actual header row.
    Scans the first rows for the one that best matches known column names
    across all exchanges, and returns its 0-indexed position. Falls back to
    row 0 (the normal case) if nothing better is found."""
    best_row_idx, best_score = 0, 0
    scan_limit = min(max_scan_rows, len(raw_df))
    for i in range(scan_limit):
        row_values = {str(v).strip().lower() for v in raw_df.iloc[i].tolist() if pd.notna(v)}
        score = len(row_values & _ALL_KNOWN_COLUMNS)
        if score > best_score:
            best_score, best_row_idx = score, i
    return best_row_idx if best_score >= 2 else 0


def parse_sheet_smart(excel_file, sheet_name):
    """Parses a sheet, auto-detecting the real header row even if metadata
    rows (KYC info, case references, etc.) precede it."""
    raw = excel_file.parse(sheet_name, header=None)
    header_idx = find_header_row(raw)
    return excel_file.parse(sheet_name, header=header_idx)


def detect_exchange(filename, sheet_name, columns):
    for exchange, keywords in EXCHANGE_KEYWORDS.items():
        for kw in keywords:
            if kw in filename.lower() or kw in sheet_name.lower():
                return exchange

    # Fallback: match the uploaded file's actual column names against the real
    # column names captured in NORMALIZATION_SCHEMAS (from real exchange files),
    # instead of guessed keywords. Far more reliable when filename/sheet name
    # carries no brand hint (e.g. a generic export filename).
    col_set = {str(c).strip().lower() for c in columns}
    best_match, best_score = None, 0
    for (exchange, _file_type), schema in NORMALIZATION_SCHEMAS.items():
        expected_cols = {v.strip().lower() for v in schema.values() if v}
        score = len(col_set & expected_cols)
        if score > best_score:
            best_score, best_match = score, exchange

    # Require at least 2 matching columns - a single shared generic column
    # name (e.g. just "Currency" or "Amount") isn't a reliable signal on its own.
    return best_match if best_score >= 2 else "unknown"


def detect_file_type(filename, sheet_name, columns):
    text_blob = " ".join([filename.lower(), sheet_name.lower()])
    has_deposit = any(kw in text_blob for kw in DEPOSIT_KEYWORDS)
    has_withdrawal = any(kw in text_blob for kw in WITHDRAWAL_KEYWORDS)

    if has_deposit and not has_withdrawal:
        return "deposit"
    if has_withdrawal and not has_deposit:
        return "withdrawal"

    col_blob = " ".join(c.lower() for c in columns)
    if any(kw in col_blob for kw in DEPOSIT_KEYWORDS):
        return "deposit"
    if any(kw in col_blob for kw in WITHDRAWAL_KEYWORDS):
        return "withdrawal"

    return None  # not relevant -> will be ignored


# ---------------------------------------------------------------------------
# ROUTES - SUSPECTS
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return HTML_PAGE.replace("%%VIS_NETWORK_JS%%", VIS_NETWORK_JS, 1)


@app.route("/suspects", methods=["GET"])
def list_suspects():
    return jsonify([{"id": sid, "name": s["name"]} for sid, s in SUSPECTS.items()])


@app.route("/suspects", methods=["POST"])
def create_suspect():
    data = request.get_json()
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name required"}), 400
    sid = str(uuid.uuid4())
    SUSPECTS[sid] = {"name": name}
    return jsonify({"id": sid, "name": name})


@app.route("/suspects/<suspect_id>", methods=["DELETE"])
def delete_suspect(suspect_id):
    SUSPECTS.pop(suspect_id, None)
    to_remove = [fid for fid, f in CATALOG.items() if f["suspect_id"] == suspect_id]
    for fid in to_remove:
        del CATALOG[fid]
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# ROUTES - FILES
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():
    files = request.files.getlist("files")
    suspect_id = request.form.get("suspect_id")

    if not suspect_id or suspect_id not in SUSPECTS:
        return jsonify({"error": "No active suspect selected"}), 400
    if not files:
        return jsonify({"error": "No file received"}), 400

    results = []
    ignored_count = 0

    for f in files:
        # Filename may arrive in various encodings depending on browser/OS -
        # normalize defensively so non-Latin filenames (Hebrew, etc.) never crash the request.
        try:
            filename = f.filename or "unnamed_file"
        except Exception:
            filename = "unnamed_file"

        try:
            file_bytes = f.read()
            excel_file = pd.ExcelFile(io.BytesIO(file_bytes))
        except Exception as e:
            results.append({
                "id": str(uuid.uuid4()), "filename": filename,
                "error": f"Unable to read this file: {str(e)}",
            })
            continue

        for sheet_name in excel_file.sheet_names:
            try:
                df = parse_sheet_smart(excel_file, sheet_name)
            except Exception as e:
                results.append({
                    "id": str(uuid.uuid4()), "filename": filename, "sheet_name": sheet_name,
                    "error": f"Unable to read sheet '{sheet_name}': {str(e)}",
                })
                continue

            if df.empty or len(df.columns) == 0:
                continue

            columns = [str(c) for c in df.columns]
            file_type = detect_file_type(filename, sheet_name, columns)

            # Only keep Deposit / Withdrawal sheets - everything else is silently ignored
            if file_type is None:
                ignored_count += 1
                continue

            exchange = detect_exchange(filename, sheet_name, columns)
            file_id = str(uuid.uuid4())
            normalized_df, missing_fields = normalize_dataframe(df, exchange, file_type)

            CATALOG[file_id] = {
                "filename": filename, "sheet_name": sheet_name,
                "exchange": exchange, "file_type": file_type,
                "columns": columns, "row_count": len(df),
                "dataframe": df, "suspect_id": suspect_id,
                "normalized_dataframe": normalized_df, "missing_fields": missing_fields,
            }

            results.append({
                "id": file_id, "filename": filename, "sheet_name": sheet_name,
                "exchange": exchange, "file_type": file_type,
                "columns": columns, "row_count": len(df), "suspect_id": suspect_id,
                "missing_fields": missing_fields,
            })

    return jsonify({"results": results, "ignored_count": ignored_count})


@app.route("/update_label", methods=["POST"])
def update_label():
    data = request.get_json()
    file_id = data.get("id")
    field = data.get("field")
    value = data.get("value")

    if file_id not in CATALOG:
        return jsonify({"error": "File not found"}), 404
    if field not in ("exchange", "file_type", "suspect_id"):
        return jsonify({"error": "Invalid field"}), 400

    CATALOG[file_id][field] = value
    return jsonify({"success": True})


@app.route("/preview/<file_id>")
def preview(file_id):
    if file_id not in CATALOG:
        return jsonify({"error": "File not found"}), 404

    try:
        entry = CATALOG[file_id]
        df = entry["dataframe"].head(15)
        # fillna("") before stringifying: pandas' astype(str) leaves empty cells
        # as raw NaN instead of converting them to text, which breaks JSON output
        # (this is exactly what was happening with MatrixPort files with blank cells)
        preview_data = df.fillna("").astype(str).to_dict(orient="records")
        return jsonify({
            "filename": entry["filename"], "sheet_name": entry["sheet_name"],
            "columns": entry["columns"], "rows": preview_data,
        })
    except Exception as e:
        # Surface the real error to the UI instead of a silent/generic failure,
        # so any issue tied to specific file content can be diagnosed precisely.
        traceback.print_exc()
        return jsonify({"error": f"Preview failed: {str(e)}"}), 500


def _to_float(val):
    try:
        if val is None:
            return None
        f = float(val)
        return None if f != f else f  # filters NaN
    except (TypeError, ValueError):
        return None


def _to_datetime(val):
    try:
        ts = pd.to_datetime(val, errors="coerce")
        return None if pd.isna(ts) else ts
    except Exception:
        return None


def _clean_str(val):
    """Converts a pandas cell to a clean string, or None if empty/NaN.
    Needed because pandas leaves blank cells as raw float NaN, which
    breaks JSON output (same root cause as the earlier MatrixPort preview bug -
    here applied to every text field, not just external_address)."""
    if val is None:
        return None
    s = str(val).strip()
    return None if s == "" or s.lower() == "nan" else s


def get_all_transactions(suspect_ids=None):
    """Flattens every imported sheet's normalized data into one list of dicts,
    each tagged with which suspect/exchange/file it came from.
    If suspect_ids is given (a set/list), only those suspects' data is included -
    used to scope exports to selected suspects."""
    rows = []
    for file_id, entry in CATALOG.items():
        if suspect_ids is not None and entry["suspect_id"] not in suspect_ids:
            continue
        ndf = entry.get("normalized_dataframe")
        if ndf is None:
            continue
        suspect_name = SUSPECTS.get(entry["suspect_id"], {}).get("name", "Unknown suspect")
        has_usd = "amount_usd" in ndf.columns

        for _, r in ndf.iterrows():
            rows.append({
                "file_id": file_id,
                "suspect_id": entry["suspect_id"],
                "suspect_name": suspect_name,
                "exchange": entry["exchange"],
                "file_type": entry["file_type"],
                "date": _to_datetime(r.get("date")),
                "currency": _clean_str(r.get("currency")),
                "amount": _to_float(r.get("amount")),
                "amount_usd": _to_float(r.get("amount_usd")) if has_usd else None,
                "txid": _clean_str(r.get("txid")),
                "external_address": _clean_str(r.get("external_address")),
            })
    return rows


def compute_addresses_analysis(suspect_ids=None):
    """Dominant wallets + addresses shared across different suspect/exchange combos."""
    rows = [r for r in get_all_transactions(suspect_ids)
            if r["external_address"] and r["external_address"].lower() not in EXCLUDED_ADDRESSES]

    # Group case-insensitively (ETH checksummed vs lowercase should still match),
    # but keep the first-seen original casing for display.
    by_address = {}
    for r in rows:
        by_address.setdefault(r["external_address"].lower(), []).append(r)

    results = []
    for addr_lower, occurrences in by_address.items():
        distinct_combos = {(o["suspect_id"], o["exchange"]) for o in occurrences}
        distinct_suspects = {o["suspect_id"] for o in occurrences}
        results.append({
            "address": occurrences[0]["external_address"],
            "occurrence_count": len(occurrences),
            "distinct_accounts": len(distinct_combos),
            "is_cross_account": len(distinct_combos) > 1,
            # Distinguishes "same person, multiple exchanges" (cross_account but not
            # cross_suspect) from "different people" (cross_suspect) - the two are very
            # different findings and were previously conflated into one flag.
            "distinct_suspect_count": len(distinct_suspects),
            "is_cross_suspect": len(distinct_suspects) > 1,
            "occurrences": [{
                "suspect_id": o["suspect_id"], "suspect_name": o["suspect_name"], "exchange": o["exchange"],
                "file_type": o["file_type"], "amount": o["amount"], "amount_usd": o["amount_usd"],
                "currency": o["currency"],
                "date": o["date"].isoformat() if o["date"] is not None else None,
                "txid": o["txid"],
            } for o in occurrences],
        })

    results.sort(key=lambda x: x["occurrence_count"], reverse=True)
    return results


def _parse_suspect_ids():
    """Reads the optional ?suspects=id1,id2 query param shared by every analysis/export
    route, so the same suspect-filter selection drives both the on-screen tabs and exports."""
    suspects_param = request.args.get("suspects", "").strip()
    return set(suspects_param.split(",")) if suspects_param else None


@app.route("/analysis/addresses")
def analysis_addresses():
    return jsonify(compute_addresses_analysis(_parse_suspect_ids()))


@app.route("/addresses/excluded", methods=["GET"])
def list_excluded_addresses():
    """Hidden wallets with enough context to decide whether to restore one without having
    to go re-check the Wallets tab - just the raw address isn't enough to remember why it
    mattered."""
    rows = [r for r in get_all_transactions() if r["external_address"]]
    by_address = {}
    for r in rows:
        by_address.setdefault(r["external_address"].lower(), []).append(r)

    result = []
    for addr_lower, original in EXCLUDED_ADDRESSES.items():
        occurrences = by_address.get(addr_lower, [])
        result.append({
            "address": original,
            "occurrence_count": len(occurrences),
            "suspect_names": sorted({o["suspect_name"] for o in occurrences}),
        })
    result.sort(key=lambda x: x["address"].lower())
    return jsonify(result)


@app.route("/addresses/exclude", methods=["POST"])
def exclude_address():
    data = request.get_json()
    addr = (data.get("address") or "").strip()
    if not addr:
        return jsonify({"error": "Address required"}), 400
    EXCLUDED_ADDRESSES[addr.lower()] = addr
    return jsonify({"success": True})


@app.route("/addresses/include", methods=["POST"])
def include_address():
    data = request.get_json()
    addr = (data.get("address") or "").strip().lower()
    EXCLUDED_ADDRESSES.pop(addr, None)
    return jsonify({"success": True})


def compute_amounts_analysis(suspect_ids=None):
    """Every transaction, sorted largest to smallest (USD-equivalent first when available)."""
    rows = get_all_transactions(suspect_ids)

    def sort_key(r):
        # rows with a USD value sort among themselves by that value;
        # rows without one fall back to raw amount, sorted after.
        return (r["amount_usd"] is not None, r["amount_usd"] or r["amount"] or 0)

    rows.sort(key=sort_key, reverse=True)

    return [{
        "suspect_name": r["suspect_name"], "exchange": r["exchange"], "file_type": r["file_type"],
        "amount": r["amount"], "amount_usd": r["amount_usd"], "currency": r["currency"],
        "date": r["date"].isoformat() if r["date"] is not None else None,
        "external_address": r["external_address"], "txid": r["txid"],
    } for r in rows]


@app.route("/analysis/amounts")
def analysis_amounts():
    return jsonify(compute_amounts_analysis(_parse_suspect_ids()))


def _transfer_side(o):
    return {
        "suspect_id": o["suspect_id"], "suspect_name": o["suspect_name"], "exchange": o["exchange"],
        "amount": o["amount"], "amount_usd": o["amount_usd"], "currency": o["currency"],
        "date": o["date"].isoformat(), "txid": o["txid"],
    }


def _pair_score(w, d):
    """Ranks a candidate (withdrawal, deposit) match sharing the same external address.
    Lower is better. Same-currency pairs whose amounts are close (tier 0) always outrank
    pairs with mismatched/unknown currency or amount (tier 1, only compared by time gap) -
    this is what lets the 1-to-1 matching below pick the single most plausible deposit for
    each withdrawal instead of pairing every withdrawal with every later deposit."""
    gap_hours = (d["date"] - w["date"]).total_seconds() / 3600
    same_currency = (
        w["currency"] is not None and d["currency"] is not None
        and w["currency"].strip().upper() == d["currency"].strip().upper()
    )
    rel_diff = None
    if same_currency and w["amount"] and d["amount"]:
        rel_diff = abs(w["amount"] - d["amount"]) / max(abs(w["amount"]), abs(d["amount"]), 1e-9)
    tier = 0 if rel_diff is not None else 1
    return (tier, rel_diff if rel_diff is not None else 0.0, gap_hours)


def compute_transfers_analysis(suspect_ids=None):
    """Links a withdrawal to a deposit two ways, in priority order:

    1. TXID match (confirmed): the exact same blockchain transaction hash was logged by
       both sides - one exchange recorded it as an outgoing withdrawal, another (or the same
       one) recorded it as an incoming deposit. Same hash = definitely the same transfer, no
       guessing. This also catches cases where one side's export has no usable address column
       at all but does log the tx hash.
    2. Address match (probable): no shared txid, but the withdrawal's destination address
       equals a later deposit's source address. Heuristic - ranked by currency/amount
       closeness then time gap.

    Every row is matched to AT MOST ONE counterpart: txid matching runs first and claims
    what it can with certainty, then address matching runs on whatever's left, greedily
    pairing best-match-first. This avoids pairing every withdrawal on an address with every
    later deposit on it (the earlier bug, which turned e.g. 3 withdrawals + 4 deposits on one
    address into up to 12 fabricated "transfers").

    Returns {"matched": [...], "unmatched": [...]}. Unmatched entries are withdrawals/deposits
    that had a txid or address to work with but couldn't be confidently linked to anything -
    still worth a human's attention, listed separately rather than dropped or force-matched.
    """
    rows = [r for r in get_all_transactions(suspect_ids)
            if r["date"] is not None and (r["txid"] or r["external_address"])]
    claimed = [False] * len(rows)
    matched = []

    def emit(wi, di, match_type):
        w, d = rows[wi], rows[di]
        tier, rel_diff, _ = _pair_score(w, d)
        claimed[wi] = claimed[di] = True
        matched.append({
            "address": w["external_address"] or d["external_address"],
            "match_type": match_type,
            "withdrawal": _transfer_side(w),
            "deposit": _transfer_side(d),
            "gap_hours": round(abs((d["date"] - w["date"]).total_seconds()) / 3600, 2),
            "same_suspect": w["suspect_id"] == d["suspect_id"],
            "same_exchange": w["exchange"] == d["exchange"],
            "amount_matched": tier == 0,
            "amount_diff_pct": round(rel_diff * 100, 2) if tier == 0 else None,
        })

    # Pass 1: exact TXID match - highest confidence, runs first so it claims rows before
    # the address heuristic gets a chance to guess wrong.
    by_txid = {}
    for i, r in enumerate(rows):
        if r["txid"]:
            by_txid.setdefault(r["txid"].strip().lower(), []).append(i)
    for idxs in by_txid.values():
        withdrawals = [i for i in idxs if rows[i]["file_type"] == "withdrawal"]
        deposits = [i for i in idxs if rows[i]["file_type"] == "deposit"]
        candidates = sorted(
            (abs((rows[di]["date"] - rows[wi]["date"]).total_seconds()), wi, di)
            for wi in withdrawals for di in deposits
        )
        for _, wi, di in candidates:
            if not claimed[wi] and not claimed[di]:
                emit(wi, di, "txid")

    # Pass 2: shared external address (only rows the txid pass didn't already claim; manually
    # excluded/noise addresses never participate in address-based matching).
    by_address = {}
    for i, r in enumerate(rows):
        if not claimed[i] and r["external_address"] and r["external_address"].lower() not in EXCLUDED_ADDRESSES:
            by_address.setdefault(r["external_address"].lower(), []).append(i)
    for idxs in by_address.values():
        withdrawals = [i for i in idxs if rows[i]["file_type"] == "withdrawal"]
        deposits = [i for i in idxs if rows[i]["file_type"] == "deposit"]
        candidates = []
        for wi in withdrawals:
            for di in deposits:
                if rows[di]["date"] < rows[wi]["date"]:
                    continue  # deposit happened before the withdrawal - not this direction
                candidates.append((_pair_score(rows[wi], rows[di]), wi, di))
        candidates.sort(key=lambda c: c[0])
        for score, wi, di in candidates:
            if not claimed[wi] and not claimed[di]:
                emit(wi, di, "address")

    unmatched = [
        {"address": r["external_address"], "direction": r["file_type"], **_transfer_side(r)}
        for i, r in enumerate(rows) if not claimed[i]
    ]

    matched.sort(key=lambda p: (p["match_type"] != "txid", p["gap_hours"]))
    unmatched.sort(key=lambda u: u["date"], reverse=True)
    return {"matched": matched, "unmatched": unmatched}


@app.route("/analysis/transfers")
def analysis_transfers():
    return jsonify(compute_transfers_analysis(_parse_suspect_ids()))


def _fmt_amount_export(amount, currency):
    if amount is None:
        return "-"
    return f"{amount:,.8f} {currency or ''}".rstrip("0").rstrip(".") if amount != int(amount) else f"{int(amount):,} {currency or ''}"


def _fmt_usd_export(amount_usd):
    return f"${amount_usd:,.2f}" if amount_usd is not None else ""


def _fmt_date_export(iso_str):
    if not iso_str:
        return "-"
    try:
        return datetime.fromisoformat(iso_str).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_str


def build_report_context(suspect_ids=None):
    """Gathers everything an export needs: the 3 analysis datasets plus
    metadata (generation time, suspects included). If suspect_ids is given,
    the report is scoped to only those suspects."""
    if suspect_ids is not None:
        names = sorted({s["name"] for sid, s in SUSPECTS.items() if sid in suspect_ids})
    else:
        names = sorted({s["name"] for s in SUSPECTS.values()})
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "suspect_names": names or ["(none)"],
        "addresses": compute_addresses_analysis(suspect_ids),
        "amounts": compute_amounts_analysis(suspect_ids),
        "transfers": compute_transfers_analysis(suspect_ids),
    }


# ---------------------------------------------------------------------------
# EXPORT - Excel
# ---------------------------------------------------------------------------

def export_xlsx(suspect_ids=None):
    import openpyxl
    from openpyxl.styles import Font, PatternFill

    ctx = build_report_context(suspect_ids)
    wb = openpyxl.Workbook()
    header_fill = PatternFill(start_color="1F2937", end_color="1F2937", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True)

    def write_header(ws, headers):
        ws.append(headers)
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = header_font

    # --- Wallets sheet (one row per occurrence, address repeated) ---
    ws = wb.active
    ws.title = "Wallets"
    write_header(ws, ["Address", "Total Occurrences", "Distinct Accounts", "Different People",
                       "Suspect", "Exchange", "Type", "Amount", "Currency", "Amount USD", "Date", "TXID"])
    for item in ctx["addresses"]:
        for o in item["occurrences"]:
            ws.append([
                item["address"], item["occurrence_count"], item["distinct_accounts"],
                "YES" if item["is_cross_suspect"] else "",
                o["suspect_name"], o["exchange"], o["file_type"],
                o["amount"], o["currency"], o["amount_usd"], _fmt_date_export(o["date"]), o["txid"],
            ])

    # --- Amounts sheet ---
    ws2 = wb.create_sheet("Amounts")
    write_header(ws2, ["Suspect", "Exchange", "Type", "Amount", "Currency", "Amount USD",
                        "Date", "External Address", "TXID"])
    for r in ctx["amounts"]:
        ws2.append([
            r["suspect_name"], r["exchange"], r["file_type"], r["amount"], r["currency"],
            r["amount_usd"], _fmt_date_export(r["date"]), r["external_address"], r["txid"],
        ])

    # --- Transfers sheet (one confirmed withdrawal <-> deposit match per row) ---
    ws3 = wb.create_sheet("Transfers")
    write_header(ws3, ["Match Type", "Address", "Same Person", "Same Exchange", "Amount Match", "Gap (hours)",
                        "Withdrawal Suspect", "Withdrawal Exchange", "Withdrawal Amount", "Withdrawal Date", "Withdrawal TXID",
                        "Deposit Suspect", "Deposit Exchange", "Deposit Amount", "Deposit Date", "Deposit TXID"])
    for p in ctx["transfers"]["matched"]:
        w, d = p["withdrawal"], p["deposit"]
        ws3.append([
            "TXID" if p["match_type"] == "txid" else "Address",
            p["address"], "YES" if p["same_suspect"] else "NO", "YES" if p["same_exchange"] else "NO",
            "YES" if p["amount_matched"] else "unverified", p["gap_hours"],
            w["suspect_name"], w["exchange"], w["amount"], _fmt_date_export(w["date"]), w["txid"],
            d["suspect_name"], d["exchange"], d["amount"], _fmt_date_export(d["date"]), d["txid"],
        ])

    # --- Unmatched movements sheet (shared address, no confident counterpart found) ---
    ws4 = wb.create_sheet("Unmatched movements")
    write_header(ws4, ["Address", "Direction", "Suspect", "Exchange", "Amount", "Currency", "Date", "TXID"])
    for u in ctx["transfers"]["unmatched"]:
        ws4.append([
            u["address"], u["direction"], u["suspect_name"], u["exchange"],
            u["amount"], u["currency"], _fmt_date_export(u["date"]), u["txid"],
        ])

    for ws_ in wb.worksheets:
        for col in ws_.columns:
            max_len = max((len(str(c.value)) for c in col if c.value is not None), default=10)
            ws_.column_dimensions[col[0].column_letter].width = min(max_len + 2, 45)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# EXPORT - Word
# ---------------------------------------------------------------------------

def export_docx(suspect_ids=None):
    ctx = build_report_context(suspect_ids)
    doc = Document()

    title = doc.add_heading("CryptoLink - Analysis Report", level=0)
    meta = doc.add_paragraph()
    meta.add_run(f"Generated: {ctx['generated_at']}\n").italic = True
    meta.add_run(f"Suspects included: {', '.join(ctx['suspect_names'])}").italic = True

    # --- Wallets ---
    doc.add_heading("Wallets", level=1)
    doc.add_paragraph(f"{len(ctx['addresses'])} distinct address(es), sorted by frequency.")
    for item in ctx["addresses"]:
        p = doc.add_paragraph()
        run = p.add_run(item["address"])
        run.bold = True
        run.font.name = "Consolas"
        p.add_run(f"  —  {item['occurrence_count']} occurrence(s), {item['distinct_accounts']} distinct account(s)")
        if item["is_cross_suspect"]:
            warn = p.add_run("  [SHARED BETWEEN DIFFERENT PEOPLE]")
            warn.bold = True
            warn.font.color.rgb = RGBColor(0xC0, 0x30, 0x30)
        elif item["is_cross_account"]:
            warn = p.add_run("  [SAME PERSON - MULTIPLE EXCHANGES]")
            warn.bold = True
            warn.font.color.rgb = RGBColor(0x1F, 0x5C, 0xA8)

        table = doc.add_table(rows=1, cols=6)
        table.style = "Light Grid Accent 1"
        hdr = table.rows[0].cells
        for i, h in enumerate(["Suspect", "Exchange", "Type", "Amount", "Date", "TXID"]):
            hdr[i].text = h
        for o in item["occurrences"]:
            row = table.add_row().cells
            row[0].text = o["suspect_name"]
            row[1].text = o["exchange"]
            row[2].text = o["file_type"]
            row[3].text = _fmt_amount_export(o["amount"], o["currency"])
            row[4].text = _fmt_date_export(o["date"])
            row[5].text = o["txid"] or "-"
        doc.add_paragraph()

    # --- Amounts ---
    doc.add_heading("Amounts", level=1)
    doc.add_paragraph(f"{len(ctx['amounts'])} transaction(s), sorted largest to smallest.")
    table = doc.add_table(rows=1, cols=7)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    for i, h in enumerate(["Suspect", "Exchange", "Type", "Amount", "Date", "Address", "TXID"]):
        hdr[i].text = h
    for r in ctx["amounts"]:
        row = table.add_row().cells
        row[0].text = r["suspect_name"]
        row[1].text = r["exchange"]
        row[2].text = r["file_type"]
        row[3].text = _fmt_amount_export(r["amount"], r["currency"]) + (f" ({_fmt_usd_export(r['amount_usd'])})" if r["amount_usd"] else "")
        row[4].text = _fmt_date_export(r["date"])
        row[5].text = r["external_address"] or "-"
        row[6].text = r["txid"] or "-"

    # --- Transfers ---
    matched, unmatched = ctx["transfers"]["matched"], ctx["transfers"]["unmatched"]
    doc.add_heading("Transfers", level=1)
    doc.add_paragraph(
        f"{len(matched)} confirmed transfer(s) - each withdrawal matched to its single most "
        f"likely deposit (closest amount/currency, then closest time), sorted by time gap."
    )
    for p in matched:
        w, d = p["withdrawal"], p["deposit"]
        para = doc.add_paragraph()
        if p["match_type"] == "txid":
            tag = para.add_run("[CONFIRMED - SAME TXID]  ")
            tag.bold = True
            tag.font.color.rgb = RGBColor(0x0F, 0x8A, 0x4E)
        para.add_run(f"Address: ").bold = True
        run = para.add_run(p["address"] or "-")
        run.font.name = "Consolas"
        if not p["same_suspect"]:
            warn = para.add_run("  [DIFFERENT PEOPLE]")
            warn.bold = True
            warn.font.color.rgb = RGBColor(0xC0, 0x80, 0x00)
        else:
            note = para.add_run("  [SAME PERSON]")
            note.bold = True
            note.font.color.rgb = RGBColor(0x1F, 0x5C, 0xA8)
        if not p["same_exchange"]:
            para.add_run("  (cross-exchange)")
        if not p["amount_matched"]:
            warn2 = para.add_run("  [amount unverified - review manually]")
            warn2.italic = True
            warn2.font.color.rgb = RGBColor(0xC0, 0x30, 0x30)

        table = doc.add_table(rows=3, cols=2)
        table.style = "Light Grid Accent 1"
        table.rows[0].cells[0].text = "Withdrawal (sent)"
        table.rows[0].cells[1].text = "Deposit (received)"
        table.rows[1].cells[0].text = f"{w['exchange']} — {w['suspect_name']}\n{_fmt_amount_export(w['amount'], w['currency'])}\n{_fmt_date_export(w['date'])}"
        table.rows[1].cells[1].text = f"{d['exchange']} — {d['suspect_name']}\n{_fmt_amount_export(d['amount'], d['currency'])}\n{_fmt_date_export(d['date'])}"
        table.rows[2].cells[0].text = f"TXID: {w['txid'] or '-'}"
        table.rows[2].cells[1].text = f"TXID: {d['txid'] or '-'}"
        doc.add_paragraph(f"Time gap: {p['gap_hours']} hour(s)")
        doc.add_paragraph()

    if unmatched:
        doc.add_heading("Unmatched movements (needs manual review)", level=1)
        doc.add_paragraph(
            f"{len(unmatched)} withdrawal(s)/deposit(s) couldn't be "
            f"confidently paired with a counterpart."
        )
        table = doc.add_table(rows=1, cols=6)
        table.style = "Light Grid Accent 1"
        hdr = table.rows[0].cells
        for i, h in enumerate(["Direction", "Suspect", "Exchange", "Amount", "Date", "Address"]):
            hdr[i].text = h
        for u in unmatched:
            row = table.add_row().cells
            row[0].text = u["direction"]
            row[1].text = u["suspect_name"]
            row[2].text = u["exchange"]
            row[3].text = _fmt_amount_export(u["amount"], u["currency"])
            row[4].text = _fmt_date_export(u["date"])
            row[5].text = u["address"]

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# EXPORT - PDF
# ---------------------------------------------------------------------------

def export_pdf(suspect_ids=None):
    ctx = build_report_context(suspect_ids)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter), topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=18)
    warn_style = ParagraphStyle("Warn", parent=styles["Normal"], textColor=colors.HexColor("#C03030"), fontSize=8)

    elements = [
        Paragraph("CryptoLink - Analysis Report", title_style),
        Paragraph(f"Generated: {ctx['generated_at']} | Suspects: {', '.join(ctx['suspect_names'])}", styles["Normal"]),
        Spacer(1, 16),
    ]

    def add_table(headers, rows, col_widths=None):
        data = [headers] + rows
        t = Table(data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ]))
        return t

    # --- Wallets ---
    elements.append(Paragraph("Wallets", styles["Heading1"]))
    elements.append(Paragraph(f"{len(ctx['addresses'])} distinct address(es), sorted by frequency.", styles["Normal"]))
    elements.append(Spacer(1, 6))
    wallet_rows = []
    for item in ctx["addresses"]:
        for o in item["occurrences"]:
            wallet_rows.append([
                item["address"][:40], str(item["occurrence_count"]),
                "DIFF. PEOPLE" if item["is_cross_suspect"] else ("same person" if item["is_cross_account"] else ""),
                o["suspect_name"], o["exchange"], o["file_type"],
                _fmt_amount_export(o["amount"], o["currency"]), _fmt_date_export(o["date"]), (o["txid"] or "-")[:24],
            ])
    if wallet_rows:
        elements.append(add_table(
            ["Address", "Occ.", "Shared", "Suspect", "Exchange", "Type", "Amount", "Date", "TXID"],
            wallet_rows
        ))
    elements.append(Spacer(1, 16))

    # --- Amounts ---
    elements.append(Paragraph("Amounts", styles["Heading1"]))
    elements.append(Paragraph(f"{len(ctx['amounts'])} transaction(s), sorted largest to smallest.", styles["Normal"]))
    elements.append(Spacer(1, 6))
    amount_rows = [[
        r["suspect_name"], r["exchange"], r["file_type"],
        _fmt_amount_export(r["amount"], r["currency"]), _fmt_date_export(r["date"]),
        (r["external_address"] or "-")[:30], (r["txid"] or "-")[:24],
    ] for r in ctx["amounts"]]
    if amount_rows:
        elements.append(add_table(
            ["Suspect", "Exchange", "Type", "Amount", "Date", "Address", "TXID"],
            amount_rows
        ))
    elements.append(Spacer(1, 16))

    # --- Transfers ---
    matched, unmatched = ctx["transfers"]["matched"], ctx["transfers"]["unmatched"]
    elements.append(Paragraph("Transfers", styles["Heading1"]))
    elements.append(Paragraph(
        f"{len(matched)} confirmed transfer(s) - each withdrawal matched to its single most likely "
        f"deposit (closest amount/currency, then closest time), sorted by time gap.", styles["Normal"]))
    elements.append(Spacer(1, 6))
    transfer_rows = []
    for p in matched:
        w, d = p["withdrawal"], p["deposit"]
        flags = ["TXID" if p["match_type"] == "txid" else "address"]
        flags.append("DIFF. PEOPLE" if not p["same_suspect"] else "same person")
        if not p["same_exchange"]:
            flags.append("cross-exch.")
        if not p["amount_matched"]:
            flags.append("unverified amt")
        transfer_rows.append([
            (p["address"] or "-")[:30], " / ".join(flags), str(p["gap_hours"]),
            f"{w['exchange']}/{w['suspect_name']}", _fmt_amount_export(w["amount"], w["currency"]), _fmt_date_export(w["date"]),
            f"{d['exchange']}/{d['suspect_name']}", _fmt_amount_export(d["amount"], d["currency"]), _fmt_date_export(d["date"]),
        ])
    if transfer_rows:
        elements.append(add_table(
            ["Address", "Flags", "Gap (h)", "Withdrawal from", "W. Amount", "W. Date",
             "Deposit to", "D. Amount", "D. Date"],
            transfer_rows
        ))
    elements.append(Spacer(1, 16))

    # --- Unmatched movements ---
    if unmatched:
        elements.append(Paragraph("Unmatched movements (needs manual review)", styles["Heading1"]))
        elements.append(Paragraph(
            f"{len(unmatched)} withdrawal(s)/deposit(s) couldn't be "
            f"confidently paired with a counterpart.", styles["Normal"]))
        elements.append(Spacer(1, 6))
        unmatched_rows = [[
            u["direction"], u["suspect_name"], u["exchange"],
            _fmt_amount_export(u["amount"], u["currency"]), _fmt_date_export(u["date"]), u["address"][:30],
        ] for u in unmatched]
        elements.append(add_table(
            ["Direction", "Suspect", "Exchange", "Amount", "Date", "Address"],
            unmatched_rows
        ))

    doc.build(elements)
    buf.seek(0)
    return buf


@app.route("/export/<fmt>")
def export_report(fmt):
    suspect_ids = _parse_suspect_ids()

    try:
        if fmt == "xlsx":
            buf = export_xlsx(suspect_ids)
            return send_file(buf, as_attachment=True, download_name="cryptolink_report.xlsx",
                              mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        elif fmt == "docx":
            buf = export_docx(suspect_ids)
            return send_file(buf, as_attachment=True, download_name="cryptolink_report.docx",
                              mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        elif fmt == "pdf":
            buf = export_pdf(suspect_ids)
            return send_file(buf, as_attachment=True, download_name="cryptolink_report.pdf",
                              mimetype="application/pdf")
        else:
            return jsonify({"error": "Unknown format"}), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Export failed: {str(e)}"}), 500


def compute_graph_data(suspect_ids=None):
    """Builds a node/edge graph: suspects and wallet addresses as nodes,
    transactions as edges between them (aggregated per suspect-address pair).
    Only addresses that are actually cross-account (is_cross_account) are
    included - i.e. the address links either two different suspects, or the
    same suspect across two different exchanges. A wallet only ever seen on
    one suspect's one exchange isn't a "connection" and adds noise, so it's
    excluded entirely (no toggle - this is the graph's whole purpose)."""
    addresses = compute_addresses_analysis(suspect_ids)
    nodes = {}
    edges = []

    for item in addresses:
        if not item["is_cross_account"]:
            continue

        addr_id = f"addr:{item['address']}"
        nodes[addr_id] = {
            "id": addr_id,
            "label": item["address"][:6] + "…" + item["address"][-4:] if len(item["address"]) > 12 else item["address"],
            "title": item["address"],
            # Red for a wallet shared between different people, amber when it's the same
            # person reusing a wallet across their own exchange accounts - visually distinct
            # findings, not the same alert level.
            "group": "address_shared_cross_suspect" if item["is_cross_suspect"] else "address_shared_same_suspect",
        }

        by_suspect = {}
        for o in item["occurrences"]:
            key = o["suspect_id"]
            agg = by_suspect.setdefault(key, {
                "suspect_name": o["suspect_name"], "count": 0,
                "deposits": 0, "withdrawals": 0, "total_usd": 0.0, "exchanges": set(),
            })
            agg["count"] += 1
            agg["exchanges"].add(o["exchange"])
            if o["file_type"] == "deposit":
                agg["deposits"] += 1
            else:
                agg["withdrawals"] += 1
            if o["amount_usd"]:
                agg["total_usd"] += o["amount_usd"]

        for suspect_id, agg in by_suspect.items():
            suspect_node_id = f"suspect:{suspect_id}"
            if suspect_node_id not in nodes:
                nodes[suspect_node_id] = {
                    "id": suspect_node_id, "label": agg["suspect_name"],
                    "title": agg["suspect_name"], "group": "suspect",
                }
            title = f"{agg['count']} transaction(s) ({agg['deposits']} deposit, {agg['withdrawals']} withdrawal) via {', '.join(sorted(agg['exchanges']))}"
            if agg["total_usd"]:
                title += f" — ~${agg['total_usd']:,.2f}"
            edges.append({
                "from": suspect_node_id, "to": addr_id,
                "value": agg["count"], "title": title,
            })

    # Direct suspect-to-suspect edges for TXID-confirmed transfers between two different
    # people. Needed on top of the address-sharing loop above because a TXID match can link
    # two people even when no usable shared address exists (e.g. one side's export only logs
    # an internal/exchange address, not the counterparty's - see compute_transfers_analysis).
    for p in compute_transfers_analysis(suspect_ids)["matched"]:
        if p["match_type"] != "txid" or p["same_suspect"]:
            continue
        w, d = p["withdrawal"], p["deposit"]
        for suspect_id, name in ((w["suspect_id"], w["suspect_name"]), (d["suspect_id"], d["suspect_name"])):
            node_id = f"suspect:{suspect_id}"
            if node_id not in nodes:
                nodes[node_id] = {"id": node_id, "label": name, "title": name, "group": "suspect"}
        edges.append({
            "from": f"suspect:{w['suspect_id']}", "to": f"suspect:{d['suspect_id']}",
            "value": 3, "color": {"color": "#3ecf8e"},
            "title": f"Confirmed transfer (same TXID {w['txid']}) — {w['amount']} {w['currency']} on {w['exchange']} → {d['exchange']}",
        })

    return {"nodes": list(nodes.values()), "edges": edges}


@app.route("/analysis/graph")
def analysis_graph():
    return jsonify(compute_graph_data(_parse_suspect_ids()))


@app.route("/delete/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    CATALOG.pop(file_id, None)
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CryptoLink - Exchange File Import</title>
<script>%%VIS_NETWORK_JS%%</script>
<style>
    :root {
        --bg: #0f1420; --bg-card: #171d2e; --border: #2a3348;
        --text: #e6e9f0; --text-dim: #8b93a7;
        --accent: #4f8cff; --accent-dim: #2a4a8a;
        --success: #3ecf8e; --warning: #f5a623; --danger: #f0556b;
        --radius: 10px;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 32px 20px 100px; }
    header { margin-bottom: 24px; }
    header h1 { font-size: 26px; margin: 0 0 6px; font-weight: 600; }
    header p { color: var(--text-dim); margin: 0; font-size: 14px; }

    .panel {
        background: var(--bg-card); border: 1px solid var(--border);
        border-radius: var(--radius); padding: 18px 20px; margin-bottom: 20px;
    }
    .panel-title { font-size: 13px; color: var(--text-dim); margin-bottom: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; }

    .suspect-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    select, input[type="text"] {
        background: #101625; color: var(--text); border: 1px solid var(--border);
        border-radius: 6px; padding: 9px 12px; font-size: 14px;
    }
    select:focus, input[type="text"]:focus { outline: none; border-color: var(--accent); }
    #activeSuspectSelect { min-width: 220px; }
    .search-row { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
    #analysisSearch { width: 100%; max-width: 420px; font-family: "SF Mono", Consolas, monospace; }
    .search-match-note { font-size: 12px; color: var(--text-dim); margin-left: 2px; }
    mark.search-hit { background: rgba(245,166,35,0.35); color: inherit; border-radius: 2px; padding: 0 1px; }

    .btn {
        background: var(--accent-dim); color: var(--text); border: none;
        padding: 9px 16px; border-radius: 6px; cursor: pointer; font-size: 13.5px;
    }
    .btn:hover { background: var(--accent); }
    .btn.small { padding: 6px 12px; font-size: 12.5px; }
    .btn.danger { background: rgba(240,85,107,0.15); color: var(--danger); }
    .btn.danger:hover { background: rgba(240,85,107,0.3); }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }

    .dropzone {
        border: 2px dashed var(--border); border-radius: var(--radius);
        padding: 40px 24px; text-align: center; cursor: pointer;
        transition: all 0.15s ease; background: var(--bg-card);
    }
    .dropzone:hover, .dropzone.dragover { border-color: var(--accent); background: #1a2236; }
    .dropzone.disabled { opacity: 0.5; cursor: not-allowed; }
    .dropzone .icon { font-size: 30px; margin-bottom: 8px; }
    .dropzone .main-text { font-size: 14.5px; font-weight: 500; }
    .dropzone .sub-text { font-size: 12.5px; color: var(--text-dim); margin-top: 4px; }
    input[type="file"] { display: none; }

    .toast {
        position: fixed; bottom: 24px; right: 24px; background: var(--success);
        color: #0a1f16; padding: 13px 20px; border-radius: 8px; font-size: 13.5px;
        font-weight: 600; box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        transform: translateY(20px); opacity: 0; transition: all 0.25s ease;
        z-index: 200; max-width: 380px;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.warn { background: var(--warning); }

    .suspect-block { margin-top: 22px; }
    .suspect-header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 12px 4px; cursor: pointer;
    }
    .suspect-header h2 { font-size: 16px; margin: 0; display: flex; align-items: center; gap: 10px; }
    .suspect-header .name-text { unicode-bidi: isolate; }
    .suspect-header .count-badge {
        background: var(--accent-dim); color: var(--text); font-size: 11.5px;
        padding: 2px 9px; border-radius: 20px; font-weight: 600;
    }
    .suspect-header .chevron { transition: transform 0.15s ease; color: var(--text-dim); }
    .suspect-header .chevron.collapsed { transform: rotate(-90deg); }

    .table-wrap { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
    thead th { text-align: left; padding: 11px 14px; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border); white-space: nowrap; }
    tbody td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr:hover { background: #1c2438; }
    tbody tr.highlight { animation: flashHighlight 1.8s ease; }
    @keyframes flashHighlight { 0% { background: rgba(62,207,142,0.25); } 100% { background: transparent; } }

    /* Isolate bidirectional text (e.g. Hebrew filenames) so it never scrambles
       neighboring Latin text (sheet names, dashes, etc.) */
    .bidi-safe { unicode-bidi: isolate; direction: auto; display: inline-block; }

    select.unknown { border-color: var(--warning); }
    .badge { display: inline-block; padding: 3px 9px; border-radius: 20px; font-size: 11.5px; font-weight: 600; }
    .badge.deposit { background: rgba(62,207,142,0.15); color: var(--success); }
    .badge.withdrawal { background: rgba(240,85,107,0.15); color: var(--danger); }

    .empty-state { text-align: center; padding: 40px; color: var(--text-dim); font-size: 14px; }

    .modal-overlay {
        display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.6); z-index: 100; align-items: center; justify-content: center;
    }
    .modal-overlay.active { display: flex; }
    .modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); width: 90%; max-width: 900px; max-height: 80vh; display: flex; flex-direction: column; }
    .modal-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .modal-header h3 { margin: 0; font-size: 15px; unicode-bidi: isolate; overflow: hidden; text-overflow: ellipsis; }
    .modal-close { cursor: pointer; color: var(--text-dim); font-size: 20px; background: none; border: none; flex-shrink: 0; }
    .modal-body { padding: 12px 20px; overflow: auto; }
    .modal-body table { font-size: 12px; }
    .modal-body th { position: sticky; top: 0; background: var(--bg-card); }
    .modal-body td, .modal-body th { unicode-bidi: isolate; }
    .modal-error { color: var(--danger); font-size: 13.5px; padding: 10px 0; }

    @media (max-width: 700px) {
        .table-wrap { overflow-x: auto; }
        table { min-width: 650px; }
        .suspect-row { flex-direction: column; align-items: stretch; }
        #activeSuspectSelect { min-width: 0; }
    }

    .main-tabs, .sub-tabs {
        display: flex; gap: 6px; margin-bottom: 20px; border-bottom: 1px solid var(--border);
        padding-bottom: 0;
    }
    .sub-tabs { margin-bottom: 16px; }
    .tab-btn {
        background: none; border: none; color: var(--text-dim); font-size: 14px;
        padding: 10px 16px; cursor: pointer; border-bottom: 2px solid transparent;
        margin-bottom: -1px;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
    .sub-tabs .tab-btn { font-size: 13px; padding: 8px 12px; }

    .analysis-loading { text-align: center; padding: 40px; color: var(--text-dim); font-size: 14px; }
    .analysis-empty { text-align: center; padding: 40px; color: var(--text-dim); font-size: 14px; }

    .cross-badge {
        display: inline-block; padding: 3px 9px; border-radius: 20px; font-size: 11px;
        font-weight: 700; background: rgba(240,85,107,0.18); color: var(--danger); margin-left: 8px;
    }
    .diff-suspect-badge {
        display: inline-block; padding: 3px 9px; border-radius: 20px; font-size: 11px;
        font-weight: 700; background: rgba(245,166,35,0.18); color: var(--warning);
    }
    .same-person-badge {
        display: inline-block; padding: 3px 9px; border-radius: 20px; font-size: 11px;
        font-weight: 700; background: rgba(79,140,255,0.18); color: var(--accent); margin-left: 8px;
    }
    .unverified-badge {
        display: inline-block; padding: 3px 9px; border-radius: 20px; font-size: 11px;
        font-weight: 700; background: rgba(245,166,35,0.18); color: var(--warning); margin-left: 8px;
    }

    .addr-row { cursor: pointer; }
    .addr-detail-row td { background: #10141f; padding: 0; }
    .addr-detail-wrap { padding: 10px 30px; }
    .addr-detail-wrap table { font-size: 12.5px; }
    .addr-mono { font-family: "SF Mono", Consolas, monospace; font-size: 12.5px; unicode-bidi: isolate; }

    .transfer-card {
        background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius);
        padding: 16px; margin-bottom: 12px;
    }
    .transfer-card .addr-line { font-size: 12px; color: var(--text-dim); margin-bottom: 10px; }
    .transfer-flow { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
    .transfer-side { flex: 1; min-width: 200px; }
    .transfer-side .label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-bottom: 4px; }
    .transfer-side .exchange-name { font-weight: 700; text-transform: capitalize; }
    .transfer-side .amount { font-size: 15px; font-weight: 600; margin-top: 2px; }
    .transfer-side .txid-line { font-size: 11.5px; color: var(--text-dim); margin-top: 8px; word-break: break-all; }
    .transfer-arrow { color: var(--accent); font-size: 20px; }
    .transfer-gap { font-size: 11.5px; color: var(--text-dim); margin-top: 10px; }

    .results-note { font-size: 12.5px; color: var(--text-dim); margin-bottom: 12px; }

    .export-row { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    .export-label { font-size: 12.5px; color: var(--text-dim); margin-right: 4px; }
    a.btn { text-decoration: none; display: inline-block; }

    .field-warning {
        display: inline-block; margin-left: 8px; font-size: 11px; font-weight: 600;
        color: var(--warning); cursor: help; border-bottom: 1px dotted var(--warning);
    }

    .export-panel { margin-bottom: 16px; }
    .suspect-filter-panel {
        background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius);
        padding: 12px 14px; margin-top: 8px; max-width: 420px;
    }
    .suspect-filter-actions { display: flex; gap: 8px; margin-bottom: 10px; }
    .suspect-filter-list { display: flex; flex-direction: column; gap: 6px; max-height: 200px; overflow-y: auto; }
    .suspect-filter-item { display: flex; align-items: center; gap: 8px; font-size: 13px; }
    .suspect-filter-item input { cursor: pointer; }

    .graph-controls {
        display: flex; justify-content: space-between; align-items: center;
        margin-bottom: 12px; flex-wrap: wrap; gap: 10px;
    }
    .graph-toggle { font-size: 12.5px; color: var(--text-dim); display: flex; align-items: center; gap: 6px; cursor: pointer; }
    .graph-legend { display: flex; gap: 14px; flex-wrap: wrap; }
    .legend-item { font-size: 11.5px; color: var(--text-dim); display: flex; align-items: center; gap: 5px; }
    .legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
    #graphCanvas {
        width: 100%; height: 560px; background: var(--bg-card); border: 1px solid var(--border);
        border-radius: var(--radius);
    }
    .graph-canvas-wrap { position: relative; }
    .node-toolbar {
        position: absolute; display: none; gap: 4px; background: var(--bg-card);
        border: 1px solid var(--border); border-radius: 6px; padding: 4px;
        box-shadow: 0 6px 18px rgba(0,0,0,0.35); z-index: 10;
    }

    .analysis-layout { display: flex; gap: 20px; align-items: flex-start; }
    .analysis-main { flex: 1; min-width: 0; }
    .hidden-wallets-sidebar {
        flex: 0 0 260px; background: var(--bg-card); border: 1px solid var(--border);
        border-radius: var(--radius); padding: 14px; position: sticky; top: 20px;
    }
    .hidden-wallets-sidebar h3 { font-size: 12.5px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.03em; margin: 0 0 10px; }
    .hidden-wallet-item { border-bottom: 1px solid var(--border); padding: 10px 0; }
    .hidden-wallet-item:last-child { border-bottom: none; padding-bottom: 0; }
    .hidden-wallet-addr { display: flex; align-items: center; gap: 6px; }
    .hidden-wallet-meta { font-size: 11.5px; color: var(--text-dim); margin: 4px 0 8px; }
    @media (max-width: 900px) {
        .analysis-layout { flex-direction: column; }
        .hidden-wallets-sidebar { flex: none; width: 100%; position: static; }
    }

    .row-actions { display: inline-flex; gap: 2px; margin-left: 8px; opacity: 0; transition: opacity 0.12s ease; vertical-align: middle; }
    tr:hover .row-actions, .hidden-wallet-item:hover .row-actions, .hidden-wallet-addr:hover .row-actions { opacity: 1; }
    .icon-btn {
        background: none; border: none; cursor: pointer; color: var(--text-dim); font-size: 13px;
        padding: 3px 5px; border-radius: 4px; line-height: 1;
    }
    .icon-btn:hover { color: var(--text); background: #1c2438; }
    .icon-btn.danger:hover { color: var(--danger); background: rgba(240,85,107,0.12); }
</style>
</head>
<body>

<div class="container">
    <header>
        <h1>CryptoLink</h1>
        <p>Import Excel files received from exchanges. Only Deposit/Withdrawal sheets are kept.</p>
    </header>

    <div class="main-tabs">
        <button class="tab-btn active" id="tabBtnFiles" onclick="switchMainTab('files')">Files</button>
        <button class="tab-btn" id="tabBtnAnalysis" onclick="switchMainTab('analysis')">Analysis</button>
    </div>

    <div id="filesView">
        <div class="panel">
            <div class="panel-title">Active suspect</div>
            <div class="suspect-row">
                <select id="activeSuspectSelect" onchange="onSuspectChange()">
                    <option value="">-- No suspect selected --</option>
                </select>
                <input type="text" id="newSuspectName" placeholder="New suspect name">
                <button class="btn" onclick="addSuspect()">+ Add suspect</button>
                <button class="btn danger" id="deleteSuspectBtn" onclick="removeSuspect()" disabled>Delete this suspect</button>
            </div>
        </div>

        <div class="dropzone disabled" id="dropzone">
            <div class="icon">📁</div>
            <div class="main-text" id="dropzoneText">Select an active suspect above first</div>
            <div class="sub-text">.xlsx / .xls - only Deposit/Withdrawal sheets will be imported</div>
            <input type="file" id="fileInput" multiple accept=".xlsx,.xls">
        </div>

        <div id="suspectBlocks"></div>

        <div class="empty-state" id="emptyState">No files imported yet.</div>
    </div>

    <div id="analysisView" style="display:none;">
        <div class="export-panel">
            <div class="export-row">
                <span class="export-label">Export report:</span>
                <button class="btn small" onclick="triggerExport('docx')">Word (.docx)</button>
                <button class="btn small" onclick="triggerExport('xlsx')">Excel (.xlsx)</button>
                <button class="btn small" onclick="triggerExport('pdf')">PDF</button>
                <button class="btn small" id="suspectFilterToggleBtn" onclick="toggleSuspectFilterPanel()">Filter suspects ▾</button>
            </div>
            <div id="suspectFilterPanel" class="suspect-filter-panel" style="display:none;">
                <div class="suspect-filter-actions">
                    <button class="btn small" onclick="setAllSuspectFilter(true)">Select all</button>
                    <button class="btn small" onclick="setAllSuspectFilter(false)">Select none</button>
                </div>
                <div id="suspectFilterList" class="suspect-filter-list"></div>
            </div>
        </div>
        <div class="analysis-layout">
            <div class="analysis-main">
                <div class="search-row">
                    <input type="text" id="analysisSearch" placeholder="Search by wallet address or TXID..." oninput="onAnalysisSearch(this.value)">
                    <button class="btn small" id="analysisSearchClear" onclick="clearAnalysisSearch()" style="display:none;">Clear</button>
                </div>
                <div class="sub-tabs">
                    <button class="tab-btn active" id="subTabAddresses" onclick="switchAnalysisTab('addresses')">Wallets</button>
                    <button class="tab-btn" id="subTabAmounts" onclick="switchAnalysisTab('amounts')">Amounts</button>
                    <button class="tab-btn" id="subTabTransfers" onclick="switchAnalysisTab('transfers')">Transfers</button>
                    <button class="tab-btn" id="subTabGraph" onclick="switchAnalysisTab('graph')">Graph</button>
                </div>
                <div id="analysisContent"></div>
            </div>
            <aside id="hiddenWalletsSidebar" class="hidden-wallets-sidebar" style="display:none;"></aside>
        </div>
    </div>
</div>

<div class="modal-overlay" id="modalOverlay">
    <div class="modal">
        <div class="modal-header">
            <h3 id="modalTitle">Preview</h3>
            <button class="modal-close" onclick="closeModal()">&times;</button>
        </div>
        <div class="modal-body" id="modalBody"></div>
    </div>
</div>

<div class="toast" id="toast"></div>

<script>
const EXCHANGES = ["binance", "okx", "bybit", "redotpay", "matrix", "unknown"];
const TYPE_LABELS = {"deposit": "Deposit", "withdrawal": "Withdrawal"};

let suspects = {};       // id -> name
let catalogData = {};    // file id -> entry
let activeSuspectId = "";
let collapsedSuspects = {};

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");

function refreshSuspects() {
    fetch("/suspects").then(r => r.json()).then(list => {
        suspects = {};
        list.forEach(s => suspects[s.id] = s.name);
        const sel = document.getElementById("activeSuspectSelect");
        sel.innerHTML = '<option value="">-- No suspect selected --</option>';
        list.forEach(s => {
            const opt = document.createElement("option");
            opt.value = s.id; opt.innerText = s.name;
            if (s.id === activeSuspectId) opt.selected = true;
            sel.appendChild(opt);
        });
        renderAll();
        syncSuspectFilterWithSuspects();
    });
}

function addSuspect() {
    const input = document.getElementById("newSuspectName");
    const name = input.value.trim();
    if (!name) { input.focus(); return; }
    fetch("/suspects", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name })
    }).then(r => r.json()).then(data => {
        if (data.error) { showToast(data.error, true); return; }
        input.value = "";
        activeSuspectId = data.id;
        refreshSuspects();
        updateDropzoneState();
        showToast("Suspect '" + name + "' created and selected", false);
    });
}

function removeSuspect() {
    if (!activeSuspectId) return;
    const name = suspects[activeSuspectId];
    if (!confirm("Delete '" + name + "' and all imported files?")) return;
    fetch("/suspects/" + activeSuspectId, { method: "DELETE" }).then(() => {
        Object.keys(catalogData).forEach(fid => {
            if (catalogData[fid].suspect_id === activeSuspectId) delete catalogData[fid];
        });
        activeSuspectId = "";
        refreshSuspects();
        updateDropzoneState();
    });
}

function onSuspectChange() {
    activeSuspectId = document.getElementById("activeSuspectSelect").value;
    updateDropzoneState();
}

function updateDropzoneState() {
    const hasActive = !!activeSuspectId;
    dropzone.classList.toggle("disabled", !hasActive);
    document.getElementById("deleteSuspectBtn").disabled = !hasActive;
    document.getElementById("dropzoneText").innerText = hasActive
        ? "Drag " + suspects[activeSuspectId] + "'s files here, or click to browse"
        : "Select an active suspect above first";
}

dropzone.addEventListener("click", () => { if (activeSuspectId) fileInput.click(); });
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); if (activeSuspectId) dropzone.classList.add("dragover"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (activeSuspectId) handleFiles(e.dataTransfer.files);
});
fileInput.addEventListener("change", (e) => handleFiles(e.target.files));

function handleFiles(fileList) {
    if (!fileList.length || !activeSuspectId) return;
    const formData = new FormData();
    for (const f of fileList) formData.append("files", f);
    formData.append("suspect_id", activeSuspectId);

    const originalText = document.getElementById("dropzoneText").innerText;
    document.getElementById("dropzoneText").innerText = "Importing...";

    fetch("/upload", { method: "POST", body: formData })
        .then(r => r.json())
        .then(data => {
            document.getElementById("dropzoneText").innerText = originalText;
            if (data.error) { showToast(data.error, true); return; }

            const newIds = [];
            const errors = [];
            data.results.forEach(item => {
                if (item.error) { errors.push((item.filename || "file") + ": " + item.error); return; }
                catalogData[item.id] = item;
                newIds.push(item.id);
            });

            renderAll(newIds);

            if (errors.length) {
                showToast("Error: " + errors.join(" / "), true);
            } else if (newIds.length === 0) {
                showToast("No Deposit/Withdrawal sheet detected in this file(s)" +
                    (data.ignored_count ? " (" + data.ignored_count + " tab(s) ignored)" : ""), true);
            } else {
                let msg = "✓ " + newIds.length + " sheet(s) added to " + suspects[activeSuspectId];
                if (data.ignored_count) msg += " (" + data.ignored_count + " other tab(s) ignored)";
                showToast(msg, false);
            }
        })
        .catch(err => {
            document.getElementById("dropzoneText").innerText = originalText;
            showToast("Network error during import: " + err, true);
        });
    fileInput.value = "";
}

function showToast(msg, isWarn) {
    const t = document.getElementById("toast");
    t.innerText = msg;
    t.classList.toggle("warn", !!isWarn);
    t.classList.add("show");
    clearTimeout(window._toastTimer);
    window._toastTimer = setTimeout(() => t.classList.remove("show"), 4200);
}

function renderAll(highlightIds) {
    highlightIds = highlightIds || [];
    const container = document.getElementById("suspectBlocks");
    container.innerHTML = "";

    const bySuspect = {};
    Object.keys(catalogData).forEach(id => {
        const item = catalogData[id];
        if (!bySuspect[item.suspect_id]) bySuspect[item.suspect_id] = [];
        bySuspect[item.suspect_id].push(id);
    });

    const suspectIds = Object.keys(bySuspect);
    document.getElementById("emptyState").style.display = suspectIds.length ? "none" : "block";

    suspectIds.forEach(sid => {
        const suspectName = suspects[sid] || "Deleted suspect";
        const ids = bySuspect[sid];
        const exchangeCount = new Set(ids.map(id => catalogData[id].exchange)).size;

        const block = document.createElement("div");
        block.className = "suspect-block";

        const collapsed = !!collapsedSuspects[sid];

        block.innerHTML = `
            <div class="suspect-header" onclick="toggleSuspect('${sid}')">
                <h2><span class="chevron ${collapsed ? 'collapsed' : ''}">▾</span> <span class="name-text">${escapeHtml(suspectName)}</span>
                    <span class="count-badge">${ids.length} sheet(s) - ${exchangeCount} exchange(s)</span>
                </h2>
            </div>
            <div class="table-wrap" style="${collapsed ? 'display:none;' : ''}" id="tw-${sid}">
                <table>
                    <thead>
                        <tr>
                            <th>File</th><th>Sheet</th><th>Exchange</th><th>Type</th><th>Rows</th><th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="tbody-${sid}"></tbody>
                </table>
            </div>
        `;
        container.appendChild(block);

        const tbody = block.querySelector("#tbody-" + sid);
        ids.forEach(id => {
            const item = catalogData[id];
            const tr = document.createElement("tr");
            if (highlightIds.includes(id)) tr.className = "highlight";
            const missing = item.missing_fields || [];
            const missingWarning = missing.length
                ? `<span class="field-warning" title="Columns not found in this file: ${escapeHtml(missing.join(', '))}. Those fields will be blank for every row - analysis relying on them (e.g. address matching) may miss data here.">⚠ ${missing.length} field(s) not mapped</span>`
                : "";
            tr.innerHTML = `
                <td><span class="bidi-safe">${escapeHtml(item.filename)}</span></td>
                <td><span class="bidi-safe">${escapeHtml(item.sheet_name)}</span></td>
                <td>${buildExchangeSelect(id, item.exchange)}</td>
                <td><span class="badge ${item.file_type}">${TYPE_LABELS[item.file_type]}</span></td>
                <td>${item.row_count}${missingWarning}</td>
                <td>
                    <button class="btn small" onclick="showPreview('${id}')">Preview</button>
                    <button class="btn small danger" onclick="deleteFile('${id}')">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    });
}

function toggleSuspect(sid) {
    collapsedSuspects[sid] = !collapsedSuspects[sid];
    renderAll();
}

function buildExchangeSelect(id, current) {
    const cls = current === "unknown" ? "unknown" : "";
    let html = `<select class="${cls}" onclick="event.stopPropagation()" onchange="updateLabel('${id}', 'exchange', this.value, this)">`;
    EXCHANGES.forEach(opt => {
        const label = opt.charAt(0).toUpperCase() + opt.slice(1);
        html += `<option value="${opt}" ${opt === current ? "selected" : ""}>${label}</option>`;
    });
    html += `</select>`;
    return html;
}

function updateLabel(id, field, value, selectEl) {
    fetch("/update_label", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, field, value })
    }).then(r => r.json()).then(() => {
        catalogData[id][field] = value;
        selectEl.classList.toggle("unknown", value === "unknown");
    });
}

function deleteFile(id) {
    fetch("/delete/" + id, { method: "DELETE" }).then(() => {
        delete catalogData[id];
        renderAll();
    });
}

function showPreview(id) {
    document.getElementById("modalTitle").innerText = "Loading...";
    document.getElementById("modalBody").innerHTML = "";
    document.getElementById("modalOverlay").classList.add("active");

    fetch("/preview/" + id)
        .then(r => r.json().then(data => ({ ok: r.ok, data })))
        .then(({ ok, data }) => {
            if (!ok || data.error) {
                document.getElementById("modalTitle").innerText = "Preview error";
                document.getElementById("modalBody").innerHTML =
                    `<div class="modal-error">${escapeHtml(data.error || "Unknown error")}</div>`;
                return;
            }
            document.getElementById("modalTitle").innerHTML =
                `<span class="bidi-safe">${escapeHtml(data.filename)}</span> - <span class="bidi-safe">${escapeHtml(data.sheet_name)}</span>`;
            let html = "<table><thead><tr>";
            data.columns.forEach(c => html += `<th>${escapeHtml(c)}</th>`);
            html += "</tr></thead><tbody>";
            data.rows.forEach(row => {
                html += "<tr>";
                data.columns.forEach(c => html += `<td>${escapeHtml(String(row[c] ?? ""))}</td>`);
                html += "</tr>";
            });
            html += "</tbody></table>";
            document.getElementById("modalBody").innerHTML = html;
        })
        .catch(err => {
            document.getElementById("modalTitle").innerText = "Preview error";
            document.getElementById("modalBody").innerHTML =
                `<div class="modal-error">Network/parsing error: ${escapeHtml(String(err))}</div>`;
        });
}

function closeModal() { document.getElementById("modalOverlay").classList.remove("active"); }

function escapeHtml(str) {
    const div = document.createElement("div");
    div.innerText = str;
    return div.innerHTML;
}

// ---------------------------------------------------------------------------
// ANALYSIS TAB
// ---------------------------------------------------------------------------

let currentMainTab = "files";
let currentAnalysisTab = "addresses";

function switchMainTab(tab) {
    currentMainTab = tab;
    document.getElementById("filesView").style.display = tab === "files" ? "block" : "none";
    document.getElementById("analysisView").style.display = tab === "analysis" ? "block" : "none";
    document.getElementById("tabBtnFiles").classList.toggle("active", tab === "files");
    document.getElementById("tabBtnAnalysis").classList.toggle("active", tab === "analysis");
    if (tab === "analysis") { loadAnalysisTab(currentAnalysisTab); refreshHiddenWalletsSidebar(); }
}

function switchAnalysisTab(tab) {
    currentAnalysisTab = tab;
    document.getElementById("subTabAddresses").classList.toggle("active", tab === "addresses");
    document.getElementById("subTabAmounts").classList.toggle("active", tab === "amounts");
    document.getElementById("subTabTransfers").classList.toggle("active", tab === "transfers");
    document.getElementById("subTabGraph").classList.toggle("active", tab === "graph");
    loadAnalysisTab(tab);
}

function loadAnalysisTab(tab) {
    const container = document.getElementById("analysisContent");
    container.innerHTML = '<div class="analysis-loading">Loading...</div>';
    if (tab === "addresses") loadAddresses(container);
    else if (tab === "amounts") loadAmounts(container);
    else if (tab === "transfers") loadTransfers(container);
    else if (tab === "graph") loadGraph(container);
}

function fmtAmount(amount, currency) {
    if (amount === null || amount === undefined) return "-";
    return amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + (currency ? " " + currency : "");
}
function fmtUsd(amountUsd) {
    if (amountUsd === null || amountUsd === undefined) return "";
    return "≈ $" + amountUsd.toLocaleString(undefined, { maximumFractionDigits: 2 });
}
function fmtDate(iso) {
    if (!iso) return "-";
    return new Date(iso).toLocaleString();
}

function truncMono(value, keepStart, keepEnd) {
    keepStart = keepStart || 8;
    keepEnd = keepEnd || 6;
    if (!value) return `<span class="addr-mono">-</span>`;
    const v = String(value);
    // Show the full value (highlighted) instead of truncating when it's what matched the
    // active search - truncation would otherwise hide the very match the user searched for.
    if (analysisSearchQuery && matchesSearch(v)) {
        return `<span class="addr-mono">${highlightMatch(v)}</span>`;
    }
    if (v.length <= keepStart + keepEnd + 3) {
        return `<span class="addr-mono">${escapeHtml(v)}</span>`;
    }
    const shortened = v.slice(0, keepStart) + "…" + v.slice(-keepEnd);
    return `<span class="addr-mono" title="${escapeHtml(v)}">${escapeHtml(shortened)}</span>`;
}

function loadAddresses(container) {
    fetch("/analysis/addresses" + suspectsQueryParam()).then(r => r.json()).then(data => {
        cachedAddresses = data;
        renderAddresses(container);
    }).catch(err => {
        container.innerHTML = `<div class="analysis-empty">Error loading data: ${escapeHtml(String(err))}</div>`;
    });
}

function renderAddresses(container) {
    const data = cachedAddresses || [];
    if (!data.length) {
        container.innerHTML = '<div class="analysis-empty">No addresses found yet - import some files first.</div>';
        return;
    }
    // An address matches if its own text matches, or any of its occurrences' TXID does -
    // the search field covers both wallet addresses and TXIDs per the same box.
    const filtered = data.filter(item =>
        matchesSearch(item.address) || item.occurrences.some(o => matchesSearch(o.txid))
    );
    if (!filtered.length) {
        container.innerHTML = `<div class="analysis-empty">No address or TXID matches "${escapeHtml(analysisSearchQuery)}".</div>`;
        return;
    }
    let html = `<div class="results-note">${filtered.length} of ${data.length} distinct address(es) shown, sorted by frequency. Click a row to see all occurrences. Hover an address for actions - wallets that aren't relevant to your case can be hidden from Wallets, Transfers and the Graph.</div>`;
    html += '<div class="table-wrap"><table><thead><tr><th>Address</th><th>Occurrences</th><th>Distinct accounts</th><th></th></tr></thead><tbody>';
    filtered.forEach((item, idx) => {
        html += `<tr class="addr-row" onclick="toggleAddrDetail(${idx})">
            <td>${addressCellHtml(item.address)}</td>
            <td>${item.occurrence_count}</td>
            <td>${item.distinct_accounts}</td>
            <td>${item.is_cross_suspect ? '<span class="cross-badge">DIFFERENT PEOPLE</span>' : (item.is_cross_account ? '<span class="same-person-badge">SAME PERSON · MULTIPLE EXCHANGES</span>' : "")}</td>
        </tr>
        <tr class="addr-detail-row" id="addrDetail${idx}" style="display:${analysisSearchQuery ? 'table-row' : 'none'};">
            <td colspan="4">
                <div class="addr-detail-wrap">
                    <table><thead><tr><th>Suspect</th><th>Exchange</th><th>Type</th><th>Amount</th><th>Date</th><th>TXID</th></tr></thead><tbody>
                    ${item.occurrences.map(o => `<tr>
                        <td>${escapeHtml(o.suspect_name)}</td>
                        <td>${escapeHtml(o.exchange)}</td>
                        <td><span class="badge ${o.file_type}">${TYPE_LABELS[o.file_type] || o.file_type}</span></td>
                        <td>${fmtAmount(o.amount, o.currency)}${o.amount_usd ? ' <span style="color:var(--text-dim);font-size:11px;">(' + fmtUsd(o.amount_usd) + ')</span>' : ""}</td>
                        <td>${fmtDate(o.date)}</td>
                        <td class="addr-mono">${highlightMatch(o.txid || "-")}</td>
                    </tr>`).join("")}
                    </tbody></table>
                </div>
            </td>
        </tr>`;
    });
    html += "</tbody></table></div>";
    container.innerHTML = html;
}

function toggleAddrDetail(idx) {
    const row = document.getElementById("addrDetail" + idx);
    row.style.display = row.style.display === "none" ? "table-row" : "none";
}

// Address cell with copy/hide icons that only appear on hover (see .row-actions CSS).
// Used anywhere a wallet address is listed. Pass includeHide=false where the wallet is
// already hidden (the sidebar) - a "hide" action there would be redundant with Restore.
function addressCellHtml(address, includeHide) {
    if (includeHide === undefined) includeHide = true;
    const esc = escapeHtml(address).replace(/'/g, "\\'");
    return `<span class="addr-mono">${highlightMatch(address)}</span>
        <span class="row-actions">
            <button class="icon-btn" title="Copy address" onclick="event.stopPropagation(); copyAddress('${esc}')">📋</button>
            ${includeHide ? `<button class="icon-btn danger" title="Hide this wallet" onclick="event.stopPropagation(); hideWallet('${esc}')">🗑️</button>` : ""}
        </span>`;
}

// Search box shared by Wallets/Amounts/Transfers (Graph handles it separately by
// highlighting/focusing a matching node instead of filtering a list).
let analysisSearchQuery = "";
let cachedAddresses = null, cachedAmounts = null, cachedTransfers = null;

function matchesSearch(text) {
    if (!analysisSearchQuery) return true;
    return (text || "").toLowerCase().includes(analysisSearchQuery);
}

function highlightMatch(text) {
    const safe = escapeHtml(text == null ? "" : String(text));
    if (!analysisSearchQuery) return safe;
    const idx = safe.toLowerCase().indexOf(escapeHtml(analysisSearchQuery).toLowerCase());
    if (idx === -1) return safe;
    return safe.slice(0, idx) + '<mark class="search-hit">' + safe.slice(idx, idx + analysisSearchQuery.length) + "</mark>" + safe.slice(idx + analysisSearchQuery.length);
}

function onAnalysisSearch(value) {
    analysisSearchQuery = value.trim().toLowerCase();
    document.getElementById("analysisSearchClear").style.display = analysisSearchQuery ? "inline-block" : "none";
    reapplyAnalysisSearch();
}

function clearAnalysisSearch() {
    document.getElementById("analysisSearch").value = "";
    onAnalysisSearch("");
}

// Re-renders the current tab from already-fetched data (no network round-trip per
// keystroke). Falls back to a full load if nothing's cached yet for that tab.
function reapplyAnalysisSearch() {
    const container = document.getElementById("analysisContent");
    if (currentAnalysisTab === "addresses") { if (cachedAddresses) renderAddresses(container); else loadAddresses(container); }
    else if (currentAnalysisTab === "amounts") { if (cachedAmounts) renderAmounts(container); else loadAmounts(container); }
    else if (currentAnalysisTab === "transfers") { if (cachedTransfers) renderTransfers(container); else loadTransfers(container); }
    else if (currentAnalysisTab === "graph") focusGraphSearchMatch();
}

function copyAddress(address) {
    navigator.clipboard.writeText(address).then(
        () => showToast("Address copied", false),
        () => showToast("Couldn't copy address", true)
    );
}

function hideWallet(address) {
    fetch("/addresses/exclude", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address })
    }).then(() => {
        showToast("Wallet hidden - restore it anytime from the sidebar", false);
        loadAnalysisTab(currentAnalysisTab);
        refreshHiddenWalletsSidebar();
    });
}

function restoreWallet(address) {
    fetch("/addresses/include", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address })
    }).then(() => {
        loadAnalysisTab(currentAnalysisTab);
        refreshHiddenWalletsSidebar();
    });
}

function refreshHiddenWalletsSidebar() {
    const sidebar = document.getElementById("hiddenWalletsSidebar");
    fetch("/addresses/excluded").then(r => r.json()).then(list => {
        if (!list.length) { sidebar.style.display = "none"; sidebar.innerHTML = ""; return; }
        sidebar.style.display = "block";
        sidebar.innerHTML = `<h3>Hidden wallets (${list.length})</h3>` + list.map(item => `
            <div class="hidden-wallet-item">
                <div class="hidden-wallet-addr">${addressCellHtml(item.address, false)}</div>
                <div class="hidden-wallet-meta">${item.occurrence_count} occurrence(s)${item.suspect_names.length ? " · " + escapeHtml(item.suspect_names.join(", ")) : ""}</div>
                <button class="btn small" onclick="restoreWallet('${escapeHtml(item.address).replace(/'/g, "\\'")}')">Restore</button>
            </div>
        `).join("");
    }).catch(() => {});
}

function loadAmounts(container) {
    fetch("/analysis/amounts" + suspectsQueryParam()).then(r => r.json()).then(data => {
        cachedAmounts = data;
        renderAmounts(container);
    }).catch(err => {
        container.innerHTML = `<div class="analysis-empty">Error loading data: ${escapeHtml(String(err))}</div>`;
    });
}

function renderAmounts(container) {
    const data = cachedAmounts || [];
    if (!data.length) {
        container.innerHTML = '<div class="analysis-empty">No transactions found yet - import some files first.</div>';
        return;
    }
    const filtered = data.filter(r => matchesSearch(r.external_address) || matchesSearch(r.txid));
    if (!filtered.length) {
        container.innerHTML = `<div class="analysis-empty">No address or TXID matches "${escapeHtml(analysisSearchQuery)}".</div>`;
        return;
    }
    let html = `<div class="results-note">${filtered.length} of ${data.length} transaction(s) shown, sorted largest to smallest (USD-equivalent first when available).</div>`;
    html += '<div class="table-wrap"><table><thead><tr><th>Suspect</th><th>Exchange</th><th>Type</th><th>Amount</th><th>Date</th><th>Address</th><th>TXID</th></tr></thead><tbody>';
    filtered.forEach(r => {
        html += `<tr>
            <td>${escapeHtml(r.suspect_name)}</td>
            <td>${escapeHtml(r.exchange)}</td>
            <td><span class="badge ${r.file_type}">${TYPE_LABELS[r.file_type] || r.file_type}</span></td>
            <td>${fmtAmount(r.amount, r.currency)}${r.amount_usd ? ' <span style="color:var(--text-dim);font-size:11.5px;">(' + fmtUsd(r.amount_usd) + ')</span>' : ""}</td>
            <td>${fmtDate(r.date)}</td>
            <td>${truncMono(r.external_address)}</td>
            <td>${truncMono(r.txid)}</td>
        </tr>`;
    });
    html += "</tbody></table></div>";
    container.innerHTML = html;
}

function loadTransfers(container) {
    fetch("/analysis/transfers" + suspectsQueryParam()).then(r => r.json()).then(data => {
        cachedTransfers = data;
        renderTransfers(container);
    }).catch(err => {
        container.innerHTML = `<div class="analysis-empty">Error loading data: ${escapeHtml(String(err))}</div>`;
    });
}

function renderTransfers(container) {
    const allMatched = (cachedTransfers && cachedTransfers.matched) || [];
    const allUnmatched = (cachedTransfers && cachedTransfers.unmatched) || [];
    if (!allMatched.length && !allUnmatched.length) {
        container.innerHTML = '<div class="analysis-empty">No wallet-to-wallet transfers detected yet.</div>';
        return;
    }

    const matched = allMatched.filter(p => matchesSearch(p.address) || matchesSearch(p.withdrawal.txid) || matchesSearch(p.deposit.txid));
    const unmatched = allUnmatched.filter(u => matchesSearch(u.address) || matchesSearch(u.txid));
    if (!matched.length && !unmatched.length) {
        container.innerHTML = `<div class="analysis-empty">No address or TXID matches "${escapeHtml(analysisSearchQuery)}".</div>`;
        return;
    }

    const diffPeopleCount = matched.filter(p => !p.same_suspect).length;
    const samePersonCount = matched.length - diffPeopleCount;
    const txidCount = matched.filter(p => p.match_type === "txid").length;

    let html = `<div class="results-note">
        ${matched.length}${analysisSearchQuery ? ` of ${allMatched.length}` : ""} confirmed transfer(s) shown — <b>${txidCount}</b> proven by matching <b>TXID</b> (same blockchain tx on both sides),
        ${matched.length - txidCount} inferred from a shared address. <b>${samePersonCount}</b> between wallets of the <b>same person</b>,
        <b>${diffPeopleCount}</b> between <b>two different people</b>.
        ${unmatched.length ? `${unmatched.length} movement(s) could not be confidently paired — see below.` : ""}
    </div>`;

    matched.forEach(p => {
        const w = p.withdrawal, d = p.deposit;
        const who = p.same_suspect
            ? `<b>${escapeHtml(w.suspect_name)}</b> sent to themself`
            : `<b>${escapeHtml(w.suspect_name)}</b> sent to <b>${escapeHtml(d.suspect_name)}</b>`;
        const viaLabel = p.match_type === "txid"
            ? `matching TX hash <span class="addr-mono">${highlightMatch(w.txid)}</span>`
            : `shared address <span class="addr-mono">${highlightMatch(p.address)}</span>`;
        html += `<div class="transfer-card">
            <div class="addr-line">
                ${p.match_type === "txid" ? '<span class="same-person-badge" style="background:rgba(62,207,142,0.18);color:var(--success);">✓ CONFIRMED (SAME TXID)</span> ' : '<span class="unverified-badge" style="background:rgba(139,147,167,0.18);color:var(--text-dim);">PROBABLE (SAME ADDRESS)</span> '}
                ${who} — via ${viaLabel}
                ${p.same_suspect ? '<span class="same-person-badge">SAME PERSON</span>' : '<span class="diff-suspect-badge">DIFFERENT PEOPLE</span>'}
                ${!p.same_exchange ? '<span class="same-person-badge" style="background:rgba(139,147,167,0.18);color:var(--text-dim);">CROSS-EXCHANGE</span>' : ""}
                ${!p.amount_matched ? '<span class="unverified-badge" title="Amount and/or currency could not be confirmed between the two sides - verify manually.">⚠ AMOUNT UNVERIFIED</span>' : ""}
            </div>
            <div class="transfer-flow">
                <div class="transfer-side">
                    <div class="label">Sent (withdrawal)</div>
                    <div class="exchange-name">${escapeHtml(w.exchange)}</div>
                    <div>${escapeHtml(w.suspect_name)}</div>
                    <div class="amount">${fmtAmount(w.amount, w.currency)}</div>
                    <div style="color:var(--text-dim);font-size:12px;">${fmtDate(w.date)}</div>
                    <div class="txid-line">TX Hash: <span class="addr-mono">${highlightMatch(w.txid || "-")}</span></div>
                </div>
                <div class="transfer-arrow">→</div>
                <div class="transfer-side">
                    <div class="label">Received (deposit)</div>
                    <div class="exchange-name">${escapeHtml(d.exchange)}</div>
                    <div>${escapeHtml(d.suspect_name)}</div>
                    <div class="amount">${fmtAmount(d.amount, d.currency)}</div>
                    <div style="color:var(--text-dim);font-size:12px;">${fmtDate(d.date)}</div>
                    <div class="txid-line">TX Hash: <span class="addr-mono">${highlightMatch(d.txid || "-")}</span></div>
                </div>
            </div>
            <div class="transfer-gap">Time gap: ${p.gap_hours} hour(s)</div>
        </div>`;
    });

    if (unmatched.length) {
        html += `<div class="panel-title" style="margin-top:24px;">Unmatched movements (needs manual review)</div>`;
        html += '<div class="table-wrap"><table><thead><tr><th>Direction</th><th>Suspect</th><th>Exchange</th><th>Amount</th><th>Date</th><th>Address</th><th>TXID</th></tr></thead><tbody>';
        unmatched.forEach(u => {
            html += `<tr>
                <td><span class="badge ${u.direction}">${TYPE_LABELS[u.direction] || u.direction}</span></td>
                <td>${escapeHtml(u.suspect_name)}</td>
                <td>${escapeHtml(u.exchange)}</td>
                <td>${fmtAmount(u.amount, u.currency)}</td>
                <td>${fmtDate(u.date)}</td>
                <td>${truncMono(u.address)}</td>
                <td>${truncMono(u.txid)}</td>
            </tr>`;
        });
        html += "</tbody></table></div>";
    }

    container.innerHTML = html;
}

let graphNetworkInstance = null;

let graphToolbarHideTimer = null;

function loadGraph(container) {
    container.innerHTML = `
        <div class="graph-controls">
            <div class="results-note" style="margin-bottom:0;">Only accounts linked by a shared wallet or a confirmed TXID transfer are shown. Hover a wallet node for actions.</div>
            <div class="graph-legend">
                <span class="legend-item"><span class="legend-dot" style="background:#4f8cff;"></span> Suspect</span>
                <span class="legend-item"><span class="legend-dot" style="background:#f0556b;"></span> Wallet shared between different people</span>
                <span class="legend-item"><span class="legend-dot" style="background:#f5a623;"></span> Wallet shared by the same person</span>
                <span class="legend-item"><span class="legend-dot" style="background:#3ecf8e;"></span> Confirmed TXID transfer (direct link)</span>
            </div>
        </div>
        <div class="graph-canvas-wrap">
            <div id="graphCanvas"></div>
            <div id="graphNodeToolbar" class="node-toolbar">
                <button class="icon-btn" title="Copy address" onclick="copyAddress(document.getElementById('graphNodeToolbar').dataset.address)">📋</button>
                <button class="icon-btn danger" title="Hide this wallet" onclick="hideWallet(document.getElementById('graphNodeToolbar').dataset.address)">🗑️</button>
            </div>
        </div>
    `;

    const toolbar = document.getElementById("graphNodeToolbar");
    toolbar.addEventListener("mouseenter", () => clearTimeout(graphToolbarHideTimer));
    toolbar.addEventListener("mouseleave", scheduleHideGraphToolbar);

    fetch("/analysis/graph" + suspectsQueryParam()).then(r => r.json()).then(data => {
        if (!data.nodes.length) {
            if (graphNetworkInstance) { graphNetworkInstance.destroy(); graphNetworkInstance = null; }
            document.getElementById("graphCanvas").outerHTML =
                '<div class="analysis-empty">No wallet connects two different accounts yet.</div>';
            return;
        }

        const nodes = new vis.DataSet(data.nodes);
        const edges = new vis.DataSet(data.edges);

        const options = {
            nodes: {
                shape: "dot", size: 16, font: { color: "#e6e9f0", size: 12 },
                borderWidth: 2,
            },
            edges: {
                color: { color: "#3a4258", highlight: "#4f8cff" },
                smooth: { type: "continuous" },
                scaling: { min: 1, max: 8 },
            },
            groups: {
                suspect: { color: { background: "#4f8cff", border: "#2a4a8a" }, shape: "dot", size: 22 },
                address_shared_cross_suspect: { color: { background: "#f0556b", border: "#8a2030" } },
                address_shared_same_suspect: { color: { background: "#f5a623", border: "#8a5c10" } },
            },
            physics: { stabilization: true, barnesHut: { gravitationalConstant: -3000, springLength: 120 } },
            interaction: { hover: true, tooltipDelay: 100, dragNodes: true },
        };

        if (graphNetworkInstance) graphNetworkInstance.destroy();
        graphNetworkInstance = new vis.Network(document.getElementById("graphCanvas"), { nodes, edges }, options);
        // Physics only runs for the initial layout. Once it settles, turn it off so dragging
        // one node repositions just that node instead of the whole graph reacting/reshuffling.
        graphNetworkInstance.once("stabilizationIterationsDone", () => {
            graphNetworkInstance.setOptions({ physics: false });
        });

        // Hover a wallet node -> show a small floating copy/hide toolbar next to it (suspect
        // nodes can't be hidden, so they get no toolbar). A short delay on hide lets the
        // mouse travel from the node onto the toolbar itself without it disappearing first.
        graphNetworkInstance.on("hoverNode", params => {
            const node = nodes.get(params.node);
            if (!node.group || !node.group.startsWith("address_shared")) return;
            clearTimeout(graphToolbarHideTimer);
            const pos = graphNetworkInstance.canvasToDOM(graphNetworkInstance.getPositions([params.node])[params.node]);
            toolbar.style.left = (pos.x + 16) + "px";
            toolbar.style.top = (pos.y - 14) + "px";
            toolbar.style.display = "flex";
            toolbar.dataset.address = node.title;
        });
        graphNetworkInstance.on("blurNode", scheduleHideGraphToolbar);
        graphNetworkInstance.on("dragStart", () => { toolbar.style.display = "none"; });
        graphNetworkInstance.on("zoom", () => { toolbar.style.display = "none"; });

        focusGraphSearchMatch();
    }).catch(err => {
        document.getElementById("graphCanvas").outerHTML = `<div class="analysis-empty">Error loading graph: ${escapeHtml(String(err))}</div>`;
    });
}

function scheduleHideGraphToolbar() {
    clearTimeout(graphToolbarHideTimer);
    graphToolbarHideTimer = setTimeout(() => {
        const toolbar = document.getElementById("graphNodeToolbar");
        if (toolbar) toolbar.style.display = "none";
    }, 250);
}

// Graph tab has no per-row list to filter, so the shared search box instead selects and
// centers on the matching wallet node (by address) or, failing that, the matching
// TXID-confirmed edge - same search box, same query, adapted to a graph instead of a table.
function focusGraphSearchMatch() {
    if (!graphNetworkInstance) return;
    if (!analysisSearchQuery) { graphNetworkInstance.unselectAll(); return; }

    const nodeMatch = graphNetworkInstance.body.data.nodes.get().find(n => matchesSearch(n.title));
    if (nodeMatch) {
        graphNetworkInstance.selectNodes([nodeMatch.id]);
        graphNetworkInstance.focus(nodeMatch.id, { scale: 1.3, animation: true });
        return;
    }
    const edgeMatch = graphNetworkInstance.body.data.edges.get().find(e => matchesSearch(e.title));
    if (edgeMatch) {
        graphNetworkInstance.selectEdges([edgeMatch.id]);
        graphNetworkInstance.focus(edgeMatch.from, { scale: 1.2, animation: true });
        return;
    }
    graphNetworkInstance.unselectAll();
}


// ---------------------------------------------------------------------------
// EXPORT SUSPECT FILTER
// ---------------------------------------------------------------------------

let suspectFilterSelected = new Set();

function syncSuspectFilterWithSuspects() {
    // keep filter selection in sync when suspects are added/removed -
    // new suspects default to "included", removed ones are dropped
    const currentIds = new Set(Object.keys(suspects));
    for (const id of currentIds) {
        if (!suspectFilterSelected.has(id)) suspectFilterSelected.add(id);
    }
    for (const id of Array.from(suspectFilterSelected)) {
        if (!currentIds.has(id)) suspectFilterSelected.delete(id);
    }
}

function toggleSuspectFilterPanel() {
    const panel = document.getElementById("suspectFilterPanel");
    const isHidden = panel.style.display === "none";
    panel.style.display = isHidden ? "block" : "none";
    if (isHidden) renderSuspectFilterList();
}

function renderSuspectFilterList() {
    const list = document.getElementById("suspectFilterList");
    const ids = Object.keys(suspects);
    if (!ids.length) {
        list.innerHTML = '<div style="color:var(--text-dim);font-size:12.5px;">No suspects yet.</div>';
        return;
    }
    list.innerHTML = ids.map(id => `
        <label class="suspect-filter-item">
            <input type="checkbox" ${suspectFilterSelected.has(id) ? "checked" : ""} onchange="onSuspectFilterChange('${id}', this.checked)">
            <span>${escapeHtml(suspects[id])}</span>
        </label>
    `).join("");
}

function onSuspectFilterChange(id, checked) {
    if (checked) suspectFilterSelected.add(id);
    else suspectFilterSelected.delete(id);
    refreshCurrentAnalysisTab();
}

function setAllSuspectFilter(selectAll) {
    const ids = Object.keys(suspects);
    suspectFilterSelected = selectAll ? new Set(ids) : new Set();
    renderSuspectFilterList();
    refreshCurrentAnalysisTab();
}

function refreshCurrentAnalysisTab() {
    if (currentMainTab === "analysis") loadAnalysisTab(currentAnalysisTab);
}

// Builds the ?suspects=id1,id2 query string shared by every analysis fetch and by export,
// so the same suspect-filter selection drives both the on-screen tabs and exports. Empty
// string when nothing is filtered out (i.e. show/export everything).
function suspectsQueryParam() {
    const allIds = Object.keys(suspects);
    const selected = Array.from(suspectFilterSelected);
    const isFiltered = selected.length > 0 && selected.length < allIds.length;
    return isFiltered ? `?suspects=${selected.join(",")}` : "";
}

function triggerExport(fmt) {
    const allIds = Object.keys(suspects);
    const selected = Array.from(suspectFilterSelected);

    if (allIds.length && selected.length === 0) {
        showToast("No suspects selected for export - check the filter.", true);
        return;
    }

    window.location.href = `/export/${fmt}${suspectsQueryParam()}`;
}


refreshSuspects();
</script>

</body>
</html>
"""

if __name__ == "__main__":
    print("=" * 50)
    print("CryptoLink starting.")
    print("Open your browser at: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)