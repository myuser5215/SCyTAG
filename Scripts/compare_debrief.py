#!/usr/bin/env python3
"""
compare_debrief.py

Compare two CALDERA debrief JSON reports.

What it does:
1) Loads two JSON reports
2) Normalizes timestamps (UTC + seconds-from-report-start)
3) Computes basic comparison metrics (summary, abilities, tactics/techniques, hosts, statuses)
4) Writes CSV tables and (optionally) bar charts

Example:
  python compare_debrief.py \
    /path/to/report_A.json /path/to/report_B.json \
    -o ./out --charts

Outputs (in -o / --outdir):
  - summary.csv
  - actions_A.csv, actions_B.csv
  - abilities_compare.csv
  - techniques_compare.csv
  - tactics_compare.csv
  - statuses_compare.csv
  - (optional) *.png charts
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

try:
    import matplotlib.pyplot as plt  # optional
except Exception:  # pragma: no cover
    plt = None


# -----------------------------
# 1) IO + timestamp normalization
# -----------------------------

def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_ts(value: Any) -> pd.Timestamp:
    """
    Parse common timestamp formats into a timezone-aware pandas Timestamp (UTC).

    Supports:
      - ISO strings like "2026-02-03T10:44:08Z"
      - Unix epoch (seconds or milliseconds) as int/float
      - None / missing => NaT
    """
    if value is None or value == "":
        return pd.NaT

    # epoch seconds/millis
    if isinstance(value, (int, float)):
        # heuristic: 13 digits => ms, 10 digits => seconds
        if value > 1e12:
            return pd.to_datetime(int(value), unit="ms", utc=True, errors="coerce")
        return pd.to_datetime(float(value), unit="s", utc=True, errors="coerce")

    # strings (ISO 8601 etc.)
    return pd.to_datetime(value, utc=True, errors="coerce")


# -----------------------------
# 2) Flatten debrief JSON to an "actions" table
# -----------------------------

def extract_host_group_links(report: Dict[str, Any]) -> pd.DataFrame:
    """
    Flatten report['host_group'][*]['links'][*] (when present).

    These are often low-level "link" records attached to each agent/paw and
    include rich ability/executor metadata.
    """
    rows: List[Dict[str, Any]] = []
    for agent in report.get("host_group", []) or []:
        paw = agent.get("paw")
        host = agent.get("host")
        username = agent.get("username")
        group = agent.get("group")

        for link in agent.get("links", []) or []:
            ability = link.get("ability") or {}
            executor = link.get("executor") or {}

            rows.append(
                {
                    "source": "host_group_link",
                    "paw": paw,
                    "host": host,
                    "username": username,
                    "group": group,
                    "ability_id": ability.get("ability_id") or link.get("ability_id"),
                    "ability_name": ability.get("name") or link.get("name"),
                    "tactic": ability.get("tactic") or link.get("tactic"),
                    "technique_id": ability.get("technique_id") or link.get("technique_id"),
                    "technique_name": ability.get("technique_name") or link.get("technique_name"),
                    "executor": executor.get("name") if isinstance(executor, dict) else link.get("executor"),
                    "platform": executor.get("platform") if isinstance(executor, dict) else link.get("platform"),
                    "status": link.get("status"),
                    "command": link.get("plaintext_command") or link.get("command"),
                    "decide": link.get("decide"),
                    "collect": link.get("collect"),
                    "finish": link.get("finish"),
                    "agent_reported_time": link.get("agent_reported_time"),
                }
            )

    return pd.DataFrame(rows)


def extract_operation_steps(report: Dict[str, Any]) -> pd.DataFrame:
    """
    Flatten report['steps'].

    In many debriefs, report['steps'] is a dict keyed by paw, where each paw maps
    to {"steps": [ ... ]}. These "steps" are the higher-level operation records.
    """
    rows: List[Dict[str, Any]] = []
    steps_obj = report.get("steps") or {}

    if isinstance(steps_obj, dict):
        paw_items = steps_obj.items()
    else:
        # Very defensive fallback: treat as empty
        paw_items = []

    for paw, paw_blob in paw_items:
        for st in (paw_blob or {}).get("steps", []) or []:
            attack = st.get("attack") or {}
            rows.append(
                {
                    "source": "operation_step",
                    "paw": paw,
                    "host": None,
                    "username": None,
                    "group": None,
                    "ability_id": st.get("ability_id"),
                    "ability_name": st.get("name"),
                    "tactic": attack.get("tactic"),
                    "technique_id": attack.get("technique_id"),
                    "technique_name": attack.get("technique_name"),
                    "executor": st.get("executor"),
                    "platform": st.get("platform"),
                    "status": st.get("status"),
                    "command": st.get("plaintext_command") or st.get("command"),
                    "decide": None,
                    "collect": None,
                    "finish": None,
                    "agent_reported_time": st.get("agent_reported_time"),
                }
            )

    return pd.DataFrame(rows)


def build_actions_df(report: Dict[str, Any], label: str) -> pd.DataFrame:
    """
    Combine all extracted actions and normalize time columns.
    """
    links_df = extract_host_group_links(report)
    steps_df = extract_operation_steps(report)

    df = pd.concat([links_df, steps_df], ignore_index=True)
    df["report_label"] = label

    # Parse timestamps
    for col in ["decide", "collect", "finish", "agent_reported_time"]:
        if col in df.columns:
            df[col] = df[col].map(parse_ts)

    report_start = parse_ts(report.get("start"))
    report_finish = parse_ts(report.get("finish"))

    df["report_start"] = report_start
    df["report_finish"] = report_finish

    # Choose best available start/end timestamps per row
    # (Different record types expose different timestamp fields.)
    df["t_start"] = (
        df.get("decide", pd.Series(dtype="datetime64[ns, UTC]"))
        .combine_first(df.get("collect", pd.Series(dtype="datetime64[ns, UTC]")))
        .combine_first(df.get("agent_reported_time", pd.Series(dtype="datetime64[ns, UTC]")))
    )

    df["t_end"] = (
        df.get("finish", pd.Series(dtype="datetime64[ns, UTC]"))
        .combine_first(df.get("collect", pd.Series(dtype="datetime64[ns, UTC]")))
        .combine_first(df.get("agent_reported_time", pd.Series(dtype="datetime64[ns, UTC]")))
    )

    # Normalize to seconds-from-start (lets you compare runs on a common 0..T axis)
    df["rel_start_s"] = (df["t_start"] - report_start).dt.total_seconds()
    df["rel_end_s"] = (df["t_end"] - report_start).dt.total_seconds()

    return df


# -----------------------------
# 3) Metrics + comparisons
# -----------------------------

def status_bucket(status: Any) -> str:
    """
    Bucket exit/status codes into a few coarse categories.

    Convention used here:
      - 0 => success
      - 124 => timeout (commonly from 'timeout' wrapper / SIGTERM in shells)
      - None/NaN => unknown
      - otherwise => failure
    """
    if status is None or (isinstance(status, float) and pd.isna(status)):
        return "unknown"
    try:
        s = int(status)
    except Exception:
        return "unknown"
    if s == 0:
        return "success"
    if s == 124:
        return "timeout"
    return "failure"


def summarize_report(df: pd.DataFrame) -> pd.DataFrame:
    """
    One-row summary for a single report.
    """
    start = df["report_start"].iloc[0]
    finish = df["report_finish"].iloc[0]
    duration_s = (finish - start).total_seconds() if pd.notna(start) and pd.notna(finish) else None

    df2 = df.copy()
    df2["status_bucket"] = df2["status"].map(status_bucket)

    out = {
        "report_label": df["report_label"].iloc[0],
        "start_utc": start,
        "finish_utc": finish,
        "duration_s": duration_s,
        "num_actions": len(df2),
        "num_operation_steps": int((df2["source"] == "operation_step").sum()),
        "num_host_group_links": int((df2["source"] == "host_group_link").sum()),
        "num_unique_paws": int(df2["paw"].nunique(dropna=True)),
        "num_unique_hosts": int(df2["host"].nunique(dropna=True)),
        "num_unique_abilities": int(df2["ability_id"].nunique(dropna=True)),
        "success": int((df2["status_bucket"] == "success").sum()),
        "timeout": int((df2["status_bucket"] == "timeout").sum()),
        "failure": int((df2["status_bucket"] == "failure").sum()),
        "unknown": int((df2["status_bucket"] == "unknown").sum()),
    }
    return pd.DataFrame([out])


def group_counts(
    df: pd.DataFrame,
    group_cols: List[str],
    *,
    min_count: int = 1,
) -> pd.DataFrame:
    """
    Return per-group counts + successes + success rate.
    """
    d = df.copy()
    d["status_bucket"] = d["status"].map(status_bucket)

    g = d.groupby(group_cols, dropna=False)
    out = g.size().rename("count").reset_index()

    succ = g.apply(lambda x: int((x["status_bucket"] == "success").sum())).rename("success_count").reset_index(drop=True)
    out["success_count"] = succ
    out["success_rate"] = out["success_count"] / out["count"]

    out = out[out["count"] >= min_count]
    return out.sort_values("count", ascending=False)


def compare_two(
    a: pd.DataFrame,
    b: pd.DataFrame,
    group_cols: List[str],
    *,
    a_label: str,
    b_label: str,
) -> pd.DataFrame:
    """
    Outer-join the grouped counts so you get side-by-side A/B and deltas.
    """
    ga = group_counts(a, group_cols)
    gb = group_counts(b, group_cols)

    merged = ga.merge(gb, on=group_cols, how="outer", suffixes=(f"_{a_label}", f"_{b_label}")).fillna(0)

    merged[f"delta_count_{b_label}_minus_{a_label}"] = merged[f"count_{b_label}"] - merged[f"count_{a_label}"]

    # percent change from A -> B (safe divide)
    denom = merged[f"count_{a_label}"].replace({0: pd.NA})
    merged[f"pct_change_{b_label}_vs_{a_label}"] = (merged[f"delta_count_{b_label}_minus_{a_label}"] / denom) * 100

    # nice ordering: biggest absolute deltas first, then total volume
    merged["abs_delta"] = merged[f"delta_count_{b_label}_minus_{a_label}"].abs()
    merged["total"] = merged[f"count_{a_label}"] + merged[f"count_{b_label}"]

    merged = merged.sort_values(["abs_delta", "total"], ascending=False).drop(columns=["abs_delta", "total"])
    return merged


# -----------------------------
# 4) Export helpers (CSVs + optional charts)
# -----------------------------

def write_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def plot_bar_compare(
    df: pd.DataFrame,
    category_col: str,
    a_col: str,
    b_col: str,
    *,
    title: str,
    out_path: Path,
    top_n: int = 15,
) -> None:
    """
    Save a side-by-side bar chart for the top N categories.
    Uses matplotlib defaults (no custom colors).
    """
    if plt is None:
        return

    if df.empty:
        return

    # Keep only rows with some volume
    d = df.copy()
    d = d[(d[a_col] + d[b_col]) > 0]

    # Sort by combined volume, show top N
    d["_total"] = d[a_col] + d[b_col]
    d = d.sort_values("_total", ascending=False).head(top_n).drop(columns=["_total"])

    d = d.set_index(category_col)[[a_col, b_col]]
    ax = d.plot(kind="bar", figsize=(12, 5))
    ax.set_title(title)
    ax.set_ylabel("count")
    ax.set_xlabel(category_col)
    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path)
    plt.close()


# -----------------------------
# Main
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two CALDERA debrief JSON reports.")
    ap.add_argument("report_a", type=Path, help="Path to report A JSON")
    ap.add_argument("report_b", type=Path, help="Path to report B JSON")
    ap.add_argument("-o", "--outdir", type=Path, default=Path("./debrief_compare_out"), help="Output directory")
    ap.add_argument("--charts", action="store_true", help="Write bar charts (PNG) as well as CSVs")
    args = ap.parse_args()

    report_a = load_json(args.report_a)
    report_b = load_json(args.report_b)

    a_label = report_a.get("name") or args.report_a.stem or "A"
    b_label = report_b.get("name") or args.report_b.stem or "B"

    actions_a = build_actions_df(report_a, a_label)
    actions_b = build_actions_df(report_b, b_label)

    outdir = args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    # Raw action tables (useful for debugging)
    write_csv(actions_a, outdir / "actions_A.csv")
    write_csv(actions_b, outdir / "actions_B.csv")

    # Summary
    summary = pd.concat([summarize_report(actions_a), summarize_report(actions_b)], ignore_index=True)
    write_csv(summary, outdir / "summary.csv")

    # Status bucket comparison
    actions_a2 = actions_a.copy()
    actions_b2 = actions_b.copy()
    actions_a2["status_bucket"] = actions_a2["status"].map(status_bucket)
    actions_b2["status_bucket"] = actions_b2["status"].map(status_bucket)

    statuses = compare_two(
        actions_a2.rename(columns={"status_bucket": "bucket"}),
        actions_b2.rename(columns={"status_bucket": "bucket"}),
        ["bucket"],
        a_label=a_label,
        b_label=b_label,
    )
    write_csv(statuses, outdir / "statuses_compare.csv")

    # Ability-level comparison
    abilities = compare_two(actions_a, actions_b, ["ability_id", "ability_name"], a_label=a_label, b_label=b_label)
    write_csv(abilities, outdir / "abilities_compare.csv")

    # Tactic comparison
    tactics = compare_two(actions_a, actions_b, ["tactic"], a_label=a_label, b_label=b_label)
    write_csv(tactics, outdir / "tactics_compare.csv")

    # Technique comparison (technique_id + name are most useful for reporting)
    techniques = compare_two(
        actions_a, actions_b, ["technique_id", "technique_name", "tactic"], a_label=a_label, b_label=b_label
    )
    write_csv(techniques, outdir / "techniques_compare.csv")

    # Optional charts
    if args.charts:
        plot_bar_compare(
            abilities,
            category_col="ability_name",
            a_col=f"count_{a_label}",
            b_col=f"count_{b_label}",
            title="Ability counts: A vs B (top)",
            out_path=outdir / "charts" / "abilities_top.png",
        )
        plot_bar_compare(
            tactics,
            category_col="tactic",
            a_col=f"count_{a_label}",
            b_col=f"count_{b_label}",
            title="Tactic counts: A vs B",
            out_path=outdir / "charts" / "tactics.png",
        )
        plot_bar_compare(
            statuses,
            category_col="bucket",
            a_col=f"count_{a_label}",
            b_col=f"count_{b_label}",
            title="Status buckets: A vs B",
            out_path=outdir / "charts" / "statuses.png",
        )

    print(f"[OK] Wrote outputs to: {outdir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
