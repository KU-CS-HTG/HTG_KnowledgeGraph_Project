import argparse
import os, re
from pathlib import Path
from collections import defaultdict
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import tushare as ts
from matplotlib import cycler

parser = argparse.ArgumentParser()
parser.add_argument("--tushare_token", required=True,
                    help="TuShare API token")
args, unknown = parser.parse_known_args()
pro = ts.pro_api(args.tushare_token)


plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial Unicode MS"]
plt.rcParams["axes.unicode_minus"] = False

# The backtest log file of each baseline, including institutions & incices & vanilla LLMs and FinLLMs

LOG_DIR   = Path("./src/backtest/backtest_agency")

EXTRA_LOGS = {
    Path("./src/backtest/backtest_FinKario.log"):                   "FinKario-RAG",
    Path("./src/backtest/backtest_RAG.log"):              "RAG",
    Path("./src/backtest/backtest_FinGPT.log"):     "FinGPT",
    Path("./src/backtest/backtest_FinMA.log"):               "FinMA",
    Path("./src/backtest/backtest_qwen3-8b.log"):          "Qwen3-8b",
    Path("./src/backtest/backtest_gpt-4o-mini.log"):"GPT-4o-mini",
    Path("./src/backtest/backtest_xuanyuan.log"): "XuanYuan-6B",
    Path("./src/backtest/backtest_DISC-FinLLM.log"): "DISC-FinLLM",
    Path("./src/backtest/backtest_Stock-Chain.log"):   "Stock-Chain",
}
OUT_DIR   = LOG_DIR
OUT_DIR.mkdir(parents=True, exist_ok=True)
FIG_PATH  = OUT_DIR / "nav_curve_multi.png"
CSV_PATH  = OUT_DIR / "metrics.csv"

def parse_log(log_file: Path) -> dict[pd.Timestamp, list[str]]:
    preds: dict[pd.Timestamp, list[str]] = {}
    with log_file.open("r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r"(\d{4}-\d{2}-\d{2})\s*涨的股票：[：:]?(.*)", line.strip())
            if not m:
                continue
            dt = pd.to_datetime(m.group(1))
            codes = [c.strip() for c in re.split(r"[;,，]", m.group(2)) if c.strip()]
            preds.setdefault(dt, []).extend(codes)
    return preds

def get_trade_days(start: str, end: str) -> pd.Series:
    cal = pro.trade_cal(exchange="", start_date=start, end_date=end, is_open="1")
    return pd.to_datetime(cal["cal_date"], format="%Y%m%d").sort_values()

def backtest_multi(preds: dict[pd.Timestamp, list[str]], name: str) -> pd.DataFrame:
    if not preds:
        return pd.DataFrame()
    start_date = min(preds).strftime("%Y%m%d")
    end_date   = (max(preds) + pd.Timedelta(days=10)).strftime("%Y%m%d")
    trade_days = get_trade_days(start_date, end_date)
    buy_map = {d: trade_days[trade_days > d].min()
               for d in preds if not trade_days[trade_days > d].empty}
    if not buy_map:
        return pd.DataFrame()
    weekly_buys: dict[pd.Timestamp, dict[str, pd.Timestamp]] = defaultdict(dict)
    for pred_dt, codes in preds.items():
        buy_dt = buy_map.get(pred_dt)
        if buy_dt is None:
            continue
        period_end = buy_dt.to_period("W-FRI").end_time.normalize()
        for code in codes:
            prev = weekly_buys[period_end].get(code)
            if prev is None or buy_dt < prev:
                weekly_buys[period_end][code] = buy_dt
    nav = 1.0
    rows = []
    for period_end, code_buy in sorted(weekly_buys.items()):
        sell_candidate = period_end + pd.Timedelta(days=7)
        sell_dt = trade_days[trade_days <= sell_candidate].max()
        if pd.isna(sell_dt):
            continue
        mvs, rets = [], []
        for code, buy_dt in code_buy.items():
            bd, sd = buy_dt.strftime("%Y%m%d"), sell_dt.strftime("%Y%m%d")
            basic = pro.daily_basic(ts_code=code, trade_date=bd)
            if basic.empty:
                continue
            mvs.append(float(basic.iloc[0]["total_mv"]))
            p_b = pro.daily(ts_code=code, start_date=bd, end_date=bd)
            p_s = pro.daily(ts_code=code, start_date=sd, end_date=sd)
            if p_b.empty or p_s.empty:
                mvs.pop()
                continue
            rets.append(float(p_s.iloc[0]["close"]) / float(p_b.iloc[0]["close"]) - 1)
        wk_ret = float(np.dot(np.array(mvs)/np.sum(mvs), rets)) if mvs and rets else 0.0
        nav *= (1 + wk_ret)
        rows.append({"date": period_end, "weekly_return": wk_ret, "cumulative_nav": nav})
    if not rows:
        return pd.DataFrame()
    first_buy = min(buy_map.values())
    rows.insert(0, {"date": first_buy, "weekly_return": 0.0, "cumulative_nav": 1.0})
    df = pd.DataFrame(rows).sort_values("date")
    df["agency"] = name
    return df

def backtest_multi_index(ts_code, name, start_date, end_date, freq="W-FRI"):
    df = pro.index_daily(ts_code=ts_code, start_date=start_date, end_date=end_date)
    if df.empty:
        print(f"Index data is empty: {ts_code}")
        return pd.DataFrame()
    df["trade_date"] = pd.to_datetime(df["trade_date"])
    df = df.sort_values("trade_date").set_index("trade_date")
    px = df["close"].resample(freq).last()
    rets = px.pct_change(fill_method=None)
    rets.iloc[0] = 0
    nav = (1 + rets).cumprod()
    result = pd.DataFrame({
        "date": px.index,
        "weekly_return": rets.values,
        "cumulative_nav": nav.values,
        "agency": name,
    })
    return result.dropna(subset=["date", "weekly_return", "cumulative_nav"])


all_curves = []


# you can customize your indices set
INDEX_LIST = [
    ("000905.SH", "CSI 500"),
    ("000001.SH", "SSE"),
    ("399300.SZ", "CSI 300"),
    ("000015.SH", "Dividend Index"),
]

# your backtest start and end date & frequency
INDEX_START = "20240828"
INDEX_END   = "20250307"
INDEX_FREQ  = "W-FRI" 

for idx, label in INDEX_LIST:
    df_index = backtest_multi_index(idx, label, INDEX_START, INDEX_END, freq=INDEX_FREQ)
    if not df_index.empty:
        all_curves.append(df_index)
        print(f"Index {label} has been added. Week number = {len(df_index) - 1}")

for log_path in sorted(LOG_DIR.glob("backtest_*_convert.log")):
    agency = log_path.stem.split("_", 1)[1].replace("_convert", "")
    preds  = parse_log(log_path)
    df_nav = backtest_multi(preds, agency)
    if df_nav.empty:
        print(f"{agency} has no valid data, skipping")
        continue
    all_curves.append(df_nav)
    print(f"{agency} processing completed. Week number = {len(df_nav) - 1}")

for path, label in EXTRA_LOGS.items():
    if not path.is_file():
        print(f"{label} File does not exist: {path}")
        continue
    preds  = parse_log(path)
    df_nav = backtest_multi(preds, label)
    if df_nav.empty:
        print(f"{label} No valid data")
        continue
    all_curves.append(df_nav)
    print(f"{label} processing completed. Week number = {len(df_nav) - 1}")

if not all_curves:
    raise SystemExit("No curves available for generation!") 

df_all = pd.concat(all_curves, ignore_index=True)

date_union = pd.date_range(df_all["date"].min(), df_all["date"].max(), freq="W-FRI")
nav_curves = {}
for agency, grp in df_all.groupby("agency"):
    grp = grp.sort_values("date").set_index("date")
    curve = grp["cumulative_nav"].reindex(date_union).ffill()
    nav_curves[agency] = curve

color_cycler = plt.cm.get_cmap('tab20', len(nav_curves))
agency_list = list(nav_curves.keys())
plt.figure(figsize=(15, 5))
for i, agency in enumerate(agency_list):
    lw = 4 if agency == "FinKario-RAG" else 2
    plt.plot(date_union, nav_curves[agency], label=agency, linewidth=lw, color=color_cycler(i))

plt.xlabel("Date", fontsize=12)
plt.ylabel("Cumulative NAV", fontsize=12)
plt.tick_params(axis='both', labelsize=12)
plt.grid(True, linestyle='--', alpha=0.5)
plt.legend(loc="upper left", fontsize=12, ncol=3, frameon=False)
plt.tight_layout()
plt.savefig(FIG_PATH, dpi=200)
print(f"Saved NAV curve → {FIG_PATH}")
plt.show()

metrics = []
for agency in nav_curves:
    nav = nav_curves[agency].values
    rets = np.diff(nav) / nav[:-1]
    weeks = len(rets)
    if weeks == 0:
        continue
    arr = nav[-1] ** (52 / weeks) - 1
    vol = np.std(rets, ddof=1) * np.sqrt(52)
    sr = arr / vol if vol != 0 else np.nan
    peak = np.maximum.accumulate(nav)
    drawdowns = (nav - peak) / peak
    mdd = drawdowns.min()
    cr = arr / abs(mdd) if mdd < 0 else np.nan
    metrics.append({
        "agency": agency,
        "ARR": arr,
        "VOL": vol,
        "SR": sr,
        "MDD": abs(mdd),
        "CR": cr,
    })

pd.DataFrame(metrics).to_csv(CSV_PATH, index=False)
print(f"Saved metrics → {CSV_PATH}")



