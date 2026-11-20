import argparse, os, sys, json, time, asyncio, logging, re
from typing import Dict, List, Any
import pandas as pd
from collections import defaultdict
from tqdm import tqdm
from lightrag import LightRAG, QueryParam
from lightrag.utils import EmbeddingFunc
from lightrag.kg.shared_storage import initialize_pipeline_status
from lightrag.llm.openai import openai_complete_if_cache, openai_embed

parser = argparse.ArgumentParser()
parser.add_argument("--api_base", required=True)
parser.add_argument("--api_key",  required=True)
parser.add_argument("--working_dir", required=True)
args, unknown = parser.parse_known_args()

os.environ["OPENAI_API_BASE"] = args.api_base
os.environ["OPENAI_API_KEY"]  = args.api_key
WORKING_DIR = args.working_dir

DATA_DIR        = "./src/finkg" # You can generate the dataset by running the code, or you can download the dataset from the provided link (FinKario datasets/FinKario).
BACKTEST_LOG    = os.path.join(WORKING_DIR, "backtest.log")
LOG_FILE        = os.path.join(WORKING_DIR, "processing.log")
CONV_LOG        = os.path.join(WORKING_DIR, "conversation.log")



INDUSTRY_CSV_PATH = "./data/stock_industry_list_new.csv"
EMBED_MODEL     = "text-embedding-3-small" # change other embedding model
EMBED_DIM       = 1536
MAX_TOKEN_CHUNK = 8192


TREND_PAT = re.compile(r"预测\s*[:：]\s*(涨|持平|跌)", re.I)

def _extract_trend(answer: str) -> str | None:
    m = TREND_PAT.search(answer)
    return m.group(1) if m else None
 

def setup_logging() -> None:
    os.makedirs(WORKING_DIR, exist_ok=True)
    logging.basicConfig(
        level   = logging.INFO,
        format  = "%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def setup_environment() -> None:
    if not os.getenv("OPENAI_API_BASE") or not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_BASE / OPENAI_API_KEY not set!")
    if not os.path.isfile(INDUSTRY_CSV_PATH):
        raise RuntimeError(f"Expected industry CSV at {INDUSTRY_CSV_PATH} not found.")


async def embedding_func(texts: List[str]) -> List[List[float]]:
    return await openai_embed(
        texts,
        model    = EMBED_MODEL,
        api_key  = os.getenv("OPENAI_API_KEY"),
        base_url = os.getenv("OPENAI_API_BASE"),
    )

class FinancialKGProcessor:
    def __init__(self) -> None:
        setup_logging()
        setup_environment()
        self.stats = {"total": 0, "succ": 0, "fail": 0}
        self.date_map: Dict[str, List[str]] = defaultdict(list)
        self.all_codes: List[str] = []
        self.df_close: pd.DataFrame = pd.DataFrame()
        self.name_to_code: Dict[str, str] = {}
        self._load_industry_mapping()

    def _load_industry_mapping(self) -> None:
        industry_df = pd.read_csv(INDUSTRY_CSV_PATH)
        for _, row in industry_df.iterrows():
            name_x = row.get("name_x", "")
            name_y = row.get("name_y", "")
            ts_code = row.get("ts_code", "")
            if pd.notna(name_x) and isinstance(name_x, str) and name_x.strip():
                self.name_to_code[name_x.strip()] = ts_code.strip()
            if pd.notna(name_y) and isinstance(name_y, str) and name_y.strip():
                self.name_to_code[name_y.strip()] = ts_code.strip()

    def _parse_filename(self, filename: str) -> Dict[str, str]:
        parts = filename.split("-")
        if len(parts) < 5 or not parts[0].isdigit():
            raise ValueError(f"Bad filename format: {filename}")
        date_str = "-".join(parts[:3])
        company_code = parts[3]
        return {"date": date_str, "company_code": company_code}

    async def _llm_model(self, prompt: str, **kwargs) -> str:
        return await openai_complete_if_cache(
            "gpt-3.5-turbo",
            prompt,
            api_key  = os.getenv("OPENAI_API_KEY"),
            base_url = os.getenv("OPENAI_API_BASE"),
            **kwargs,
        )

    def _build_kg(self, raw: Dict[str, Any], company: str, code: str, date: str) -> Dict[str, Any]:
        src = f"FinKario_{code}_{date}"
        kg  = {"entities": [], "relationships": [], "chunks": []}
        add_entity = kg["entities"].append
        add_rel    = kg["relationships"].append
        add_entity({
            "entity_name": company,
            "entity_type": "Organization",
            "description": "",
            "source_id": src,
            "tags": [date, code],
        })

        tn = f"{company}@{date}"
        add_entity({
            "entity_name": tn,
            "entity_type": "TimePoint",
            "description": f"{company} 报告日期 {date}",
            "source_id": src,
            "tags": [date, code],
        })

        add_rel({
            "src_id": company,
            "tgt_id": tn,
            "description": f"{company} 报告发布日期为 {date}",
            "keywords": "has_report_date",
            "weight": 1.0,
            "source_id": src,
            "tags": [date, code],
        })

        for att in raw.get("attributes", []):
            rel_name = att.get("relation", "").strip()
            for val in att.get("target_entity", []):
                add_entity({
                    "entity_name": val,
                    "entity_type": "Attribute",
                    "description": f"{rel_name} 属性值",
                    "source_id": src,
                    "tags": [date, code],
                })
                add_rel({
                    "src_id": company,
                    "tgt_id": val,
                    "description": f"{company} 的 {rel_name} 是 {val}",
                    "keywords": rel_name,
                    "weight": 1.0,
                    "source_id": src,
                    "tags": [date, code],
                })

        for i, (k, evt) in enumerate(raw.get("events", {}).items()):
            kg["chunks"].append({
                "content": json.dumps({k: evt}, ensure_ascii=False),
                "source_id": src,
                "source_chunk_index": i,
                "tags": [date, code],
                "stock_code": code,
                "time_node": tn,
            })
        return kg

        
    async def process_all(self) -> None:
        setup_logging()
        setup_environment()
        for fn in os.listdir(DATA_DIR):
            if not fn.endswith(".json"):
                continue
            self.stats["total"] += 1
            try:
                info = self._parse_filename(fn)
                self.date_map[info["date"]].append(fn)
            except Exception as e:
                self.stats["fail"] += 1
                logging.error(f"Filename parse error {fn}: {e}")
        if not self.date_map:
            logging.warning("No JSON files found in DATA_DIR. Exit.")
            return

        all_dates = sorted(self.date_map.keys())
        weeks_map: Dict[str, List[str]] = defaultdict(list)
        for date_str in all_dates:
            dt = pd.to_datetime(date_str)
            week_end_date = dt.to_period("W-FRI").end_time.date().strftime("%Y-%m-%d")
            weeks_map[week_end_date].append(date_str)


        SYSTEM_PROMPT = """
你是一名量化分析师，必须基于「已知图谱信息」进行客观判断，
严禁凭空杜撰、严禁照搬研报评级结论。严禁因就评级的乐观而有 bias，请你着重考虑财务指标和风险层面，因果逻辑；做好风险控制的同时，做出正确合理的评估，对于结论给出充足的理由。
"""

        for week_end, week_dates in sorted(weeks_map.items()):
            week_dir = os.path.join(WORKING_DIR, week_end)
            os.makedirs(week_dir, exist_ok=True)

            rag = LightRAG(
                working_dir    = week_dir,
                llm_model_func = self._llm_model,
                embedding_func = EmbeddingFunc(
                    embedding_dim  = EMBED_DIM,
                    max_token_size = MAX_TOKEN_CHUNK,
                    func           = embedding_func,
                ),
            )
            await rag.initialize_storages()
            await initialize_pipeline_status()
            
            graphml_path = os.path.join(week_dir, "graph_chunk_entity_relation.graphml")
            if not os.path.exists(graphml_path):
                logging.info(f"Starting the ingest for this week ({week_end})")
                for date_str in week_dates:
                    logging.info(f"--- INGEST date {date_str} ---")
                    for fn in tqdm(self.date_map[date_str], desc=f"{date_str} ingest", unit="file"):
                        raw_path = os.path.join(DATA_DIR, fn)
                        try:
                            info = self._parse_filename(fn)
                            raw  = json.load(open(raw_path, "r", encoding="utf-8")) or {}
                            kg   = self._build_kg(raw, raw.get("company", "Unknown"),
                                                  info["company_code"], date_str)
                            await rag.ainsert_custom_kg(kg)
                            self.stats["succ"] += 1
                        except Exception as e:
                            logging.error(f"Ingest error {fn}: {e}")
                            self.stats["fail"] += 1
                    await rag.finalize_storages()
                logging.info(f" This week ({week_end}) ingestion completed ")
            else:
                logging.info(f"Detected {graphml_path}, skipping this week's ingest")

            for date_str in week_dates:
                logging.info(f"--- QUERY date {date_str} ---")
                rising_today: List[str] = []
                for fn in self.date_map[date_str]:
                    try:
                        raw_code = self._parse_filename(fn)["company_code"]
                    except:
                        continue


                    question = (
                        f"截至{date_str}收盘，请你对 {raw_code} 在下周的股价走势进行预测，"
                        "客观评价，不要依赖研报中给出的评级，自行判断，对应公司的风险评估及业绩考核，"
                        "给到的理由可以结合图谱的实体信息，如（财务指标、风险评估、主要行业、主要产品、因果事件、目标股价等），"
                        "以及相应关系以及相同行业的其他股票信息，综合考虑，"
                        "只能回答“涨”或“持平”或“跌”，并给出一个 0–10 的置信分。\n"
                        "请按如下格式作答：\n"
                        "股票代码: <code>\n"
                        "预测: <涨或持平或跌>\n"
                        "置信分: <0-10>\n"
                        "原因: <理由>\n"
                    )
                    

                    param = QueryParam(
                        # you can change the mode: global, hybrid
                        mode        = "hybrid",
                        stream      = False,
                        hl_keywords = [raw_code, date_str],
                        ll_keywords = [raw_code, date_str],
                    )

                    try:
                        ans = await rag.aquery(SYSTEM_PROMPT + "\n\n" + question, param)
                    except Exception as e:
                        logging.error(f"Query error {date_str} {raw_code}: {e}")
                        continue

                    trend = _extract_trend(ans)
                    if trend == "涨":
                        rising_today.append(raw_code)

                    with open(CONV_LOG, "a", encoding="utf-8") as f_conv:
                        f_conv.write(f"[{date_str}] [{raw_code}]\nQ: {question}\nA: {ans}\n\n")

                with open(BACKTEST_LOG, "a", encoding="utf-8") as f_bt:
                    f_bt.write(f"{date_str} 涨的股票：{', '.join(sorted(set(rising_today)))}\n")
                logging.info(f"{date_str} Rising: {', '.join(sorted(set(rising_today)))}")

        logging.info(
            f"ALL DONE TOTAL_FILES={self.stats['total']} SUCCESS_INGEST={self.stats['succ']} FAIL_INGEST={self.stats['fail']}"
        )

if __name__ == "__main__":
    asyncio.run(FinancialKGProcessor().process_all())


