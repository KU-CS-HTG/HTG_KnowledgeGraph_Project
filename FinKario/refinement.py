
import os
import re
import json
import logging
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional

FORCE_UPDATE_FIELDS = True
class TripleProcessor:
    def __init__(self, start_date: datetime, end_date: datetime):
        self.start_date = start_date
        self.end_date = end_date

        self.stock_report_df = pd.read_csv("./data/Stock_report_List_new.csv", dtype=str)
        self.name_to_ts_code = dict(zip(self.stock_report_df["name"], self.stock_report_df["ts_code"]))

        self.stock_industry_df = pd.read_csv("./data/stock_industry_list_new.csv", dtype=str)
        self.tscode_to_industry = dict(zip(self.stock_industry_df["ts_code"], self.stock_industry_df["industry"]))
        self.namex_to_industry = dict(zip(self.stock_industry_df["name_x"], self.stock_industry_df["industry"]))

        self.stock_data_df = pd.read_csv("./data/stock_data.csv", dtype=str)
        self.stock_close_dict = {}
        for _, row in self.stock_data_df.iterrows():
            code = row["ts_code"]
            date_str = row["trade_date"]
            close_price = row["close"]
            self.stock_close_dict.setdefault(code, {})[date_str] = close_price

    def _parse_filename_date(self, filename: str) -> Optional[str]:
        match = re.search(r'(\d{4})-(\d{2})-(\d{2})', filename)
        return f"{match.group(1)}{match.group(2)}{match.group(3)}" if match else None

    def _get_previous_trading_close(self, ts_code: str, date_str: str) -> Optional[str]:
        if ts_code not in self.stock_close_dict:
            return None
        try:
            current_dt = datetime.strptime(date_str, "%Y%m%d")
        except ValueError:
            return None
        for _ in range(31):
            ds = current_dt.strftime("%Y%m%d")
            if ds in self.stock_close_dict[ts_code]:
                return self.stock_close_dict[ts_code][ds]
            current_dt -= timedelta(days=1)
        return None

    def _transform_institution(self, raw_institution: str) -> str:
        raw = raw_institution.strip()
        if raw.startswith("高盛"):
            return "高盛国际"
        elif raw.startswith("太平洋"):
            return "太平洋"
        else:
            return raw[:4] if len(raw) >= 4 else raw

    def _parse_institution_from_filename(self, md_filename: str) -> str:
        base_name, _ = os.path.splitext(md_filename)
        idx = base_name.rfind('-')
        raw_inst = base_name[idx + 1:] if idx != -1 else ""
        return self._transform_institution(raw_inst) if raw_inst else "未知机构"

    def _find_unique_md_institution(self, date_str_yyyy_mm_dd: str, company_name: str) -> str:
        folder_path = os.path.join("./data/output", date_str_yyyy_mm_dd)
        if not os.path.isdir(folder_path):
            return ""
        md_files = [f for f in os.listdir(folder_path) if f.endswith(".md") and company_name in f]
        if len(md_files) == 1:
            return self._parse_institution_from_filename(md_files[0])
        return ""

    def _get_exchange_by_ts_code(self, ts_code: str) -> str:
        if not ts_code:
            return "提取错误"
        prefix = ts_code.split('.')[0]
        if prefix.startswith('6'):
            return "上海证券交易所"
        elif prefix.startswith(('0', '3')):
            return "深圳证券交易所"
        else:
            return "北京证券交易所"

    def process_triples(self, json_path: str, output_dir: str):
        filename = os.path.basename(json_path)
        date_compact = self._parse_filename_date(filename)
        if not date_compact:
            logging.info(f"{filename}: The date cannot be parsed, skipping.")
            return

        try:
            file_date = datetime.strptime(date_compact, "%Y%m%d")
        except ValueError:
            logging.info(f"{filename}: Incorrect date format, skipping.")
            return

        if not (self.start_date <= file_date <= self.end_date):
            logging.info(f"{filename}: Not within the scope of processing, skipping.")
            return

        parts = filename.split('-')
        if len(parts) < 4:
            logging.warning(f"{filename}: The file name format does not meet expectations. Skip.")
            return

        company_name = parts[3].strip()

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logging.warning(f"{filename}: JSON Parsing failed – {e}")
            return

        for t in data:
            if t.get("head_entity") != company_name:
                old = t.get("head_entity", "")
                t["head_entity"] = company_name
                logging.info(f"{filename}: head_entity '{old}' -> '{company_name}'")

        relation_map = {}
        for t in data:
            r = t.get("relation", "").strip()
            if r:
                relation_map[r] = t

        basic_rels = ["公司代码: ", "主要交易所: ", "主要行业: ", "当前股价: ", "研报机构"]
        for rel in basic_rels:
            key = rel.strip()
            if key not in relation_map:
                new_t = {
                    "head_entity": company_name,
                    "relation": f" {rel}",
                    "target_entity": ["提取错误"]
                }
                relation_map[key] = new_t
                logging.info(f"{filename}: The '{rel}' is missing. Fill in the blank triple.")

        def get_industry(tsc, cname):
            return self.tscode_to_industry.get(tsc) or self.namex_to_industry.get(cname)

        def get_price(tsc, ds):
            if not tsc:
                return None
            cp = self._get_previous_trading_close(tsc, ds)
            return f"{cp}元" if cp else None

        ts_code_final = None
        date_ymd = file_date.strftime("%Y-%m-%d")

        for rel in basic_rels:
            key = rel.strip()
            obj = relation_map[key]
            vals = obj.get("target_entity") or []
            if isinstance(vals, str):
                vals = [vals]
            first = vals[0].strip() if vals else ""

            if key == "公司代码:":
                if FORCE_UPDATE_FIELDS or not first or first.startswith("提"):
                    code = self.name_to_ts_code.get(company_name)
                    if code:
                        obj["target_entity"] = [code]
                        ts_code_final = code
                        logging.info(f"{filename}: fixing 公司代码 -> {code}")
                    else:
                        obj["target_entity"] = ["提取错误"]
                else:
                    ts_code_final = first
                    obj["target_entity"] = [first]

            elif key == "主要交易所:":
                if FORCE_UPDATE_FIELDS or not first or first.startswith("提"):
                    exch = self._get_exchange_by_ts_code(ts_code_final or self.name_to_ts_code.get(company_name))
                    obj["target_entity"] = [exch]
                    logging.info(f"{filename}: fixing 主要交易所 -> {exch}")
                else:
                    obj["target_entity"] = [first]

            elif key == "主要行业:":
                if FORCE_UPDATE_FIELDS or not first or first.startswith("提"):
                    ind = get_industry(ts_code_final or self.name_to_ts_code.get(company_name), company_name)
                    obj["target_entity"] = [ind or "提取错误"]
                    logging.info(f"{filename}: fixing 主要行业 -> {ind}")
                else:
                    obj["target_entity"] = [first]

            elif key == "当前股价:":
                if FORCE_UPDATE_FIELDS or not first or first.startswith("提"):
                    price = get_price(ts_code_final or self.name_to_ts_code.get(company_name), date_compact)
                    obj["target_entity"] = [price or "提取错误"]
                    logging.info(f"{filename}: fixing 当前股价 -> {price}")
                else:
                    obj["target_entity"] = [first]

            elif key == "研报机构":
                if FORCE_UPDATE_FIELDS or not first or first.startswith("提"):
                    inst = self._find_unique_md_institution(date_ymd, company_name)
                    obj["target_entity"] = [inst or "提取错误"]
                    logging.info(f"{filename}: fixing 研报机构 -> {inst}")
                else:
                    obj["target_entity"] = [first]

        data = list(relation_map.values())
        inst_val = relation_map["研报机构"].get("target_entity", [])
        inst_str = inst_val[1] if len(inst_val) > 1 else inst_val[0] if inst_val else "提取错误"
        inst_str = inst_str.strip() or "提取错误"
        new_fname = f"{parts[0]}-{parts[1]}-{parts[2]}-{company_name}-{inst_str}-triples.json"

        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(output_dir, new_fname)

        with open(out_path, 'w', encoding='utf-8') as fout:
            json.dump(data, fout, ensure_ascii=False, indent=2)

        logging.info(f"{filename}: process successful - {new_fname}")


def main():
    logging.basicConfig(
        filename="process_triples.log",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    processor = TripleProcessor(
        start_date=datetime(2024, 08, 28),
        end_date=datetime(2025, 02, 28)
    )

    input_dir = "./src/stock_attribute"
    output_dir = "./src/stock_attribute_updated"

    logging.info(f"Processing JSON file。Input: {input_dir}，Output: {output_dir}")
    for fname in os.listdir(input_dir):
        if fname.endswith(".json"):
            processor.process_triples(os.path.join(input_dir, fname), output_dir)
    logging.info("All file done。")


if __name__ == "__main__":
    main()