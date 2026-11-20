import os
import re
import json
import openai
import pandas as pd
import argparse
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict
from triple_extraction import extract_triples, save_triples_as_json
from attribute_schema_extraction import extract_entities, clean_entities, extract_basic_information
from markdown_opt import read_markdown_file



parser = argparse.ArgumentParser()
parser.add_argument("--api_base", required=True)
parser.add_argument("--api_key",  required=True)
args, unknown = parser.parse_known_args()
os.environ["OPENAI_API_BASE"] = args.api_base
os.environ["OPENAI_API_KEY"]  = args.api_key

openai.api_key = os.getenv("OPENAI_API_KEY")
openai.api_base = os.getenv("OPENAI_API_BASE")

CACHE_FILE_PATH = "./entity_labels_cache.json"

@dataclass
class StockEntity:
    label: str
    entities: List[str]

@dataclass
class ReportMetadata:
    filename: str
    trade_date: str
    company_name: str
    ts_code: str = ""

class EntityParser:
    def __init__(self, model="gpt-3.5-turbo"):
        self.model = model

    def extract(self, markdown_text: str, label: str) -> StockEntity:
        prompt = f'''
        # 指令：
        - 请作为一名有经验的信息提取专家，提取股票研报中的关键信息。
        - 你将从以下内容中识别与【{label}】相关的实体，并只返回实体名称。
        - 如果相关实体存在，请返回它的实体名称；如果未找到相关实体，请返回 "未找到相关信息"。
        - 输出格式要求如下：
        {{
            "label": "{label}",
            "entities": [
            "实体名称1",
            "实体名称2",
            ...
            ]
        }}
        - 研报中的公司代码应该根据其交易所进行识别：
            - 公司代码以"0"或"3"开头：属于深圳证券交易所，主要交易所填"深圳证券交易所"。
            - 公司代码以"6"开头：属于上海证券交易所，主要交易所填"上海证券交易所"。
            - 公司代码以"8"开头：属于北京证券交易所，主要交易所填"北京证券交易所"。

        - 对于公司代码，请按照以下规则补充：
            - "0"或"3"开头的公司：公司代码结尾补上".SZ"（如：`000001` → `000001.SZ` 或 `300001` → `300001.SZ`）。
            - "6"开头的公司：公司代码结尾补上".SH"（如：`600001` → `600001.SH`）。
            - "8"开头的公司：公司代码结尾补上".BJ"（如：`800001` → `800001.BJ`）。

        - 对于实体公司名称，识别缩写即可，不需要全称。
        - 对于实体，研报机构，以"证券"结尾，不予考虑多余的部分。（如：`中信证券研究所` → `中信证券`）。
        - 对于实体如：目标股价、当前股价、主要股东等，如检索不到该信息，请不要编造，请返回 "未找到相关信息"。
        - 对于实体如：市值、当前股价、目标股价、流动性、浮动股数等实体，需要考虑并包含该数值所在上下文的单位，（如"亿元，百万元"%"），避免歧义。
        - 如果无法识别某类实体或未找到相关信息，请返回 "未找到相关信息"。
        - 以下是研报内容，请提取其中的关键信息：
        ''' + "\n" + markdown_text

        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0
            )
            data = response["choices"][0]["message"]["content"]
            parsed = json.loads(data)
            return StockEntity(label=parsed["label"], entities=parsed["entities"])
        except Exception as e:
            print(f"Error extracting label {label}: {e}")
            return StockEntity(label=label, entities=["提取错误"])

class ReportProcessor:
    def __init__(self, stock_map, price_map, industry_path):
        self.stock_map = stock_map
        self.price_map = price_map
        self.industry_df = pd.read_csv(industry_path)

    def process(self, file_path: str, label_entities: List[str]) -> List[Dict]:
        metadata = self._parse_filename(file_path)
        content = read_markdown_file(file_path)
        parser = EntityParser()
        results = {}
        for label in label_entities:
            result = parser.extract(content, label)
            results[result.label] = result.entities
        results = self._assign_industry(results, metadata)
        results = self._assign_price(results, metadata)
        return extract_triples(results)

    def _parse_filename(self, path: str) -> ReportMetadata:
        name = os.path.basename(path).replace(".md", "")
        parts = name.split("-")
        return ReportMetadata(
            filename=name,
            trade_date="-".join(parts[:3]),
            company_name=parts[3]
        )

    def _assign_industry(self, entities: Dict, meta: ReportMetadata):
        code = None
        for k in entities:
            if "公司代码" in k:
                code = entities[k][0]
                break
        name = None
        for k in entities:
            if "公司名称" in k:
                name = entities[k][0]
                break
        match = self.industry_df[self.industry_df.ts_code == code] if code else self.industry_df[self.industry_df.name == name]
        industry = match.iloc[0]['industry'] if not match.empty else "未找到相关信息"
        key_to_update = None
        for k in entities:
            if "主要行业" in k:
                key_to_update = k
                break
        if key_to_update:
            entities[key_to_update] = [industry]
        else:
            entities['- 主要行业:'] = [industry]
        return entities

    def _assign_price(self, entities: Dict, meta: ReportMetadata):
        ts_code = None
        for k in entities:
            if "公司代码" in k:
                ts_code = entities[k][0]
                break
        if not ts_code:
            ts_code = self.stock_map.get(meta.company_name)
        trade_date = meta.trade_date
        price = self.price_map.get((ts_code, trade_date), "未找到相关信息")
        price_str = f"{price}元" if isinstance(price, (int, float)) else price
        key_to_update = None
        for k in entities:
            if "当前股价" in k:
                key_to_update = k
                break
        if key_to_update:
            entities[key_to_update] = [price_str]
        else:
            entities['- 当前股价:'] = [price_str]
        return entities

def load_stock_mappings(csv_path):
    df = pd.read_csv(csv_path)
    return dict(zip(df["name"].str.strip(), df["ts_code"].str.strip()))

def load_stock_prices(csv_path):
    df = pd.read_csv(csv_path)
    df["trade_date"] = pd.to_datetime(df["trade_date"], format='%Y%m%d').dt.strftime('%Y-%m-%d')
    return df.set_index(["ts_code", "trade_date"])["close"].to_dict()

def get_labels(template_path):
    if os.path.exists(CACHE_FILE_PATH):
        with open(CACHE_FILE_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("labels", "")
    section = extract_basic_information(read_markdown_file(template_path))
    labels = clean_entities(extract_entities(section))
    with open(CACHE_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump({"labels": labels}, f, ensure_ascii=False, indent=4)
    return labels

def run_pipeline(start_date, end_date, labels, industry_path, stock_map, price_map, input_dir, output_dir):
    s_date = datetime.strptime(start_date, "%Y-%m-%d")
    e_date = datetime.strptime(end_date, "%Y-%m-%d")
    processor = ReportProcessor(stock_map, price_map, industry_path)
    for folder in sorted(os.listdir(input_dir)):
        folder_path = os.path.join(input_dir, folder)
        if not os.path.isdir(folder_path):
            continue
        folder_date = datetime.strptime(folder, "%Y-%m-%d")
        if not (s_date <= folder_date <= e_date):
            continue
        for file in os.listdir(folder_path):
            if not file.endswith(".md"):
                continue
            path = os.path.join(folder_path, file)
            print(f"Processing: {path}")
            triples = processor.process(path, labels)
            identifier = "-".join(file.split('-')[:4])
            save_triples_as_json(triples, identifier, output_dir)

if __name__ == '__main__':
    template_file = "./data/rc-equity-research-report-essentials-4.md"
    industry_file = "./data/Stock_industry_grouped_w_code.csv"
    stock_map_file = "./data/Stock_report_List_new.csv"
    price_file = "./data/stock_data.csv"
    input_dir = "./data/output/"
    output_dir = "./src/stock_attribute"
    labels = get_labels(template_file)
    stock_map = load_stock_mappings(stock_map_file)
    price_map = load_stock_prices(price_file)
    for start_date, end_date in [("2024-08-28", "2025-03-28")]: # your data range / default
        run_pipeline(start_date, end_date, labels.split('\n'), industry_file, stock_map, price_map, input_dir, output_dir)
