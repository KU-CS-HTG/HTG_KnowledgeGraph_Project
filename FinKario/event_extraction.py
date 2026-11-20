import openai
import re
import json
from typing import List, Dict
import os
import csv
from datetime import datetime
import yaml
import logging
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--api_base", required=True)
parser.add_argument("--api_key",  required=True)
args, unknown = parser.parse_known_args()
os.environ["OPENAI_API_BASE"] = args.api_base
os.environ["OPENAI_API_KEY"]  = args.api_key

openai.api_key = os.getenv("OPENAI_API_KEY")
openai.api_base = os.getenv("OPENAI_API_BASE")


def extract_company_name(md_file: str) -> str:

    filename = os.path.basename(md_file)
    parts = filename.split("-")
    if len(parts) >= 4:
        company = parts[3]
        company = company.split(".")[0]
        return company
    return "公司"

def extract_main_content(text: str) -> str:

    risk_keywords = ["风险提示", "险提示", "风险因素", "示：", "# Stock Data", "评级面临的主要风险", "投资风险", "主要下行风险", "主要风险", "提示：", "# 风险"]
    lines = text.splitlines()
    collected_lines = []
    for line in lines:
        if any(kw in line for kw in risk_keywords):
            break
        collected_lines.append(line)
    return "\n".join(collected_lines).strip()


def preprocess_text(md_text: str) -> str:
    clean_text = re.sub(r'<table[\s\S]*?</table>', '', md_text, flags=re.IGNORECASE)
    clean_text = re.sub(r'<[^>]+>', '', clean_text)
    clean_text = re.sub(r'!\[.*?\]\(.*?\)', '', clean_text)
    return clean_text.strip()

def is_valid_paragraph(paragraph: str) -> bool:
    if "《" in paragraph and "》" in paragraph:
        return False
    if re.match(r'^[\d\s年月日\.]+$', paragraph):
        return False
    return len(paragraph) > 15

def split_paragraphs(text: str) -> List[str]:
    paragraphs = text.split('\n')
    valid_paragraphs = [p.strip() for p in paragraphs if is_valid_paragraph(p.strip())]
    return valid_paragraphs


DRIVER_CATEGORIES_PATH = "./driven_categories.yaml"

DESC_MAP = {}
REF_MAP = {}

try:
    with open(DRIVER_CATEGORIES_PATH, "r", encoding="utf-8") as f:
        categories_data = yaml.safe_load(f)
    raw_cats = categories_data.get("event-driven categories", [])
    if not raw_cats or not isinstance(raw_cats, list):
        raise ValueError("No categories are defined in the 'driven_categories.yaml' file. Please check the file content.") 
    DRIVER_CATEGORIES = [item["name"] for item in raw_cats]
    DESC_MAP = {item["name"]: item.get("desc", "") for item in raw_cats}
    REF_MAP = {item["name"]: item.get("fibo_reference", "") for item in raw_cats}
    logging.info(f"Loaded {len(DRIVER_CATEGORIES)} driven categories from YAML.")
except Exception as e:
    logging.error(f"Failed to load driven_categories.yaml: {e}")
    raise


def analyze_event(paragraph: str) -> Dict:

    categories_info = "\n".join(f"- {name}: {DESC_MAP.get(name, '')}\n {REF_MAP.get(name, '')}" for name in DRIVER_CATEGORIES)


    prompt = f"""
    请从以下中文段落中提取公司事件，按JSON格式返回结果：
    要求：
    1. 识别事件因果关系中的原因(cause)和结果(effect)部分，输出符合逻辑的关系。
    2. 提取涉及的实体（公司、产品、指标）
    3. 标注时间范围（如有）
    4. 提示：请忽略不具备因果关系的段落，并详细标明推理依据
    5. 因果关系围绕公司展开，如果因果事件里面没出现公司名称，可以推断是否与公司有关，与非公司参与的entity不要考虑
    6. driver_category 字段 **必须** 从以下选项中选择：{categories_info}


    示例输入1:"由于原厂减产推动存储价格上涨，德明利2023Q4净利润环比增长500%"
    示例输出1:
    {{
        "cause": "原厂减产",
        "effect": "存储价格上涨",
        "entities": {{
            "公司": ["德明利"],
            "产品": ["存储"],
            "指标": ["净利润"]
        }},
        "timeframe": "2023Q4",
        "confidence": 0.9,
        "reasoning": "因为原厂减产是导致存储价格上涨的直接因素，德明利净利润增长500%与此相关"
        "driver_category": "Supply"
    }}


    当前分析段落："{paragraph}"
    """

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        top_p=1,
        max_tokens=500
    )
    try:
        result = json.loads(response.choices[0].message.content)
        if not result.get('cause') or not result.get('effect') or result.get('confidence', 0) == 0:
            return None
        return result
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON"}


def substitute_company(result: Dict, company: str) -> Dict:

    for field in ["cause", "effect", "reasoning"]:
        if field in result and result[field]:
            value = result[field]
            if isinstance(value, list):
                value = "，".join(str(v) for v in value)
            elif not isinstance(value, str):
                value = str(value)
            value = value.replace("公司", company)
            result[field] = value
    
    if "entities" in result:
        result["entities"]["公司"] = [company]
    
    return result


def build_knowledge_graph(md_file: str) -> List[Dict]:
    real_company = extract_company_name(md_file)
    with open(md_file, 'r', encoding='utf-8') as f:
        raw_text = f.read()
    raw_text = extract_main_content(raw_text)
    clean_text = preprocess_text(raw_text)
    paragraphs = split_paragraphs(clean_text)
    knowledge_graph = []
    for idx, paragraph in enumerate(paragraphs[:50]):
        print(f"Processing paragraph {idx+1}/{len(paragraphs)}: {paragraph[:50]}...")
        result = analyze_event(paragraph)
        if result is not None and "error" not in result:
            result = substitute_company(result, real_company)
            result["source_paragraph"] = paragraph
            knowledge_graph.append(result)
    return knowledge_graph


def get_agency_prefix_len(agency: str) -> int:
    agency = agency.strip()
    if agency.startswith("高盛"):
        return 2
    elif agency.startswith("太平洋"):
        return 3
    else:
        return 4

def parse_date_from_filename(fname: str) -> datetime:

    parts = fname.split('-')
    if len(parts) < 3:
        return datetime.min
    date_str = f"{parts[0]}-{parts[1]}-{parts[2]}"
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return datetime.min

def find_md_file_for_agency(date_str: str, stock: str, agency: str) -> str:

    base_dir = "./data/output"
    date_dir = os.path.join(base_dir, date_str)
    if not os.path.isdir(date_dir):
        return ""
    
    prefix_len = get_agency_prefix_len(agency)
    agency_prefix = agency[:prefix_len]
    
    candidates = []
    for fname in os.listdir(date_dir):
        if not fname.endswith(".md"):
            continue
        if stock not in fname:
            continue
        md_no_ext = os.path.splitext(fname)[0]
        last_part = md_no_ext.split('-')[-1]
        if last_part.startswith(agency_prefix):
            candidates.append(os.path.join(date_dir, fname))
    if candidates:
        return candidates[0]
    
    alt_candidates = [f for f in os.listdir(date_dir) if f.endswith(".md") and (stock in f)]
    if len(alt_candidates) == 1:
        return os.path.join(date_dir, alt_candidates[0])
    return ""



def main_process(start_date: datetime, end_date: datetime):

    stock_tuples_dir = "./src/stock_attribute_updated"
    output_event_dir = "./src/stock_event"
    log_path = "./src/event_analysis_log.csv"

    if not os.path.exists(output_event_dir):
        os.makedirs(output_event_dir)
    

    all_files = [f for f in os.listdir(stock_tuples_dir) if f.endswith("-triples.json")]
    def file_in_range(fname: str) -> bool:
        file_date = parse_date_from_filename(fname) 
        return (file_date >= start_date) and (file_date <= end_date)
    
    filtered_files = [f for f in all_files if file_in_range(f)]
    filtered_files.sort(key=parse_date_from_filename)
    
    log_entries = []
    for fname in filtered_files:
        parts = fname.split('-')
        if len(parts) < 6:
            continue
        date_str = f"{parts[0]}-{parts[1]}-{parts[2]}"  
        company = parts[3].strip()
        agency = parts[4].strip()
        
        out_name = f"{date_str}-{company}-{agency}-event_graph.json"
        out_path = os.path.join(output_event_dir, out_name)
        
        if os.path.exists(out_path):
            print(f"[INFO] The output file {out_name} already exists, so it will be skipped.") 
            log_entries.append({
                "date": date_str,
                "company": company,
                "agency": agency,
                "md_file": "",
                "status": "skipped",
                "event_count": 0
            })
            continue
        
        md_file = find_md_file_for_agency(date_str, company, agency)
        if not md_file:
            print(f"Could not find the corresponding .md file for {date_str}-{company}-{agency}. Skipping this step.")
            log_entries.append({
                "date": date_str,
                "company": company,
                "agency": agency,
                "md_file": "",
                "status": "no_md_found",
                "event_count": 0
            })
            continue
        
        print(f"[INFO] Processing: {md_file} => {date_str}-{company}-{agency}")
        event_graph = build_knowledge_graph(md_file)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(event_graph, f, ensure_ascii=False, indent=2)
        print(f"[INFO] Extracted {len(event_graph)} events. Saved to: {out_path}")
        log_entries.append({
            "date": date_str,
            "company": company,
            "agency": agency,
            "md_file": md_file,
            "status": "done",
            "event_count": len(event_graph)
        })
    
    if log_entries:
        fieldnames = ["date", "company", "agency", "md_file", "status", "event_count"]
        with open(log_path, 'a', newline='', encoding='utf-8') as lf:
            writer = csv.DictWriter(lf, fieldnames=fieldnames)
            writer.writerows(log_entries)
        print(f"[INFO] Log processing has been appended and saved to: {log_path}")
    else:
        print("[INFO] No files were processed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # set your date range 
    parser.add_argument("--start_date", type=str, default="2024-08-28",
                        help="start_date，YYYY-MM-DD")
    parser.add_argument("--end_date", type=str, default="2025-02-28",
                        help="end_date，YYYY-MM-DD")
    args, unknown = parser.parse_known_args()
    start_dt = datetime.strptime(args.start_date, "%Y-%m-%d")
    end_dt = datetime.strptime(args.end_date, "%Y-%m-%d")
    
    main_process(start_dt, end_dt)

