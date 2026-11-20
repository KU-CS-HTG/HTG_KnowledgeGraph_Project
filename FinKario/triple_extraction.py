import json
import os
import re

def _parse_price_str(price_str: str):
    """
    尝试从字符串中提取浮点数:
    - 去掉“元”等字符
    - 去掉逗号
    - 如果解析失败就返回 None
    """
    try:
        s = price_str.strip()
        s = s.replace('元', '')
        s = s.replace(',', '')
        s = re.sub(r'[^\d\.]', '', s)  
        return float(s)
    except:
        return None

def extract_triples(stock_entities):
    triples = []

    company_name = stock_entities.get("- 公司名称:", ["未找到相关信息"])[0]
    print(company_name)
    
    current_stock_price = stock_entities.get("- 当前股价:", ["未找到相关信息"])
    if current_stock_price and len(current_stock_price) > 1:
        current_stock_price = current_stock_price[0]
    else:
        current_stock_price = current_stock_price[0] if current_stock_price else "未找到相关信息"

    for label, values in stock_entities.items():
        if label == "- 公司名称:":
            continue
        
        if values == ["未找到相关信息"] or not values:
            continue

        if label.strip() == "- 目标股价:":
            target_price_str = values[0] if isinstance(values, list) and values else ""

            if target_price_str == current_stock_price:
                continue

            target_val = _parse_price_str(target_price_str)
            current_val = _parse_price_str(current_stock_price)
            if target_val is not None and current_val is not None and target_val <= current_val:
                continue
        
 
        triples.append({
            "head_entity": company_name,
            "relation": label.strip(":-"),  
            "target_entity": values
        })

    return triples

def save_triples_as_json(triples, company_info, file_path):
    try:

        if not os.path.exists(file_path):
            os.makedirs(file_path)

        if not isinstance(triples, list):
            raise ValueError("triples must be a list")

        file_name = f"{file_path}/{company_info}-triples.json"
        with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(triples, f, ensure_ascii=False, indent=4)

        print(f"Triples saved to {file_name}")

    except Exception as e:
        print(f"Error saving triples to JSON: {str(e)}")
