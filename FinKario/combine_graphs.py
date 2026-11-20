import os
import json

tuples_dir = "./src/stock_attribute_updated"
event_dir = "./src/stock_event"

finkg_dir = "./src/finkg"

os.makedirs(finkg_dir, exist_ok=True)

def extract_key(filename: str) -> str:

    name, _ = os.path.splitext(filename)
    parts = name.split('-')
    if len(parts) < 5:
        return None
    return "-".join(parts[:5])


tuple_data = {}  
for fname in os.listdir(tuples_dir):
    if not fname.endswith(".json"):
        continue
    key = extract_key(fname)
    if not key:
        continue
    file_path = os.path.join(tuples_dir, fname)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            
            if key in tuple_data:
                tuple_data[key].extend(data)
            else:
                tuple_data[key] = data
    except Exception as e:
        print(f"Error occurred while reading the tuple file {fname}: {e}")


event_data = {}  
for fname in os.listdir(event_dir):
    if not fname.endswith(".json"):
        continue
    key = extract_key(fname)
    if not key:
        continue
    file_path = os.path.join(event_dir, fname)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            if key in event_data:
                event_data[key].extend(data)
            else:
                event_data[key] = data
    except Exception as e:
        print(f"Error occurred while reading the event file {fname}: {e}")

merged_count = 0

for key, t_data in tuple_data.items():
    if key not in event_data:
        continue
    c_data = event_data[key]

    company_name = "未知公司"
    if len(t_data) > 0 and isinstance(t_data[0], dict):
        company_name = t_data[0].get("head_entity", "未知公司")

    merged_event = {}
    for i, event in enumerate(c_data, start=1):
        if "entities" in event and "公司" in event["entities"]:
            del event["entities"]["公司"]
        merged_event[f"事件{i}"] = event

    merged_structure = {
        "key": key,
        "company": company_name,
        "attributes": t_data,           
        "events": merged_event  
    }

    out_filename = f"{key}-finkg.json"
    out_path = os.path.join(finkg_dir, out_filename)

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(merged_structure, f, ensure_ascii=False, indent=2)
        merged_count += 1
    except Exception as e:
        print(f"An error occurred while saving the merged result to {out_filename}: {e}")

print(f"Successfully merged and output {merged_count} files to {finkg_dir}")


