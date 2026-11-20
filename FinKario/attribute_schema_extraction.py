import openai
import os
import re
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--api_base", required=True)
parser.add_argument("--api_key",  required=True)
args, unknown = parser.parse_known_args()
os.environ["OPENAI_API_BASE"] = args.api_base
os.environ["OPENAI_API_KEY"]  = args.api_key

openai.api_key = os.getenv("OPENAI_API_KEY")
openai.api_base = os.getenv("OPENAI_API_BASE")

def extract_entities(text):
    prompt = '''
    # 指令：
    - 请作为一名有经验的信息提取专家。
    - 你将从金融研究报告的段落中提取关键信息，包括：公司评级、风险评估、主要产品等。
    - 如果某些信息缺失，请将其留空。
    - 明确排除分析师、证券公司实体，仅保留公司核心属性（如评级直接绑定到公司）。
    - 分模块提取产品、风险等数据，避免字段混杂。
    - 强制要求数值带单位（如"亿元"%"），避免歧义。
    ''' + "\n" + text
    
    try:

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000,
            temperature=0,
            top_p=1,        
            n=1
        )
        
        if 'choices' in response and len(response['choices']) > 0:
            entities = response['choices'][0]['message']['content']
            return entities
        else:
            return None
    except Exception as e:
        print(f"Error during entity extraction: {str(e)}")
        return None
    
def clean_entities(text):
    cleaned_text = re.sub(r'### .*\n', '', text)
    cleaned_text = re.sub(r'\*\*(.*?)\*\*', r'\1', cleaned_text)
    # cleaned_text = re.sub(r'^\s*-?\s*(.*?)\s*$', r'\1', cleaned_text, flags=re.MULTILINE)
    cleaned_text = "- 公司名称:\n" + cleaned_text
    cleaned_text = re.sub(r'\n\s*\n+', '\n', cleaned_text)
    cleaned_text = cleaned_text + "\n- 研报机构:"
    return cleaned_text


# Extract schema from CFA/JP Morgan template
def extract_basic_information(md_content):
    lines = md_content.split('\n')
    start_flag = "# BASIC INFORMATION"
    end_flag = "# "

    start_index = -1
    for i, line in enumerate(lines):
        if line.strip() == start_flag:
            start_index = i
            break
    if start_index == -1:
        return ""

    content = []
    for line in lines[start_index + 1:]:
        if line.startswith(end_flag) and len(line.strip()) > 1:  
            break
        content.append(line)
    
    while content and content[-1].strip() == '':
        content.pop()
    return '\n'.join(content).strip()

