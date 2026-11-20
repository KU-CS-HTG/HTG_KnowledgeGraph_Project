import re

def clean_markdown_content(content):

    removal_keywords = [
        r"证券分析师\b",  
        r"目录\b",
        r"图表目录\b",
    ]

    declaration_keywords = [
        r"声明$", 
        r"承诺$", 
        r"免责$",
    ]

    lines = content.split('\n')
    cleaned_lines = []
    remove_remaining_content = False  
    skip_section = False  

    for i, line in enumerate(lines):
        if remove_remaining_content:
            break  

        if re.match(r'^!\[.*\]\(images/.*\)', line):
            continue

        header_match = re.match(r'^(#+)\s*(.*)', line)
        if header_match:
            header_text = header_match.group(2).strip()

            if any(re.search(kw, header_text) for kw in declaration_keywords):
                remove_remaining_content = True
                break  

            if any(re.search(kw, header_text) for kw in removal_keywords):
                skip_section = True  
                continue  
            
            if skip_section:
                skip_section = False

        if skip_section:
            continue

        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)

def read_markdown_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        raw_content = file.read()
        return clean_markdown_content(raw_content)


