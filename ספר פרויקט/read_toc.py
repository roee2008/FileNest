import os
import re

txt_dir = r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\תשפה_txt'
files = [f for f in os.listdir(txt_dir) if f.endswith('.txt')]

# Analyze the first 3 files' headers
out_lines = []
for file in files[:3]:
    path = os.path.join(txt_dir, file)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        out_lines.append(f"--- {file} ---")
        lines = content.split('\n')
        for line in lines[:200]: # Check first 200 lines for TOC
            if len(line.strip()) > 0 and len(line.strip()) < 50:
                out_lines.append(line.strip())

with open(r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\toc_output.txt', 'w', encoding='utf-8') as out:
    out.write("\n".join(out_lines))
