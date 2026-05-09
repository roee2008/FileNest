import PyPDF2
import os

pdf_dir = r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\תשפה'
files = [f for f in os.listdir(pdf_dir) if f.endswith('.pdf')]
total_words = 0
examples_data = []

for file in files:
    pdf_path = os.path.join(pdf_dir, file)
    try:
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            text = ''
            # Extract first 5 pages of each to analyze structure, and count pages
            for i in range(min(5, len(reader.pages))):
                text += reader.pages[i].extract_text() + '\n'
            examples_data.append(f"{file} - Pages: {len(reader.pages)}")
    except Exception as e:
        examples_data.append(f"{file} - Error: {e}")

with open(r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\examples_summary.txt', 'w', encoding='utf-8') as out:
    out.write("\n".join(examples_data))
