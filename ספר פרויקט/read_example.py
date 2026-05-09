import PyPDF2
import os

pdf_dir = r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\תשפה'
files = [f for f in os.listdir(pdf_dir) if f.endswith('.pdf')]
if not files:
    print("No PDFs found")
else:
    # Pick the first one
    pdf_path = os.path.join(pdf_dir, files[0])
    with open(pdf_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        text = ''
        # Just extract first 10 pages to get a feel
        for i in range(min(15, len(reader.pages))):
            text += reader.pages[i].extract_text() + '\n'
    with open(r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\example1.txt', 'w', encoding='utf-8') as out:
        out.write(text)
    print("Saved first 15 pages of", files[0])
