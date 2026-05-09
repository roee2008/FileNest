import PyPDF2
import os

pdf_dir = r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\תשפה'
txt_dir = r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\תשפה_txt'

if not os.path.exists(txt_dir):
    os.makedirs(txt_dir)

files = [f for f in os.listdir(pdf_dir) if f.endswith('.pdf')]
print(f"Found {len(files)} PDFs. Starting conversion...")

for file in files:
    pdf_path = os.path.join(pdf_dir, file)
    txt_filename = file.replace('.pdf', '.txt')
    txt_path = os.path.join(txt_dir, txt_filename)
    
    try:
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            text = ''
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + '\n'
        
        with open(txt_path, 'w', encoding='utf-8') as out:
            out.write(text)
    except Exception as e:
        pass

print("All conversions finished.")
