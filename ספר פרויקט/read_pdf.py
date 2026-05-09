import PyPDF2
with open(r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\פורמט לספר פרויקט.pdf', 'rb') as f:
    reader = PyPDF2.PdfReader(f)
    text = ''
    for page in reader.pages:
        text += page.extract_text() + '\n'
with open(r'c:\Users\Roee4\OneDrive\מסמכים\GitHub\FileNet\ספר פרויקט\pdf_text.txt', 'w', encoding='utf-8') as out:
    out.write(text)
