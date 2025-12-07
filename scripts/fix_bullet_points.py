import os
import re

def fix_bullet_points(file_path):
    """
    Fixes bullet points that appear immediately after:
    1. Bold text without a blank line
    2. Code blocks without a blank line
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Pattern 1: bold text followed immediately by a bullet point (no blank line)
    # Match: **text**\n- bullet
    # Replace with: **text**\n\n- bullet
    pattern1 = r'(\*\*[^*]+\*\*)\n(-\s)'
    content = re.sub(pattern1, r'\1\n\n\2', content)
    
    pattern2 = r'(```)\n(-\s)'
    content = re.sub(pattern2, r'\1\n\n\2', content)
    
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def process_directory(directory):
    """
    Process all .md files in the directory and subdirectories.
    """
    fixed_files = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.md'):
                file_path = os.path.join(root, file)
                if fix_bullet_points(file_path):
                    fixed_files.append(file_path)
    
    return fixed_files

if __name__ == "__main__":
    docs_dir = "docs"
    
    print("🔍 Buscando archivos con bullet points sin espacio...")
    fixed = process_directory(docs_dir)
    
    if fixed:
        print(f"\n✅ Se corrigieron {len(fixed)} archivos:")
        for file in fixed:
            print(f"  - {file}")
    else:
        print("\n✅ No se encontraron archivos que necesiten corrección.")
