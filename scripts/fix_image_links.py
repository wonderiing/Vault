import os
import re
from pathlib import Path
from urllib.parse import quote, unquote

DOCS_PATH = Path(__file__).parent.parent / "docs"

def fix_image_links(content):
    """
    Finds standard markdown image links and fixes URL encoding.
    Decodes any existing encoding first (including double encoding), then re-encodes properly.
    Example: ![](assets/Pasted%2520image.png) -> ![](assets/Pasted%20image.png)
    """
    def replace_link(match):
        alt_text = match.group(1)
        url = match.group(2)
        
        # Only process if it looks like a local asset (contains "assets/")
        if "assets/" in url:
            # Fix incorrect relative path from previous script version
            # Change ../assets/ to assets/ if present
            clean_url = url.replace("../assets/", "assets/")
            
            # IMPORTANT: Fully decode by calling unquote repeatedly until no more changes
            # This handles double encoding: %2520 -> %20 -> space
            decoded_url = clean_url
            while True:
                new_decoded = unquote(decoded_url)
                if new_decoded == decoded_url:
                    break  # No more decoding possible
                decoded_url = new_decoded
            
            # Now encode properly (only once)
            # safe="/" preserves the path separator
            encoded_url = quote(decoded_url, safe="/")
            
            if url != encoded_url:
                print(f"    Fixed: {url} -> {encoded_url}")
            return f"![{alt_text}]({encoded_url})"
        return match.group(0)

    # Regex for standard markdown image: ![alt](url)
    pattern = r'!\[(.*?)\]\((.*?)\)'
    return re.sub(pattern, replace_link, content)

def main():
    print("Scanning for image links with incorrect encoding...")
    count = 0
    
    for md_file in DOCS_PATH.rglob("*.md"):
        print(f"Processing: {md_file.name}")
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        new_content = fix_image_links(content)
        
        if content != new_content:
            with open(md_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"[OK] Updated: {md_file.name}")
            count += 1
        else:
            print(f"  No changes needed")
            
    print(f"\nDone! Fixed links in {count} files.")

if __name__ == "__main__":
    main()
