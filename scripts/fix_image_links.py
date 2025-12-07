import os
import re
from pathlib import Path
from urllib.parse import quote

DOCS_PATH = Path(__file__).parent.parent / "docs"

def fix_image_links(content):
    """
    Finds standard markdown image links and URL-encodes the path.
    Example: ![](../assets/My Image.png) -> ![](../assets/My%20Image.png)
    """
    def replace_link(match):
        alt_text = match.group(1)
        url = match.group(2)
        
        # Only encode if it looks like a local asset (contains "assets/")
        if "assets/" in url:
            # We want to keep the directory structure but encode the filename
            # or simply encode the whole path but keep slashes.
            # safe='/:' keeps slashes and protocol chars if any (though these are local)
            encoded_url = quote(url, safe="/.")
            if url != encoded_url:
                print(f"    Fixed: {url} -> {encoded_url}")
            return f"![{alt_text}]({encoded_url})"
        return match.group(0)

    # Regex for standard markdown image: ![alt](url)
    pattern = r'!\[(.*?)\]\((.*?)\)'
    return re.sub(pattern, replace_link, content)

def main():
    print("🔧 Scanning for unencoded image links...")
    count = 0
    
    for md_file in DOCS_PATH.rglob("*.md"):
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        new_content = fix_image_links(content)
        
        if content != new_content:
            with open(md_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"✅ Updated: {md_file.name}")
            count += 1
            
    print(f"\n✨ Done! Fixed links in {count} files.")

if __name__ == "__main__":
    main()
