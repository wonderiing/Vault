"""
Script para sincronizar notas de CTFs desde el repositorio de notas a este proyecto web.
Convierte sintaxis de Obsidian a MkDocs Material.
"""

import os
import re
import shutil
from pathlib import Path
from urllib.parse import quote

from PIL import Image, ImageOps

# Configuración
NOTES_REPO_PATH = r"c:\NOTAS-PROGRA-V1\NOTAS-PROGRA\CiberSeguridad\CTFs"
DOCS_PATH = Path(__file__).parent.parent / "docs"
WEBP_SOURCE_EXTENSIONS = {".png", ".jpg", ".jpeg"}

# Mapeo de callouts de Obsidian a admonitions de MkDocs
CALLOUT_MAPPING = {
    "note": "note",
    "abstract": "abstract",
    "info": "info",
    "tip": "tip",
    "success": "success",
    "question": "question",
    "warning": "warning",
    "failure": "failure",
    "danger": "danger",
    "bug": "bug",
    "example": "example",
    "quote": "quote",
    "todo": "todo",
}


def convert_obsidian_images(content, relative_path):
    """
    Convierte sintaxis de imágenes de Obsidian a Markdown estándar.
    ![[imagen.png]] -> ![](../assets/imagen.png)
    """
    def replace_image(match):
        image_name = match.group(1)
        image_path = Path(image_name)
        if image_path.suffix.lower() in WEBP_SOURCE_EXTENSIONS:
            image_name = str(image_path.with_suffix(".webp"))
        # The assets are in the same directory as the markdown file (in 'assets' subdir)
        # So we don't need relative path calculation like ../
        
        # URL encode the image name to handle spaces
        encoded_name = quote(image_name)
        return f"![](assets/{encoded_name})"
    
    pattern = r'!\[\[([^\]]+\.(png|jpg|jpeg|gif|webp))\]\]'
    return re.sub(pattern, replace_image, content, flags=re.IGNORECASE)


def copy_asset(asset_file, dest_assets):
    if asset_file.suffix.lower() in WEBP_SOURCE_EXTENSIONS:
        dest_asset = dest_assets / asset_file.with_suffix(".webp").name
        if dest_asset.exists():
            return False

        with Image.open(asset_file) as image:
            image = ImageOps.exif_transpose(image)
            if image.mode not in ("RGB", "RGBA"):
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            image.save(dest_asset, "WEBP", quality=82, method=6)
        return True

    dest_asset = dest_assets / asset_file.name
    if dest_asset.exists():
        return False

    shutil.copy2(asset_file, dest_asset)
    return True


def convert_obsidian_callouts(content):
    """
    Convierte callouts de Obsidian a admonitions de MkDocs.
    > [!note] Título -> !!! note "Título"
    """
    lines = content.split('\n')
    result = []
    in_callout = False
    callout_type = None
    
    for line in lines:
        # Detectar inicio de callout
        callout_match = re.match(r'^>\s*\[!(\w+)\]\s*(.*)', line)
        if callout_match:
            callout_type = callout_match.group(1).lower()
            title = callout_match.group(2).strip()
            
            # Mapear el tipo de callout
            admonition_type = CALLOUT_MAPPING.get(callout_type, "note")
            
            if title:
                result.append(f'!!! {admonition_type} "{title}"')
            else:
                result.append(f'!!! {admonition_type}')
            in_callout = True
        # Continuar callout
        elif in_callout and line.startswith('>'):
            content_line = line[1:].strip()
            if content_line:
                result.append(f'    {content_line}')
            else:
                result.append('')
        # Fin de callout
        else:
            if in_callout:
                in_callout = False
            result.append(line)
    
    return '\n'.join(result)


def process_markdown_file(file_path, relative_path):
    """
    Procesa un archivo Markdown: convierte sintaxis de Obsidian a MkDocs.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Convertir imágenes
    content = convert_obsidian_images(content, relative_path)
    
    # Convertir callouts
    content = convert_obsidian_callouts(content)
    
    return content


def sync_notes():
    """
    Sincroniza las notas desde el repositorio de CTFs al directorio docs.
    Solo copia archivos nuevos que no existan en el destino.
    """
    print("🔄 Sincronizando notas de CTFs (solo archivos nuevos)...")
    
    # Crear directorio docs si no existe
    if not DOCS_PATH.exists():
        DOCS_PATH.mkdir(parents=True)
    
    notes_path = Path(NOTES_REPO_PATH)
    
    # Copiar y procesar archivos por categoría
    categories = ["DockerLabs", "HackTheBox", "HackMyVm", "TheHackerLabs"]
    
    for category in categories:
        category_path = notes_path / category
        if not category_path.exists():
            print(f"⚠️  Categoría {category} no encontrada")
            continue
        
        # Crear directorio de categoría en docs
        docs_category_path = DOCS_PATH / category
        docs_category_path.mkdir(exist_ok=True)
        
        # Crear index.md para la categoría si no existe
        category_index = docs_category_path / "index.md"
        if not category_index.exists():
            with open(category_index, 'w', encoding='utf-8') as f:
                f.write(f"# {category}\n\n")
                f.write(f"Write-ups de máquinas de {category}.\n\n")
            print(f"📝 Creado index.md para {category}")
        
        # Copiar archivos .md solo si no existen
        md_files = list(category_path.glob("*.md"))
        new_files = 0
        existing_files = 0
        
        for md_file in md_files:
            dest_file = docs_category_path / md_file.name
            
            # Solo copiar si NO existe
            if not dest_file.exists():
                relative_path = f"{category}/{md_file.name}"
                processed_content = process_markdown_file(md_file, relative_path)
                
                with open(dest_file, 'w', encoding='utf-8') as f:
                    f.write(processed_content)
                new_files += 1
                print(f"  ✨ Nuevo: {md_file.name}")
            else:
                existing_files += 1
        
        print(f"📁 {category}: {new_files} nuevos, {existing_files} ya existentes")
        
        # Copiar carpeta assets si existe (solo archivos nuevos)
        assets_path = category_path / "assets"
        if assets_path.exists():
            dest_assets = docs_category_path / "assets"
            dest_assets.mkdir(exist_ok=True)
            
            new_assets = 0
            existing_assets = 0
            
            for asset_file in assets_path.glob("*"):
                if asset_file.is_file():
                    if copy_asset(asset_file, dest_assets):
                        new_assets += 1
                        print(f"  🖼️  Nuevo asset: {asset_file.name}")
                    else:
                        existing_assets += 1
            
            if new_assets > 0 or existing_assets > 0:
                print(f"🖼️  {category}/assets: {new_assets} nuevos, {existing_assets} ya existentes")
    
    print("✅ Sincronización completada!")


if __name__ == "__main__":
    sync_notes()
