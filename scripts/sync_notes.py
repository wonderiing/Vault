"""
Script para sincronizar notas de CTFs desde el repositorio de notas a este proyecto web.
Convierte sintaxis de Obsidian a MkDocs Material.
"""

import os
import re
import shutil
from pathlib import Path

# Configuración
NOTES_REPO_PATH = r"d:\NOTAS-PROGRA-V1\NOTAS-PROGRA\CiberSeguridad\CTFs"
DOCS_PATH = Path(__file__).parent.parent / "docs"

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
        # Calcular la ruta relativa correcta desde el archivo actual
        depth = len(Path(relative_path).parts) - 1
        prefix = "../" * depth if depth > 0 else ""
        return f"![]({prefix}assets/{image_name})"
    
    pattern = r'!\[\[([^\]]+\.(png|jpg|jpeg|gif|webp))\]\]'
    return re.sub(pattern, replace_image, content, flags=re.IGNORECASE)


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
    """
    print("🔄 Sincronizando notas de CTFs...")
    
    # Función para manejar errores de permisos en Windows
    def handle_remove_readonly(func, path, exc):
        """Error handler for Windows readonly files"""
        import stat
        if not os.access(path, os.W_OK):
            os.chmod(path, stat.S_IWUSR)
            func(path)
        else:
            raise
    
    # Limpiar directorio docs (excepto index.md y stylesheets)
    if DOCS_PATH.exists():
        for item in DOCS_PATH.iterdir():
            if item.name != "index.md" and item.name != "stylesheets":
                try:
                    if item.is_dir():
                        shutil.rmtree(item, onerror=handle_remove_readonly)
                    else:
                        item.unlink()
                except Exception as e:
                    print(f"⚠️  No se pudo eliminar {item.name}: {e}")
                    # Continuar con el resto del proceso
    else:
        DOCS_PATH.mkdir(parents=True)
    
    notes_path = Path(NOTES_REPO_PATH)
    
    # Copiar y procesar archivos por categoría
    categories = ["DockerLabs", "HackTheBox", "HackMyVm"]
    
    for category in categories:
        category_path = notes_path / category
        if not category_path.exists():
            print(f"⚠️  Categoría {category} no encontrada")
            continue
        
        # Crear directorio de categoría en docs
        docs_category_path = DOCS_PATH / category
        docs_category_path.mkdir(exist_ok=True)
        
        # Crear index.md para la categoría
        category_index = docs_category_path / "index.md"
        with open(category_index, 'w', encoding='utf-8') as f:
            f.write(f"# {category}\n\n")
            f.write(f"Write-ups de máquinas de {category}.\n\n")
        
        # Copiar archivos .md
        md_files = list(category_path.glob("*.md"))
        print(f"📁 {category}: {len(md_files)} archivos")
        
        for md_file in md_files:
            relative_path = f"{category}/{md_file.name}"
            processed_content = process_markdown_file(md_file, relative_path)
            
            dest_file = docs_category_path / md_file.name
            with open(dest_file, 'w', encoding='utf-8') as f:
                f.write(processed_content)
        
        # Copiar carpeta assets si existe
        assets_path = category_path / "assets"
        if assets_path.exists():
            dest_assets = docs_category_path / "assets"
            try:
                if dest_assets.exists():
                    shutil.rmtree(dest_assets, onerror=handle_remove_readonly)
                shutil.copytree(assets_path, dest_assets)
                print(f"🖼️  {category}/assets: {len(list(assets_path.glob('*')))} archivos")
            except Exception as e:
                print(f"⚠️  Error copiando assets de {category}: {e}")
    
    print("✅ Sincronización completada!")


if __name__ == "__main__":
    sync_notes()
