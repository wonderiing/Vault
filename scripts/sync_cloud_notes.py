"""
Sincroniza notas de Cloud desde el vault original hacia este repo.

Actualmente replica solo DevOps/AWS y convierte sintaxis basica de Obsidian
a Markdown compatible con MkDocs Material.
"""

import re
import shutil
from pathlib import Path
from urllib.parse import quote

from PIL import Image, ImageOps


SOURCE_VAULT = Path(r"C:\Users\ca223\Downloads\NOTAS-PROGRA\NOTAS-PROGRA")
AWS_SOURCE = SOURCE_VAULT / "DevOps" / "AWS"
DOCS_PATH = Path(__file__).parent.parent / "docs"
CLOUD_PATH = DOCS_PATH / "Cloud"
AWS_DEST = CLOUD_PATH / "AWS"

ASSET_LOOKUP_DIRS = [
    AWS_SOURCE / "assets",
    AWS_SOURCE,
    SOURCE_VAULT,
    SOURCE_VAULT / "imagenes-videos",
]

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"}
WEBP_SOURCE_EXTENSIONS = {".png", ".jpg", ".jpeg"}

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


def convert_obsidian_images(content):
    def replace_image(match):
        target = match.group(1).split("|", 1)[0].strip()
        image_name = Path(target).name
        image_path = Path(image_name)
        if image_path.suffix.lower() in WEBP_SOURCE_EXTENSIONS:
            image_name = image_path.with_suffix(".webp").name
        return f"![](assets/{quote(image_name)})"

    return re.sub(
        r"!\[\[([^\]]+\.(?:png|jpg|jpeg|gif|webp|svg)(?:\|[^\]]+)?)\]\]",
        replace_image,
        content,
        flags=re.IGNORECASE,
    )


def convert_obsidian_callouts(content):
    lines = content.split("\n")
    result = []
    in_callout = False

    for line in lines:
        callout_match = re.match(r"^>\s*\[!(\w+)\]\s*(.*)", line)
        if callout_match:
            callout_type = callout_match.group(1).lower()
            title = callout_match.group(2).strip()
            admonition_type = CALLOUT_MAPPING.get(callout_type, "note")
            result.append(
                f'!!! {admonition_type} "{title}"' if title else f"!!! {admonition_type}"
            )
            in_callout = True
        elif in_callout and line.startswith(">"):
            content_line = line[1:].strip()
            result.append(f"    {content_line}" if content_line else "")
        else:
            in_callout = False
            result.append(line)

    return "\n".join(result)


def referenced_images(content):
    matches = re.findall(
        r"!\[\[([^\]]+\.(?:png|jpg|jpeg|gif|webp|svg)(?:\|[^\]]+)?)\]\]",
        content,
        flags=re.IGNORECASE,
    )
    return {Path(match.split("|", 1)[0].strip()).name for match in matches}


def find_asset(asset_name):
    for directory in ASSET_LOOKUP_DIRS:
        candidate = directory / asset_name
        if candidate.exists():
            return candidate
    matches = list(SOURCE_VAULT.glob(f"**/{asset_name}"))
    return matches[0] if matches else None


def copy_asset(asset_file, assets_dest):
    if asset_file.suffix.lower() in WEBP_SOURCE_EXTENSIONS:
        destination_asset = assets_dest / asset_file.with_suffix(".webp").name
        if destination_asset.exists():
            return False

        with Image.open(asset_file) as image:
            image = ImageOps.exif_transpose(image)
            if image.mode not in ("RGB", "RGBA"):
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            image.save(destination_asset, "WEBP", quality=82, method=6)
        return True

    destination_asset = assets_dest / asset_file.name
    if destination_asset.exists():
        return False

    shutil.copy2(asset_file, destination_asset)
    return True


def write_index_files():
    CLOUD_PATH.mkdir(parents=True, exist_ok=True)
    AWS_DEST.mkdir(parents=True, exist_ok=True)

    cloud_index = CLOUD_PATH / "index.md"
    if not cloud_index.exists():
        cloud_index.write_text(
            "# Cloud\n\nNotas relacionadas con servicios cloud y DevOps.\n",
            encoding="utf-8",
        )

    aws_index = AWS_DEST / "index.md"
    if not aws_index.exists():
        aws_index.write_text(
            "# AWS\n\nNotas de Amazon Web Services.\n",
            encoding="utf-8",
        )


def sync_aws_notes():
    if not AWS_SOURCE.exists():
        raise FileNotFoundError(f"No existe la ruta origen: {AWS_SOURCE}")

    write_index_files()
    assets_dest = AWS_DEST / "assets"
    assets_dest.mkdir(exist_ok=True)

    copied_notes = 0
    copied_assets = 0
    missing_assets = set()

    for md_file in sorted(AWS_SOURCE.glob("*.md")):
        content = md_file.read_text(encoding="utf-8")

        for image_name in referenced_images(content):
            source_asset = find_asset(image_name)
            if source_asset is None:
                missing_assets.add(image_name)
                continue

            if copy_asset(source_asset, assets_dest):
                copied_assets += 1

        processed_content = convert_obsidian_callouts(convert_obsidian_images(content))
        (AWS_DEST / md_file.name).write_text(processed_content, encoding="utf-8")
        copied_notes += 1

    for asset_file in (AWS_SOURCE / "assets").glob("*"):
        if asset_file.is_file() and asset_file.suffix.lower() in IMAGE_EXTENSIONS:
            if copy_asset(asset_file, assets_dest):
                copied_assets += 1

    print(f"Notas AWS sincronizadas: {copied_notes}")
    print(f"Assets copiados: {copied_assets}")
    if missing_assets:
        print("Assets no encontrados:")
        for asset_name in sorted(missing_assets):
            print(f"- {asset_name}")


if __name__ == "__main__":
    sync_aws_notes()
