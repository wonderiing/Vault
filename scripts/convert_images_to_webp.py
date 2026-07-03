import argparse
import os
import re
from pathlib import Path
from urllib.parse import quote, unquote

from PIL import Image, ImageOps


ROOT_PATH = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_PATH = ROOT_PATH / "docs"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}
MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")


def is_external_url(url):
    lowered = url.lower()
    return lowered.startswith(("http://", "https://", "data:", "mailto:"))


def split_url_suffix(url):
    suffix_start = len(url)
    for marker in ("#", "?"):
        index = url.find(marker)
        if index != -1:
            suffix_start = min(suffix_start, index)
    return url[:suffix_start], url[suffix_start:]


def iter_source_images(scan_path):
    for image_path in scan_path.rglob("*"):
        if image_path.is_file() and image_path.suffix.lower() in IMAGE_EXTENSIONS:
            yield image_path


def convert_image(image_path, quality, overwrite, dry_run):
    output_path = image_path.with_suffix(".webp")

    if output_path.exists() and not overwrite:
        return output_path, "skipped"

    if dry_run:
        return output_path, "dry-run"

    with Image.open(image_path) as image:
        image = ImageOps.exif_transpose(image)

        if image.mode not in ("RGB", "RGBA"):
            image = image.convert("RGBA" if "A" in image.getbands() else "RGB")

        image.save(output_path, "WEBP", quality=quality, method=6)

    return output_path, "converted"


def resolve_markdown_target(md_file, raw_url, converted_paths):
    url_without_suffix, suffix = split_url_suffix(raw_url.strip())

    if is_external_url(url_without_suffix):
        return None

    decoded_url = unquote(url_without_suffix)
    candidates = [md_file.parent / decoded_url]

    if "../assets/" in decoded_url.replace("\\", "/"):
        candidates.append(md_file.parent / decoded_url.replace("../assets/", "assets/"))

    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in converted_paths:
            rel_path = os.path.relpath(converted_paths[resolved], md_file.parent)
            rel_path = rel_path.replace(os.sep, "/")
            return quote(rel_path, safe="/") + suffix

    return None


def update_markdown_links(scan_path, converted_paths, dry_run):
    updated_files = 0
    updated_links = 0

    def replace_link(md_file):
        def replacement(match):
            nonlocal updated_links

            new_url = resolve_markdown_target(md_file, match.group(2), converted_paths)
            if new_url is None:
                return match.group(0)

            updated_links += 1
            return f"![{match.group(1)}]({new_url})"

        return replacement

    for md_file in scan_path.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        new_content = MARKDOWN_IMAGE_RE.sub(replace_link(md_file), content)

        if new_content != content:
            updated_files += 1
            if not dry_run:
                md_file.write_text(new_content, encoding="utf-8")

    return updated_files, updated_links


def format_size(bytes_count):
    for unit in ("B", "KB", "MB", "GB"):
        if bytes_count < 1024 or unit == "GB":
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024


def main():
    parser = argparse.ArgumentParser(
        description="Convert PNG/JPG/JPEG images to WebP and update Markdown image links."
    )
    parser.add_argument("--path", type=Path, default=DEFAULT_SCAN_PATH, help="Path to scan. Defaults to docs/.")
    parser.add_argument("--quality", type=int, default=82, help="WebP quality, from 1 to 100. Defaults to 82.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing .webp files.")
    parser.add_argument("--delete-originals", action="store_true", help="Delete original PNG/JPG/JPEG files after conversion.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing files.")
    args = parser.parse_args()

    scan_path = args.path.resolve()
    if not scan_path.exists():
        raise SystemExit(f"Path does not exist: {scan_path}")

    converted_paths = {}
    converted_count = 0
    skipped_count = 0
    original_size = 0
    webp_size = 0

    for image_path in iter_source_images(scan_path):
        original_size += image_path.stat().st_size
        output_path, status = convert_image(image_path, args.quality, args.overwrite, args.dry_run)

        if status in ("converted", "dry-run"):
            converted_count += 1
        elif status == "skipped":
            skipped_count += 1

        if output_path.exists() and not args.dry_run:
            webp_size += output_path.stat().st_size

        converted_paths[image_path.resolve()] = output_path.resolve()

    updated_files, updated_links = update_markdown_links(scan_path, converted_paths, args.dry_run)

    deleted_count = 0
    if args.delete_originals and not args.dry_run:
        for original_path in converted_paths:
            webp_path = converted_paths[original_path]
            if webp_path.exists():
                original_path.unlink()
                deleted_count += 1

    if args.dry_run:
        print(f"Images to convert: {converted_count}")
    else:
        print(f"Images converted: {converted_count}")
    print(f"Images skipped: {skipped_count}")
    print(f"Markdown files updated: {updated_files}")
    print(f"Markdown links updated: {updated_links}")
    print(f"Original size scanned: {format_size(original_size)}")
    if not args.dry_run:
        print(f"WebP size written: {format_size(webp_size)}")
    if args.delete_originals:
        print(f"Original images deleted: {deleted_count}")


if __name__ == "__main__":
    main()
