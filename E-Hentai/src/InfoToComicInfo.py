"""
Convert info.txt files to ComicInfo.xml format
Processes gallery folders containing info.txt and generates ComicInfo.xml
Also renames images to %08d format (00000001.jpg, 00000002.jpg, etc.)

Usage:
    python InfoToComicInfo.py <parent_folder>
    python InfoToComicInfo.py  # Uses config.json gallery_parent_dir
    python InfoToComicInfo.py <parent_folder> --overwrite  # Overwrite existing ComicInfo.xml
    python InfoToComicInfo.py <parent_folder> --no-rename  # Skip image renaming
"""

import re
import sys
import json
from pathlib import Path
from xml.etree.ElementTree import Element, ElementTree

SCRIPT_DIR = Path(__file__).parent.parent
CONFIG_FILE = SCRIPT_DIR / "config.json"

GALLERY_URL_PATTERN = r'https://(exhentai|e-hentai)\.org/g/(\d+)/([a-f0-9]+)/?'

# Files to exclude from renaming
EXCLUDE_FILES = {'info.txt', 'ComicInfo.xml', 'desktop.ini', 'thumbs.db', '.ds_store'}
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.avif'}


def rename_images_in_folder(folder_path):
    """Rename all images in folder to %08d format

    Args:
        folder_path: Path to the folder

    Returns:
        int: Number of files renamed
    """
    renamed_count = 0

    # Get all files except excluded ones
    files = []
    for f in folder_path.iterdir():
        if f.is_file() and f.name.lower() not in EXCLUDE_FILES:
            # Only include image files
            if f.suffix.lower() in IMAGE_EXTENSIONS:
                files.append(f)

    if not files:
        return 0

    # Sort files by name for consistent ordering
    files.sort(key=lambda x: x.name)

    # First pass: rename to temp names to avoid conflicts
    temp_names = []
    for i, file_path in enumerate(files):
        temp_name = f"__temp_rename_{i:08d}__" + file_path.suffix
        temp_path = folder_path / temp_name
        file_path.rename(temp_path)
        temp_names.append(temp_path)

    # Second pass: rename to final %08d format
    for index, temp_path in enumerate(temp_names, start=1):
        extension = temp_path.suffix
        new_name = f"{index:08d}{extension}"
        new_path = folder_path / new_name
        temp_path.rename(new_path)
        renamed_count += 1

    return renamed_count


def count_images_in_folder(folder_path):
    """Count image files in a folder"""
    count = 0
    for f in folder_path.iterdir():
        if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS:
            count += 1
    return count


class InfoTxtParser:
    """Parse info.txt from E-Hentai Downloader with flexible format handling"""

    @staticmethod
    def parse(info_txt_path):
        """Parse info.txt and return gallery info dict"""
        with open(info_txt_path, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')

        info = {
            'url': '',
            'title_english': '',
            'title_japanese': '',
            'artist': '',
            'group': '',
            'characters': '',
            'tags': '',
            'page_count': '',
            'rating': '',
            'parody': '',
            'language': '',
            'category': ''
        }

        # Parse first 3 lines flexibly for title(s) and URL
        # Possible formats:
        # 1. Line 1: English, Line 2: Japanese, Line 3: URL
        # 2. Line 1: Japanese only, Line 2: empty, Line 3: URL
        # 3. Line 1: Japanese only, Line 2: URL
        # 4. Line 1: English, Line 2: URL (no Japanese title)

        url_found = False
        title_lines = []

        for i, line in enumerate(lines[:5]):  # Check first 5 lines
            line = line.strip()
            if not line:
                continue

            url_match = re.search(GALLERY_URL_PATTERN, line)
            if url_match:
                info['url'] = url_match.group(0)
                url_found = True
                break
            else:
                title_lines.append(line)

        # Assign titles based on what we found
        if len(title_lines) >= 2:
            # Check if first line looks like romaji/english (contains ASCII)
            first_has_ascii = bool(re.search(r'[a-zA-Z]', title_lines[0]))
            second_has_cjk = bool(re.search(r'[\u3040-\u30ff\u4e00-\u9fff]', title_lines[1]))

            if first_has_ascii and second_has_cjk:
                info['title_english'] = title_lines[0]
                info['title_japanese'] = title_lines[1]
            elif first_has_ascii:
                info['title_english'] = title_lines[0]
                # Second line might also be a title variation
                if not title_lines[1].startswith('Category:'):
                    info['title_japanese'] = title_lines[1]
            else:
                # First line is Japanese
                info['title_japanese'] = title_lines[0]
                if len(title_lines) > 1 and not title_lines[1].startswith('Category:'):
                    info['title_english'] = title_lines[1]
        elif len(title_lines) == 1:
            # Single title - determine if English or Japanese
            if re.search(r'[\u3040-\u30ff\u4e00-\u9fff]', title_lines[0]):
                info['title_japanese'] = title_lines[0]
            else:
                info['title_english'] = title_lines[0]

        # If only Japanese title exists, use it as English too for Series field
        if info['title_japanese'] and not info['title_english']:
            info['title_english'] = info['title_japanese']
            info['title_japanese'] = ''

        # Parse metadata fields
        for line in lines:
            line = line.strip()

            if line.startswith('Category:'):
                info['category'] = line.replace('Category:', '').strip()
            elif line.startswith('Language:'):
                lang = line.replace('Language:', '').strip()
                # Clean up language (remove extra spaces, flags, etc.)
                lang = re.sub(r'\s+', ' ', lang).strip()
                info['language'] = lang
            elif line.startswith('Length:'):
                match = re.search(r'(\d+)\s*pages?', line)
                if match:
                    info['page_count'] = match.group(1)
            elif line.startswith('Rating:'):
                match = re.search(r'[\d.]+', line)
                if match:
                    info['rating'] = match.group(0)

        # Parse tags section
        in_tags = False
        artists = []
        groups = []
        characters = []
        parodies = []
        other_tags = []

        for line in lines:
            line = line.strip()

            if line == 'Tags:':
                in_tags = True
                continue

            if in_tags:
                if line.startswith('>'):
                    tag_line = line[1:].strip()
                    if ':' in tag_line:
                        tag_type, tag_values = tag_line.split(':', 1)
                        tag_type = tag_type.strip().lower()
                        tags = [t.strip() for t in tag_values.split(',') if t.strip()]

                        if tag_type == 'artist':
                            artists.extend(tags)
                        elif tag_type == 'group':
                            groups.extend(tags)
                        elif tag_type == 'character':
                            characters.extend(tags)
                        elif tag_type == 'parody':
                            parodies.extend(tags)
                        elif tag_type in ('female', 'male', 'mixed', 'other'):
                            other_tags.extend(tags)
                elif line and not line.startswith('>') and not line.startswith('Uploader'):
                    # Check if this is still part of tags (could be a continuation)
                    # End of tags section markers
                    if line.startswith('Page ') or line.startswith('Image ') or line.startswith('Downloaded'):
                        in_tags = False

        info['artist'] = ', '.join(artists)
        info['group'] = ', '.join(groups)
        info['characters'] = ', '.join(characters)
        info['parody'] = ', '.join(parodies)
        info['tags'] = ', '.join(other_tags)

        return info


class ComicInfoGenerator:
    """Generate ComicInfo.xml files"""

    @staticmethod
    def create(gallery_info, output_path):
        """Create ComicInfo.xml from gallery info"""
        root = Element('ComicInfo')
        root.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        root.set('xsi:noNamespaceSchemaLocation',
                 'https://raw.githubusercontent.com/anansi-project/comicinfo/main/schema/v2.0/ComicInfo.xsd')

        # Field mapping: (info_key, xml_tag)
        field_map = [
            ('title_english', 'Series'),
            ('title_japanese', 'AlternateSeries'),
            ('artist', 'Penciller'),
            ('group', 'Writer'),
            ('characters', 'Characters'),
            ('parody', 'Teams'),
            ('tags', 'Genre'),
            ('page_count', 'PageCount'),
            ('rating', 'CommunityRating'),
            ('language', 'LanguageISO'),
            ('url', 'Web'),
        ]

        for info_key, xml_tag in field_map:
            value = gallery_info.get(info_key, '')
            if value:
                elem = Element(xml_tag)
                elem.text = str(value)
                root.append(elem)

        tree = ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        return True


def process_gallery_folder(folder_path, overwrite=False, rename=True):
    """Process a single gallery folder

    Args:
        folder_path: Path to gallery folder
        overwrite: If True, overwrite existing ComicInfo.xml
        rename: If True, rename images to %08d format

    Returns:
        tuple: (success: bool, message: str)
    """
    info_txt_path = folder_path / "info.txt"
    comic_info_path = folder_path / "ComicInfo.xml"

    if not info_txt_path.exists():
        return False, "No info.txt found"

    if comic_info_path.exists() and not overwrite:
        return True, "ComicInfo.xml already exists (skipped)"

    try:
        # Rename images first
        renamed_count = 0
        if rename:
            renamed_count = rename_images_in_folder(folder_path)

        gallery_info = InfoTxtParser.parse(info_txt_path)

        if not gallery_info.get('title_english') and not gallery_info.get('title_japanese'):
            return False, "Could not extract title from info.txt"

        ComicInfoGenerator.create(gallery_info, comic_info_path)

        title = gallery_info.get('title_english') or gallery_info.get('title_japanese')
        artist = gallery_info.get('artist') or 'N/A'
        rename_msg = f" | Renamed: {renamed_count} images" if renamed_count > 0 else ""
        return True, f"Created ComicInfo.xml | Artist: {artist}{rename_msg}"

    except Exception as e:
        return False, f"Error: {e}"


def process_all_galleries(parent_dir, overwrite=False, rename=True):
    """Process all gallery folders in parent directory

    Args:
        parent_dir: Path to parent directory containing gallery folders
        overwrite: If True, overwrite existing ComicInfo.xml files
        rename: If True, rename images to %08d format
    """
    parent_path = Path(parent_dir)

    if not parent_path.exists():
        print(f"[ERROR] Directory not found: {parent_path}")
        return

    # Find all folders with info.txt
    gallery_folders = []
    for folder in parent_path.iterdir():
        if folder.is_dir() and not folder.name.startswith('.'):
            if (folder / "info.txt").exists():
                gallery_folders.append(folder)

    if not gallery_folders:
        print("[INFO] No gallery folders with info.txt found")
        return

    print(f"[INFO] Found {len(gallery_folders)} galleries with info.txt")
    print("=" * 70)

    success_count = 0
    skip_count = 0
    error_count = 0

    for i, folder in enumerate(sorted(gallery_folders), 1):
        success, message = process_gallery_folder(folder, overwrite, rename)

        status = "[OK]" if success else "[FAIL]"
        if "skipped" in message.lower():
            status = "[SKIP]"
            skip_count += 1
        elif success:
            success_count += 1
        else:
            error_count += 1

        print(f"{status} [{i}/{len(gallery_folders)}] {folder.name}")
        print(f"      {message}")

    print("=" * 70)
    print(f"[SUMMARY] Created: {success_count} | Skipped: {skip_count} | Errors: {error_count}")


def main():
    print("=" * 70)
    print("Info.txt to ComicInfo.xml Converter")
    print("=" * 70)

    # Get directory
    if len(sys.argv) > 1:
        # Filter out flags to get directory path
        args = [a for a in sys.argv[1:] if not a.startswith('-')]
        parent_dir = args[0] if args else ""
        overwrite = '--overwrite' in sys.argv or '-f' in sys.argv
        rename = '--no-rename' not in sys.argv
    else:
        # Try to load from config
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            parent_dir = config.get("gallery_parent_dir", "")
        else:
            parent_dir = ""

        if not parent_dir:
            print("Enter parent folder containing gallery folders:")
            parent_dir = input("Folder: ").strip()

        overwrite = False
        rename = True

    if not parent_dir:
        print("[ERROR] No directory specified")
        return

    print(f"Directory: {parent_dir}")
    print(f"Overwrite: {overwrite}")
    print(f"Rename images: {rename}")
    print("=" * 70)

    process_all_galleries(parent_dir, overwrite, rename)


if __name__ == "__main__":
    main()
