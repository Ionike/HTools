#!/usr/bin/env python3
"""
Process gallery folders and convert to CBZ format based on ComicInfo.xml Web tag.
"""

import os
import sys
import zipfile
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime


def setup_logging(parent_dir):
    """Create log file in the parent directory."""
    log_filename = f"gallery_processing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_path = Path(parent_dir) / log_filename
    return log_path


def log_message(log_path, message):
    """Append message to log file and print to console."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {message}\n"
    print(log_line.strip())
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(log_line)


def check_web_tag(comicinfo_path):
    """
    Check if ComicInfo.xml contains exhentai or e-hentai link in Web tag.

    Returns:
        tuple: (has_ehentai_link: bool, web_url: str or None)
    """
    try:
        tree = ET.parse(comicinfo_path)
        root = tree.getroot()

        # Find Web tag (handle namespace if present)
        web_element = root.find('Web')
        if web_element is None:
            # Try with namespace
            web_element = root.find('.//{*}Web')

        if web_element is None or not web_element.text:
            return False, None

        web_url = web_element.text.strip()

        # Check if URL contains exhentai or e-hentai
        if 'exhentai.org' in web_url.lower() or 'e-hentai.org' in web_url.lower():
            return True, web_url

        return False, web_url

    except Exception as e:
        return None, str(e)


def create_cbz(gallery_path, zipped_dir, log_path):
    """
    Create CBZ file from gallery folder and move to ZIPPED directory.

    The CBZ file will be created in the ZIPPED subdirectory of the parent folder.
    """
    gallery_path = Path(gallery_path)
    # Create CBZ in the same location first
    temp_cbz_path = gallery_path.parent / (gallery_path.name + '.cbz')
    # Final destination in ZIPPED folder
    final_cbz_path = zipped_dir / (gallery_path.name + '.cbz')

    # Check if CBZ already exists in ZIPPED folder
    if final_cbz_path.exists():
        log_message(log_path, f"  ⚠ CBZ already exists in ZIPPED folder, skipping: {final_cbz_path.name}")
        return False

    try:
        with zipfile.ZipFile(temp_cbz_path, 'w', zipfile.ZIP_DEFLATED) as cbz:
            # Add all files from the gallery folder
            for item in gallery_path.rglob('*'):
                if item.is_file():
                    # Store with relative path from gallery root
                    arcname = item.relative_to(gallery_path)
                    cbz.write(item, arcname)

        # Move to ZIPPED folder
        shutil.move(str(temp_cbz_path), str(final_cbz_path))

        log_message(log_path, f"  ✓ Created and moved to ZIPPED: {final_cbz_path.name}")
        return True

    except Exception as e:
        log_message(log_path, f"  ✗ Error creating CBZ for {gallery_path.name}: {e}")
        # Remove partial CBZ if it was created
        if temp_cbz_path.exists():
            temp_cbz_path.unlink()
        if final_cbz_path.exists():
            final_cbz_path.unlink()
        return False


def process_galleries(parent_dir):
    """
    Process all gallery folders in the parent directory.
    """
    parent_path = Path(parent_dir)

    if not parent_path.exists() or not parent_path.is_dir():
        print(f"Error: '{parent_dir}' is not a valid directory")
        return

    log_path = setup_logging(parent_dir)
    log_message(log_path, f"Starting gallery processing in: {parent_path.absolute()}")
    log_message(log_path, "=" * 80)

    # Create ZIPPED folder
    zipped_dir = parent_path / 'ZIPPED'
    zipped_dir.mkdir(exist_ok=True)
    log_message(log_path, f"CBZ files will be saved to: {zipped_dir}")
    log_message(log_path, "=" * 80)

    stats = {
        'total': 0,
        'converted': 0,
        'skipped_ehentai': 0,
        'errors': 0
    }

    # Iterate through all subdirectories
    for gallery_dir in sorted(parent_path.iterdir()):
        if not gallery_dir.is_dir():
            continue

        # Skip the ZIPPED folder itself
        if gallery_dir.name == 'ZIPPED':
            continue

        stats['total'] += 1
        comicinfo_path = gallery_dir / 'ComicInfo.xml'

        log_message(log_path, f"\nProcessing: {gallery_dir.name}")

        # Check if ComicInfo.xml exists
        if not comicinfo_path.exists():
            # No ComicInfo.xml - create CBZ
            log_message(log_path, f"  ⊘ No ComicInfo.xml found - converting to CBZ")
            if create_cbz(gallery_dir, zipped_dir, log_path):
                stats['converted'] += 1
            continue

        # Check Web tag
        has_ehentai_link, web_info = check_web_tag(comicinfo_path)

        if has_ehentai_link is None:
            # Error parsing XML - skip
            stats['errors'] += 1
            log_message(log_path, f"  ✗ Error parsing ComicInfo.xml: {web_info}")
            continue

        if has_ehentai_link:
            # Has exhentai/e-hentai link - skip
            stats['skipped_ehentai'] += 1
            log_message(log_path, f"  ⊘ Skipped (has exhentai/e-hentai link): {web_info}")
            continue

        # No exhentai/e-hentai link (or no Web tag) - create CBZ
        if web_info is None:
            log_message(log_path, f"  ✓ No <Web> tag - converting to CBZ")
        else:
            log_message(log_path, f"  ✓ Different URL (not exhentai/e-hentai) - converting to CBZ: {web_info}")

        if create_cbz(gallery_dir, zipped_dir, log_path):
            stats['converted'] += 1

    # Print summary
    log_message(log_path, "\n" + "=" * 80)
    log_message(log_path, "SUMMARY:")
    log_message(log_path, f"  Total galleries processed: {stats['total']}")
    log_message(log_path, f"  Converted to CBZ: {stats['converted']}")
    log_message(log_path, f"  Skipped (exhentai/e-hentai links): {stats['skipped_ehentai']}")
    log_message(log_path, f"  Errors: {stats['errors']}")
    log_message(log_path, "=" * 80)
    log_message(log_path, f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    print("=" * 80)
    print("Gallery to CBZ Converter")
    print("=" * 80)
    print()

    # Check if path provided as argument
    if len(sys.argv) >= 2:
        parent_directory = sys.argv[1]
    else:
        # Prompt for path
        print("Enter the parent directory containing gallery folders:")
        print("(You can drag and drop the folder here)")
        parent_directory = input("> ").strip().strip('"').strip("'")
        print()

    if not parent_directory:
        print("Error: No directory specified")
        input("\nPress Enter to exit...")
        sys.exit(1)

    process_galleries(parent_directory)

    print("\n" + "=" * 80)
    input("Press Enter to exit...")
