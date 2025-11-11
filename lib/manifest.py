import os
import re
from typing import Dict, List

from apkInspector.axml import parse_apk_for_manifest


def info(apk_path: str) -> Dict[str, List[str]]:
    """Extract manifest metadata directly from the APK using apkInspector."""
    result: Dict[str, List[str]] = {}

    if not apk_path or not os.path.isfile(apk_path):
        return result

    try:
        # Context: apkInspector CLI (`apkInspector -apk sample.apk -m`) also relies on parse_apk_for_manifest
        manifest_xml = parse_apk_for_manifest(apk_path, raw=False)
    except Exception:
        return result

    if not manifest_xml:
        return result

    if isinstance(manifest_xml, bytes):
        manifest_xml = manifest_xml.decode("utf-8", errors="ignore")

    regex = {
        "permission": r"android\.permission\.[A-Z_]+",
        "application": r"com\.[A-Za-z0-9.]+",
    }

    for key, pattern in regex.items():
        matches = sorted(set(re.findall(pattern, manifest_xml)))
        result[key] = matches

    return result
