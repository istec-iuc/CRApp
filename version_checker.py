# version_checker.py

import os, json, platform
from packaging import version as pkg_version

# JSON mapping’i yükle, anahtarları lowercase yap
BASE = os.path.dirname(__file__)
try:
    with open(os.path.join(BASE, 'version_mapping.json'), encoding='utf-8') as f:
        _raw = json.load(f)
    VERSION_MAP = {k.lower(): v for k, v in _raw.items()}
except FileNotFoundError:
    VERSION_MAP = {}


import re
from packaging import version as pkg_version

def clean_version(v):
    if not v or not isinstance(v, str):
        return ''
    
    # Remove common non-semver suffixes/prefixes
    v = v.strip().lower()
    v = v.replace("lts", "").replace("release", "")
    v = re.sub(r'^v', '', v)  # remove leading 'v'
    v = v.strip()

    # Extract the first version-like pattern
    match = re.search(r'\d+(\.\d+)*', v)
    return match.group(0) if match else ''

def safe_parse(v):
    try:
        return pkg_version.parse(v)
    except Exception:
        return None


def check_version(components):
    results = []
    for comp in components:
        name    = comp.get('component','').strip()
        current = comp.get('version') or 'unknown'
        key     = name.lower()
        raw     = VERSION_MAP.get(key)

        # Get version and homepage info from new format
        latest_raw = raw.get('latest') if isinstance(raw, dict) else raw
        homepage   = raw.get('homepage') if isinstance(raw, dict) else None

        # Python bileşeni için ortam sürümü
        if key == 'python':
            latest_list = [platform.python_version()]
        elif isinstance(latest_raw, list):
            latest_list = latest_raw
        elif isinstance(latest_raw, str):
            latest_list = [latest_raw]
        else:
            latest_list = []

        # en yüksek versiyon (varsa)
        #try:
        #    latest = str(max(latest_list, key=pkg_version.parse))
        #except Exception:
        #    latest = 'unknown'

        #if latest_list is None or not latest_list:
        #    latest_list = ['unknown']

        parsed_versions = [
            (v, safe_parse(clean_version(v)))
            for v in latest_list
        ]
        parsed_versions = [pv for pv in parsed_versions if pv[1] is not None]

        if parsed_versions:
            latest = max(parsed_versions, key=lambda x: x[1])[0]
        else:
            latest = latest_list[0] if latest_list else 'unknown'


        # güncel mi?
        is_current = False
        if current != 'unknown' and latest != 'unknown':
            try:
                is_current = pkg_version.parse(current) >= pkg_version.parse(latest)
            except:
                is_current = False

        results.append({
            'component':       name,
            'current_version': current,
            'latest_version':  latest,
            'all_latest':      latest_list,
            'homepage':        homepage,
            'is_current':      is_current
        })

        print(f"Checking {name}: raw={raw}, latest_raw={latest_raw}, latest_list={latest_list}")
    return results