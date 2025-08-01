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

def check_version(components):
    results = []
    for comp in components:
        name    = comp.get('component','').strip()
        current = comp.get('version') or 'unknown'
        key     = name.lower()
        raw     = VERSION_MAP.get(key)

        # Python bileşeni için ortam sürümü
        if key == 'python':
            latest_list = [platform.python_version()]
        # eğer JSON’da bir liste varsa
        elif isinstance(raw, list):
            latest_list = raw
        # tek değer ise listeye al
        elif isinstance(raw, str):
            latest_list = [raw]
        else:
            latest_list = []

        # en yüksek versiyon (varsa)
        try:
            latest = str(max(latest_list, key=pkg_version.parse))
        except Exception:
            latest = 'unknown'

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
            'is_current':      is_current
        })
    return results