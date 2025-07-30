import requests

def check_version(components):
    results = []

    for comp in components:
        name = comp.get('component')
        current = comp.get('version') or 'unknown'
        latest_ver = None

        # 1) PyPI'de ara
        try:
            r = requests.get(f'https://pypi.org/pypi/{name}/json', timeout=5)
            if r.status_code == 200:
                latest_ver = r.json().get('info', {}).get('version')
        except Exception:
            pass

        # 2) npm registry'de ara (fallback)
        if not latest_ver:
            try:
                r2 = requests.get(f'https://registry.npmjs.org/{name}', timeout=5)
                if r2.status_code == 200:
                    latest_ver = r2.json().get('dist-tags', {}).get('latest')
            except Exception:
                pass

        results.append({
            'component':       name,
            'current_version': current,
            'latest_version':  latest_ver or 'unknown'
        })

    return results