# sbom_parser.py
import json
import xml.etree.ElementTree as ET

def parse_sbom(path):
    """
    CycloneDX JSON, SPDX JSON veya XML SBOM dosyasını parse eder,
    her bileşen için {'component': adı, 'version': versiyonu} listesi döner.
    """
    # JSON olarak açmayı dene
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        comps = data.get('components') or data.get('packages') or []
        result = []
        for c in comps:
            name = c.get('name') or c.get('SPDXID') or ''
            version = c.get('version') or c.get('versionInfo') or ''
            result.append({'component': name, 'version': version})
        return result
    except json.JSONDecodeError:
        # JSON değilse XML parse et
        tree = ET.parse(path)
        root = tree.getroot()
        # Namespace tespiti
        ns = {}
        if '}' in root.tag:
            uri = root.tag.split('}')[0].strip('{')
            ns = {'b': uri}
        result = []
        for comp in root.findall('.//b:components/b:component', ns):
            name_el = comp.find('b:name', ns)
            ver_el  = comp.find('b:version', ns)
            name    = name_el.text if name_el is not None else ''
            version = ver_el.text if ver_el is not None else ''
            result.append({'component': name, 'version': version})
        return result