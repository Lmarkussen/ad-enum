def template_key(value):
    value = str(value)
    return value.rsplit(",", 1)[-1].removeprefix("CN=").casefold()

def build_publication_index(cas, templates):
    """Resolve only explicit CA certificateTemplates references; retain dangling names."""
    by_key = {}
    duplicates = {}
    for template in templates:
        key = template_key(template.name)
        if key in by_key: duplicates.setdefault(key, [by_key[key]]).append(template)
        else: by_key[key] = template
    template_to_cas = {template.name: [] for template in templates}; dangling = []
    for ca in cas:
        for ref in ca.templates:
            template = by_key.get(template_key(ref))
            if template is None: dangling.append((ca.name, ref)); continue
            template_to_cas[template.name].append(ca)
    return template_to_cas, dangling, duplicates
