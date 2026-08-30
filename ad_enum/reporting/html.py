"""Standalone HTML renderer for the normalized AD-Enum report model."""
import html
import json
import os
from pathlib import Path


def _e(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def _json(value):
    return _e(json.dumps(value, indent=2, sort_keys=True, default=str))


def _affected_objects(finding):
    evidence = finding.get("evidence", {}) or {}
    values = evidence.get("affected_objects")
    if values is None:
        for key in ("hosts", "accounts", "groups", "computers", "shares", "templates", "gpos", "objects"):
            if isinstance(evidence.get(key), list):
                values = evidence[key]
                break
    if not isinstance(values, list) or len(values) <= 1:
        return []
    result = []
    for value in values:
        if isinstance(value, dict):
            value = (value.get("fqdn") or value.get("host") or value.get("name") or
                     value.get("account") or value.get("share") or value.get("dn") or value.get("ip"))
        if value not in (None, "") and str(value) not in result:
            result.append(str(value))
    return result


def render_html(model):
    findings = model.get("findings", [])
    grouped = {}
    for finding in findings:
        grouped.setdefault(finding.get("category", "OTHER"), []).append(finding)
    category_order = model.get("category_order", [])
    categories = [x for x in category_order if x in grouped]
    categories.extend(x for x in grouped if x not in categories)
    finding_sections = []
    for category in categories:
        cards = []
        for finding in grouped[category]:
            evidence = finding.get("evidence", {}) or {}
            sources = finding.get("sources", []) or []
            details = "" if not evidence else f"<details><summary>Evidence</summary><pre>{_json(evidence)}</pre></details>"
            objects = _affected_objects(finding)
            object_block = (f"<details open><summary>Affected objects ({len(objects)})</summary><ul>" +
                            "".join(f"<li>{_e(value)}</li>" for value in objects) + "</ul></details>") if objects else ""
            cards.append(
                '<article class="finding">'
                f"<h3>{_e(finding.get('title', 'Finding'))}</h3>"
                f"<div class=\"badges\"><span class=\"status status-{_e(str(finding.get('status', 'unknown')).lower())}\">{_e(str(finding.get('status', 'UNKNOWN')).upper())}</span>"
                f"<span class=\"meta\">Object: {_e(finding.get('affected_object', 'unknown'))}</span></div>"
                f"<dl><dt>Impact</dt><dd>{_e(evidence.get('impact', finding.get('impact', '')) or '—')}</dd>"
                f"<dt>Sources</dt><dd>{_e(', '.join(str(x.get('source', '')) for x in sources if isinstance(x, dict)) or '—')}</dd></dl>"
                f"{object_block}{details}</article>"
            )
        finding_sections.append(f'<section id="finding-{_e(category.lower())}"><h2>{_e(category)}</h2>{"".join(cards)}</section>')

    collectors = "".join(f"<tr><td>{_e(k)}</td><td><span class=\"status status-{_e(str(v).lower())}\">{_e(v)}</span></td></tr>"
                          for k, v in model.get("collectors", {}).items())
    inventory = "".join(f"<div class=\"metric\"><strong>{_e(v)}</strong><span>{_e(k)}</span></div>"
                        for k, v in model.get("inventory", {}).items())
    coverage = "".join(f"<tr><td>{_e(k)}</td><td><span class=\"status status-{_e(str(v.get('status', '')).lower().replace(' ', '-'))}\">{_e(v.get('status'))}</span></td><td>{_e(v.get('detail', ''))}</td></tr>"
                       for k, v in model.get("coverage", {}).items())
    credentials = model.get("credentials", [])
    credential_section = ""
    if credentials:
        rows = "".join(f"<tr><td>{_e(x.get('account', 'UNKNOWN'))}</td><td>{_e(x.get('type', 'secret'))}</td><td><code>{_e(x.get('value', ''))}</code></td><td>{_e(x.get('source', ''))}</td><td>{_e(x.get('context', ''))}</td></tr>" for x in credentials)
        credential_section = f'<section id="credentials"><h2>Credentials / Secrets</h2><div class="table-wrap"><table><thead><tr><th>Account</th><th>Type</th><th>Value</th><th>Source</th><th>Context</th></tr></thead><tbody>{rows}</tbody></table></div></section>'
    shares = model.get("smb_shares", []) or []
    share_section = ""
    if shares:
        rows = []
        for share in shares:
            if share.get("writable"):
                access = "READ / WRITE"
            elif share.get("readable") is True:
                access = "READ"
            elif share.get("readable") is False:
                access = "DENIED"
            else:
                access = "UNKNOWN"
            rows.append(f"<tr><td>{_e(share.get('host') or share.get('ip', ''))}</td>"
                        f"<td>{_e(share.get('share', ''))}</td><td><span class=\"status status-{_e(access.lower().replace(' ', '-').replace('/', ''))}\">{_e(access)}</span></td>"
                        f"<td><code>{_e(share.get('unc', ''))}</code></td></tr>")
        share_section = '<section id="smb-shares"><h2>SMB Share Access</h2><div class="table-wrap"><table><thead><tr><th>Host</th><th>Share</th><th>Access</th><th>UNC path</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div></section>"
    sccm = model.get("sccm") or {}
    sccm_section = ""
    if sccm:
        sccm_section = f'<section id="sccm"><h2>SCCM / MECM</h2><pre>{_json(sccm)}</pre></section>'
    nav_items = [("Overview", "overview"), ("Inventory", "inventory"), ("Findings", "findings"),
                 ("SMB Shares", "smb-shares"), ("Credentials", "credentials"), ("SCCM", "sccm"), ("Coverage", "coverage")]
    nav = "".join(f'<a href="#{anchor}">{label}</a>' for label, anchor in nav_items
                   if anchor in {"overview", "inventory", "findings", "coverage"} or (anchor == "smb-shares" and shares) or (anchor == "credentials" and credentials) or (anchor == "sccm" and sccm))
    banner = model.get("banner", "AD-Enum")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD-Enum — {_e(model.get("domain", "Report"))}</title>
<style>
:root {{ color-scheme: light dark; --bg:#f6f8fa; --panel:#fff; --text:#1f2328; --muted:#656d76; --border:#d0d7de; --accent:#0969da; --good:#1a7f37; --warn:#9a6700; --bad:#cf222e; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#0d1117; --panel:#161b22; --text:#e6edf3; --muted:#8b949e; --border:#30363d; --accent:#58a6ff; --good:#3fb950; --warn:#d29922; --bad:#f85149; }} }}
* {{ box-sizing:border-box }} body {{ margin:0; background:var(--bg); color:var(--text); font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; line-height:1.5 }}
header {{ background:var(--panel); border-bottom:1px solid var(--border); padding:28px max(20px,calc((100% - 1120px)/2)) 22px }}
header pre {{ color:var(--accent); white-space:pre-wrap; overflow-wrap:anywhere; margin:0 0 18px; font:12px/1.15 ui-monospace,SFMono-Regular,monospace }} h1 {{ margin:0 }} nav {{ position:sticky; top:0; z-index:2; background:var(--panel); border-bottom:1px solid var(--border); padding:10px max(20px,calc((100% - 1120px)/2)); display:flex; gap:18px; overflow:auto }} nav a {{ color:var(--accent); text-decoration:none; white-space:nowrap }} main {{ max-width:1120px; margin:28px auto; padding:0 20px }} section {{ margin:28px 0 }} h2 {{ border-bottom:1px solid var(--border); padding-bottom:8px }} h3 {{ margin:0 0 10px }} .panel,.finding {{ background:var(--panel); border:1px solid var(--border); border-radius:7px; padding:16px; margin:12px 0 }} .metrics {{ display:flex; flex-wrap:wrap; gap:10px }} .metric {{ min-width:130px; padding:14px; border:1px solid var(--border); border-radius:7px }} .metric strong,.metric span {{ display:block }} .metric strong {{ font-size:22px }} .metric span,.meta,dt {{ color:var(--muted) }} .badges {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center }} .status {{ display:inline-block; border-radius:2em; padding:2px 9px; font-size:12px; font-weight:600; background:var(--border) }} .status-pass,.status-confirmed,.status-complete {{ color:var(--good) }} .status-failed,.status-error {{ color:var(--bad) }} .status-partial,.status-warning,.status-not-tested,.status-unknown {{ color:var(--warn) }} dl {{ display:grid; grid-template-columns:110px 1fr; gap:4px 12px }} dt {{ font-weight:600 }} dd {{ margin:0; overflow-wrap:anywhere }} table {{ width:100%; border-collapse:collapse }} th,td {{ text-align:left; padding:8px; border-bottom:1px solid var(--border); vertical-align:top; overflow-wrap:anywhere }} .table-wrap {{ overflow:auto }} pre,code {{ font:12px/1.45 ui-monospace,SFMono-Regular,monospace }} pre {{ white-space:pre-wrap; overflow-wrap:anywhere }} details {{ margin-top:12px }} summary {{ color:var(--accent); cursor:pointer }}
</style></head><body><header><pre>{_e(banner)}</pre><h1>AD-Enum</h1><div class="meta">Active Directory reconnaissance and security posture report</div></header>
<nav>{nav}</nav><main><section id="overview"><h2>Overview</h2><div class="panel"><dl><dt>Domain</dt><dd>{_e(model.get("domain"))}</dd><dt>Target</dt><dd>{_e(model.get("target"))}</dd><dt>Workspace</dt><dd>{_e(model.get("workspace"))}</dd></dl></div></section>
<section id="inventory"><h2>Inventory</h2><div class="metrics">{inventory}</div><div class="panel"><h3>Collectors</h3><table><tbody>{collectors}</tbody></table></div></section>
<section id="findings"><h2>Findings</h2>{"".join(finding_sections) or '<div class="panel">No active findings.</div>'}</section>
{share_section}{credential_section}{sccm_section}<section id="coverage"><h2>Coverage</h2><div class="table-wrap"><table><thead><tr><th>Capability</th><th>Status</th><th>Detail</th></tr></thead><tbody>{coverage}</tbody></table></div></section>
</main></body></html>'''


def write_html_report(path, model):
    """Write a standalone report atomically to the exact requested path."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temporary.write_text(render_html(model), encoding="utf-8")
    temporary.replace(destination)
    return destination
