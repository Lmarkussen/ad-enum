"""Negative ADCS regressions derived from the controlled Certipy 5.1 lab matrix."""
import copy
import json
import sys
from pathlib import Path

import pytest

from ad_enum.adapters.certipy import CertipyAdapter
from ad_enum.adcs import scan
from ad_enum.core.corroboration import Corroboration, SourceAssessment
from ad_enum.fixtures import ldap_fixture, _sd, _ace, DOMAIN
from ad_enum.normalize import normalize_directory
from ad_enum.security import ENROLL_GUID
from ad_enum.cli import _finding_lines

FIXTURE = Path(__file__).parent / 'fixtures/certipy_5_1_esc8_no_templates.json'
CA_NAME = 'LabCA'
CASES = ('NoEnroll', 'NoAuthEKU', 'Approval', 'Signatures', 'Unpublished', 'Positive')


def matrix_raw():
    raw = ldap_fixture('A')
    raw['templates'] = []
    raw['cas'][0]['certificateTemplates'] = []
    privileged = DOMAIN + '-1101'
    raw['identities'].append({
        'distinguishedName': 'CN=Privileged,DC=example,DC=test',
        'sAMAccountName': 'Privileged', 'objectSid': privileged,
        'objectClass': ['top', 'person', 'user'], 'primaryGroupID': 512,
        'userAccountControl': 512, 'memberOf': [],
    })
    for case in CASES:
        t = copy.deepcopy(ldap_fixture('A')['templates'][0])
        t['cn'] = t['displayName'] = 'Example-ESC1-' + case
        t['distinguishedName'] = f"CN={t['cn']},CN=Certificate Templates,DC=example,DC=test"
        if case == 'NoEnroll': t['nTSecurityDescriptor'] = _sd(_ace(privileged, object_type=ENROLL_GUID))
        if case == 'NoAuthEKU': t['pKIExtendedKeyUsage'] = ['1.3.6.1.5.5.7.3.3']
        if case == 'Approval': t['msPKI-Enrollment-Flag'] = 2
        if case == 'Signatures': t['msPKI-RA-Signature'] = 1
        if case != 'Unpublished': raw['cas'][0]['certificateTemplates'].append(t['cn'])
        raw['templates'].append(t)
    return raw


def matrix_certipy():
    data = json.loads(FIXTURE.read_text())
    data['Certificate Templates'] = {}
    for i, case in enumerate(CASES):
        t = {'Template Name': 'Example-ESC1-' + case,
             'Enabled': case != 'Unpublished', 'Certificate Authorities': [CA_NAME] if case != 'Unpublished' else [],
             'Client Authentication': case != 'NoAuthEKU', 'Enrollee Supplies Subject': True,
             'Certificate Name Flag': [1], 'Enrollment Flag': [2] if case == 'Approval' else [],
             'Extended Key Usage': ['Code Signing' if case == 'NoAuthEKU' else 'Client Authentication'],
             'Requires Manager Approval': case == 'Approval', 'Authorized Signatures Required': int(case == 'Signatures')}
        if case not in {'NoEnroll', 'Unpublished'}: t['[+] User Enrollable Principals'] = [r'EXAMPLE\Domain Users']
        if case == 'Positive': t['[!] Vulnerabilities'] = {'ESC1': 'Enrollee supplies subject and template allows client authentication.'}
        data['Certificate Templates'][str(i)] = t
    return data


@pytest.mark.parametrize('case', CASES)
def test_full_esc1_negative_matrix(case):
    _, cas, templates = normalize_directory(matrix_raw())
    findings, _, _, _, _ = scan(cas, templates)
    _, _, assessment = next(row for row in findings if row[0].name == 'Example-ESC1-' + case)
    assert assessment.vulnerable is (case == 'Positive')
    if case != 'Positive': assert assessment.evidence.reasons
    if case == 'Unpublished': assert assessment.evidence.published_by == []


def test_disabled_account_is_not_a_low_privileged_enroller():
    raw = matrix_raw()
    raw['identities'][-1].update(primaryGroupID=513, userAccountControl=514)
    _, cas, templates = normalize_directory(raw)
    assert not scan(cas, templates)[0][0][2].vulnerable


def test_cross_sid_deny_applies_to_every_member_token():
    raw = ldap_fixture('A')
    raw['templates'][0]['nTSecurityDescriptor'] = _sd(
        _ace('S-1-5-11', allow=False, object_type=ENROLL_GUID),
        _ace(DOMAIN + '-513', object_type=ENROLL_GUID))
    _, cas, templates = normalize_directory(raw)
    assert not scan(cas, templates)[0][0][2].vulnerable
    assert not templates[0].enroll_sids
    assert templates[0].evidence['principal_tokens']


def test_different_users_memberships_are_not_combined():
    raw = ldap_fixture('A')
    raw['identities'] = [
        {'distinguishedName': f'CN={name},DC=example,DC=test', 'objectSid': DOMAIN + '-' + rid,
         'objectClass': ['user'], 'primaryGroupID': 513, 'sAMAccountName': name}
        for name, rid in [('Allowed', '1101'), ('Denied', '1102')]]
    raw['templates'][0]['nTSecurityDescriptor'] = _sd(
        _ace(DOMAIN + '-1102', allow=False, object_type=ENROLL_GUID),
        _ace(DOMAIN + '-1101', object_type=ENROLL_GUID))
    _, cas, templates = normalize_directory(raw)
    assert scan(cas, templates)[0][0][2].vulnerable
    assert templates[0].enroll_sids == {DOMAIN + '-1101'}


def test_current_certipy_ca_survives_unavailable_template_section():
    snapshot = CertipyAdapter().from_json(FIXTURE)
    assert snapshot.template_enumeration_state == 'UNAVAILABLE'
    assert snapshot.assessments == {}
    ca = snapshot.normalized_cas()[0]
    assert ca.name == 'Example-CA' and ca.hostname == 'ca.example.test'
    assert ca.evidence['raw']['Web Enrollment']['http']['enabled'] is True
    assert [r['rule'] for r in snapshot.vulnerability_records()] == ['ESC8']


@pytest.mark.parametrize('identifier', ['ESC10', 'ESC11', 'ESC13', 'ESC15', 'ESC17'])
def test_esc1_identifier_is_exact(identifier):
    s = CertipyAdapter().from_json({'Certificate Templates': {'0': {
        'Template Name': 'Other', '[!] Vulnerabilities': {identifier: 'Different condition'}}}})
    assert s.assessments['Other'].vulnerable is not True
    assert s.vulnerability_records()[0]['rule'] == identifier


def test_unknown_enrollment_scope_is_not_disagreement_or_corroboration():
    t = matrix_certipy()['Certificate Templates']['5']
    del t['[!] Vulnerabilities']; del t['[+] User Enrollable Principals']
    assessment = CertipyAdapter().from_json({'Certificate Templates': {'0': t}}).assessments[t['Template Name']]
    assert assessment.vulnerable is None
    comparison = Corroboration(t['Template Name'], [SourceAssessment('ldap-native', True), assessment])
    assert comparison.status == 'single-source'
    comparison.assessments.append(SourceAssessment('ldap-native', True))
    assert comparison.status == 'single-source'


def test_real_disagreement_is_not_rendered_as_confirmed():
    finding = {'rule': 'ESC1', 'category': 'ADCS', 'title': 'ESC1 — Example', 'status': 'disagreement',
               'evidence': {}, 'sources': [{'source': 'ldap-native', 'vulnerable': True}, {'source': 'certipy', 'vulnerable': False}]}
    output = '\n'.join(_finding_lines([finding]))
    assert 'DISAGREEMENT' in output and 'CONFIRMED' not in output


@pytest.mark.parametrize('templates_available', [True, False])
def test_esc1_matrix_and_esc8_reach_all_report_artifacts(tmp_path, monkeypatch, templates_available):
    from test_pipeline_smoke import configure_pipeline, FakeCollector
    from ad_enum import cli
    configure_pipeline(monkeypatch, tmp_path, lambda *a, **k: {
        'hosts': [], 'management_points': [], 'distribution_points': [], 'site_servers': [],
        'sms_providers': [], 'sql_servers': [], 'sup_wsus': [], 'pxe': {'status': 'NOT TESTED'}})
    raw = matrix_raw()
    class Collector(FakeCollector):
        def preflight(self): return 'DC=example,DC=test', 'CN=Configuration,DC=example,DC=test'
        def collect(self): return normalize_directory(self.raw)
    Collector.raw = raw
    monkeypatch.setattr(cli, 'Collector', Collector)
    monkeypatch.setattr(cli, 'execute_external', lambda *a, **k: ({}, []))
    data = matrix_certipy() if templates_available else json.loads(FIXTURE.read_text())
    # Repeated CA entries must not duplicate the finding.
    data['Certificate Authorities']['1'] = copy.deepcopy(data['Certificate Authorities']['0'])
    artifact = tmp_path / 'certipy.json'; artifact.write_text(json.dumps(data))
    html = tmp_path / 'report.html'
    monkeypatch.setattr(sys, 'argv', ['ad-enum.py', '-u', 'fixture', '-p', 'synthetic', '-domain', 'example.test',
                                    '-dc-ip', '192.0.2.10', '--modules', 'adcs', '--output-dir', str(tmp_path),
                                    '--certipy-json', str(artifact), '--html-out', str(html), '--no-color'])
    assert cli.main() == 0
    root = tmp_path / 'example.test'
    rows = json.loads((root / 'ADCS/findings.json').read_text())
    esc1 = [x for x in rows if x['rule'] == 'ESC1']
    assert len(esc1) == 1 and esc1[0]['evidence']['template'] == 'Example-ESC1-Positive'
    esc8 = [x for x in rows if x['rule'] == 'ESC8']
    assert len(esc8) == 1 and esc8[0]['status'] == 'single-source'
    assert [x['source'] for x in esc8[0]['sources']] == ['certipy']
    assert esc8[0]['evidence']['certipy']['Web Enrollment']['http']['enabled'] is True
    for file in (root / 'results.txt', html):
        text = file.read_text()
        assert 'ESC8' in text and 'Example-CA' in text
        assert '\x1b[' not in text
    text = (root / 'results.txt').read_text()
    assert 'Web enrollment HTTP' in text and 'ENABLED' in text
    assert '/certsrv/' not in text  # URL was not supplied by this JSON artifact.
    evaluations = json.loads((root / 'ADCS/evaluations.json').read_text())
    assert len(evaluations) == 6
    assert sum(x['vulnerable'] for x in evaluations) == 1
