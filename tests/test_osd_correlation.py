"""Unit coverage for correlating raw PXEThief OSD variables into credentials."""
from ad_enum.pxethief_adapter import correlate_pxethief_recovered


def _names(result):
    return [credential["type"] for credential in result["credentials"]]


def test_join_account_and_password_in_one_step_pair_into_a_credential():
    result = correlate_pxethief_recovered([
        {"name": "OSDJoinAccount", "value": r"sccm.lab\sccm-naa",
         "step": "Apply Network Settings"},
        {"name": "OSDJoinPassword", "value": "JoinSecret",
         "step": "Apply Network Settings"}])

    assert _names(result) == ["Domain Join Password"]
    credential = result["credentials"][0]
    assert credential["account"] == r"sccm.lab\sccm-naa"
    assert credential["value"] == "JoinSecret"
    assert credential["step"] == "Apply Network Settings"
    # Original variable names are preserved for structured evidence.
    assert credential["raw"] == ["OSDJoinAccount", "OSDJoinPassword"]
    assert result["accounts"] == [] and result["metadata"] == []


def test_account_and_password_from_different_steps_are_not_cross_paired():
    result = correlate_pxethief_recovered([
        {"name": "OSDJoinAccount", "value": "ACCT-A", "step": "Step A"},
        {"name": "OSDJoinAccount", "value": "ACCT-B", "step": "Step B"},
        {"name": "OSDJoinPassword", "value": "PASS-B", "step": "Step B"}])

    assert _names(result) == ["Domain Join Password"]
    assert result["credentials"][0]["account"] == "ACCT-B"
    assert [account["account"] for account in result["accounts"]] == ["ACCT-A"]


def test_local_admin_password_gets_default_administrator_account():
    result = correlate_pxethief_recovered([
        {"name": "OSDLocalAdminPassword", "value": "LocalSecret",
         "step": "Apply Windows Settings"}])

    assert _names(result) == ["Local Administrator Password"]
    assert result["credentials"][0]["account"] == "Administrator"
    assert result["credentials"][0]["step"] == "Apply Windows Settings"


def test_registered_user_is_metadata_never_a_credential():
    result = correlate_pxethief_recovered([
        {"name": "OSDRegisteredUserName", "value": "User",
         "step": "Apply Windows Settings"}])

    assert result["credentials"] == []
    assert result["metadata"] == [{"label": "Registered User", "value": "User",
                                   "step": "Apply Windows Settings",
                                   "name": "OSDRegisteredUserName"}]


def test_network_access_account_stays_paired():
    result = correlate_pxethief_recovered([
        {"name": "NetworkAccessAccount", "username": r"SCCMLAB\naa-lab",
         "value": "NaaSecret"}])

    assert _names(result) == ["Network Access Account"]
    assert result["credentials"][0]["account"] == r"SCCMLAB\naa-lab"
    assert result["credentials"][0]["value"] == "NaaSecret"


def test_join_password_without_account_is_still_a_credential():
    result = correlate_pxethief_recovered([
        {"name": "OSDJoinPassword", "value": "OnlySecret",
         "step": "Apply Network Settings"}])

    assert _names(result) == ["Domain Join Password"]
    assert result["credentials"][0]["account"] == ""
    assert result["credentials"][0]["value"] == "OnlySecret"


def test_join_account_without_password_is_not_a_credential():
    result = correlate_pxethief_recovered([
        {"name": "OSDJoinAccount", "value": r"sccm.lab\svc-join",
         "step": "Apply Network Settings"}])

    assert result["credentials"] == []
    assert [account["account"] for account in result["accounts"]] == [r"sccm.lab\svc-join"]


def test_multiple_join_credentials_render_deterministically():
    result = correlate_pxethief_recovered([
        {"name": "OSDJoinAccount", "value": "ACCT-1", "step": "S"},
        {"name": "OSDJoinPassword", "value": "PASS-1", "step": "S"},
        {"name": "OSDJoinAccount", "value": "ACCT-2", "step": "S"},
        {"name": "OSDJoinPassword", "value": "PASS-2", "step": "S"}])

    assert [(c["account"], c["value"]) for c in result["credentials"]] == [
        ("ACCT-1", "PASS-1"), ("ACCT-2", "PASS-2")]


def test_non_value_items_are_ignored():
    result = correlate_pxethief_recovered([
        {"name": "media", "media_file": r"\SMS\variables.dat"},
        {"name": "bcd", "bcd_file": r"\SMS\boot.bcd"},
        {"name": "identifier", "assignment": "RECEIVED"}])

    assert result == {"credentials": [], "accounts": [], "metadata": []}


def test_full_lab_shaped_set_correlates_into_three_credentials():
    result = correlate_pxethief_recovered([
        {"name": "NetworkAccessAccount", "username": r"SCCMLAB\naa-lab", "value": "Naa"},
        {"name": "OSDRegisteredUserName", "value": "User", "step": "Apply Windows Settings"},
        {"name": "OSDLocalAdminPassword", "value": "Local", "step": "Apply Windows Settings"},
        {"name": "OSDJoinAccount", "value": r"sccm.lab\sccm-naa",
         "step": "Apply Network Settings"},
        {"name": "OSDJoinPassword", "value": "Join", "step": "Apply Network Settings"}])

    assert _names(result) == ["Network Access Account", "Local Administrator Password",
                              "Domain Join Password"]
    assert [entry["label"] for entry in result["metadata"]] == ["Registered User"]
