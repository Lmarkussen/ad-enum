"""LDAP attributes arrive as single-element lists; comparisons must unwrap them."""
from ad_enum.cli import _privileged_group_entries
from ad_enum.inventory import DomainInventory, native_inventory
from ad_enum.posture import _inventory_maps, _principal_is_low_priv


def _inventory_with_list_values():
    inventory = DomainInventory()
    inventory.add("groups", "S-1-5-21-1-2-3-1107",
                  {"sAMAccountName": ["DNSAdmins"], "name": ["DNSAdmins"],
                   "objectClass": ["top", "group"]}, "native-ldap")
    return inventory


def test_privileged_group_entries_unwrap_list_valued_names():
    inventory = _inventory_with_list_values()
    names = {"domain admins", "administrators", "dnsadmins"}

    entries = _privileged_group_entries(inventory, names)

    assert [entry["name"] for entry in entries] == ["DNSAdmins"]
    assert entries[0]["sid"] == "S-1-5-21-1-2-3-1107"


def test_principal_is_low_priv_recognises_privileged_group_with_list_values():
    inventory = _inventory_with_list_values()
    low, reason = _principal_is_low_priv("S-1-5-21-1-2-3-1107", inventory, _inventory_maps(inventory))
    assert low is False and reason == "expected-privileged"


def test_native_inventory_list_values_stay_comparable_via_unwrap():
    raw = {"defaultNamingContext": "DC=example,DC=test", "identities": [
        {"objectClass": ["group"], "objectSid": "S-1-5-21-1-2-3-512",
         "sAMAccountName": ["Domain Admins"], "name": ["Domain Admins"]}]}
    inventory = native_inventory(raw)

    entries = _privileged_group_entries(inventory, {"domain admins"})

    assert [entry["name"] for entry in entries] == ["Domain Admins"]
    # The unwrapped value is what actually matches; str(list) does not.
    assert str(inventory.records["groups"]["s-1-5-21-1-2-3-512"].attributes["sAMAccountName"]) == "['Domain Admins']"
