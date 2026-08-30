# LAB ONLY. Removes only objects created by setup_live_fixtures.ps1.
[CmdletBinding(SupportsShouldProcess)]
param()
Import-Module ActiveDirectory
foreach ($name in @('adenum-asrep-test','adenum-passwdnotreqd-test','adenum-kerberoast-test','adenum-unconstrained-test','adenum-constrained-test')) {
  Remove-ADUser -Identity $name -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-ADComputer -Identity 'ADENUM-RBCD-SOURCE' -Confirm:$false -ErrorAction SilentlyContinue
Remove-ADServiceAccount -Identity 'adenum-gmsa-test' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output 'AD-Enum lab fixtures removed.'
