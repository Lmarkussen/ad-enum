# LAB ONLY. Removes only objects created by setup_live_fixtures.ps1.
[CmdletBinding(SupportsShouldProcess)]
param()
Import-Module ActiveDirectory
foreach ($name in @('adenum-asrep-test','adenum-pwdnr','adenum-krbtest','adenum-unconst','adenum-const')) {
  Remove-ADUser -Identity $name -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-ADComputer -Identity 'ADENUM-RBCD-SOURCE' -Confirm:$false -ErrorAction SilentlyContinue
Remove-ADServiceAccount -Identity 'adenum-gmsa-test' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output 'AD-Enum lab fixtures removed.'
