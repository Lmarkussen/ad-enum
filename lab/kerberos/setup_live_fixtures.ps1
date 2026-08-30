# LAB ONLY. Run with an explicitly authorized domain administrator credential.
# This script creates detector fixtures; it is never called by AD-Enum.
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$Domain = 'SCCM.LAB',
  [string]$DnsSuffix = 'sccm.lab',
  [string]$FixturePassword = $(throw 'Use an ephemeral password supplied by the operator')
)

Import-Module ActiveDirectory
$secure = ConvertTo-SecureString $FixturePassword -AsPlainText -Force
$ou = "OU=ADEnum-Lab,$((Get-ADDomain).DistinguishedName)"
if (-not (Get-ADOrganizationalUnit -Identity $ou -ErrorAction SilentlyContinue)) {
  New-ADOrganizationalUnit -Name 'ADEnum-Lab' -Path (Get-ADDomain).DistinguishedName
}
function Ensure-User($name, $uac, $spn = $null) {
  $u = Get-ADUser -Identity $name -ErrorAction SilentlyContinue
  if (-not $u) { New-ADUser -Name $name -SamAccountName $name -Path $ou -AccountPassword $secure -Enabled $true }
  Set-ADUser -Identity $name -Replace @{userAccountControl=$uac}
  if ($spn) { Set-ADUser -Identity $name -ServicePrincipalNames @{Add=$spn} }
}

# 512 normal enabled user; add only the one detector-specific bit.
Ensure-User 'adenum-asrep-test' (0x200 + 0x400000)
Ensure-User 'adenum-pwdnr' (0x200 + 0x20)
Ensure-User 'adenum-krbtest' 0x200 "MSSQLSvc/adenum-krbtest.${DnsSuffix}:1433"
Ensure-User 'adenum-unconst' (0x200 + 0x80000) "HOST/adenum-unconst.$DnsSuffix"
Ensure-User 'adenum-const' 0x200 "HOST/adenum-const.$DnsSuffix"
Set-ADUser 'adenum-const' -Add @{'msDS-AllowedToDelegateTo'="HOST/$DnsSuffix"}

# RBCD uses an ordinary computer source and the existing CLIENT target.
$source = Get-ADComputer 'ADENUM-RBCD-SOURCE' -ErrorAction SilentlyContinue
if (-not $source) { $source = New-ADComputer -Name 'ADENUM-RBCD-SOURCE' -SamAccountName 'ADENUM-RBCD-SOURCE$' -Path "CN=Computers,$((Get-ADDomain).DistinguishedName)" -PassThru }
$target = Get-ADComputer 'CLIENT'
Set-ADComputer $target -PrincipalsAllowedToDelegateToAccount $source

# gMSA creation is best-effort because it requires a KDS root key in the lab.
if (-not (Get-ADServiceAccount 'adenum-gmsa-test' -ErrorAction SilentlyContinue)) {
  New-ADServiceAccount -Name 'adenum-gmsa-test' -DNSHostName "adenum-gmsa-test.$DnsSuffix" `
    -PrincipalsAllowedToRetrieveManagedPassword "$Domain\Domain Users" `
    -ServicePrincipalNames "HOST/adenum-gmsa-test.$DnsSuffix"
}
Write-Output 'AD-Enum lab fixtures configured.'
