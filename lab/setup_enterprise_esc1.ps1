# LAB ONLY. Run on the authorized CA/DC with an explicitly authorized
# Enterprise Admin credential. This script intentionally contains no password.
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)] [pscredential] $EnterpriseAdminCredential,
  [string] $CACommonName = "SCCMLAB-RootCA",
  [string] $TemplateName = "Snablr-ESC1-Lab",
  [string] $EnrollmentPrincipal = "SCCMLAB\Domain Users"
)

Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName $CACommonName `
  -Credential $EnterpriseAdminCredential -KeyLength 2048 -HashAlgorithmName SHA256 `
  -ValidityPeriod Years -ValidityPeriodUnits 10 -Force

# Create the template with certtmpl.msc: duplicate User, name it $TemplateName,
# enable “Supply in the request”, retain Client Authentication EKU, leave manager
# approval/signatures disabled, and grant $EnrollmentPrincipal Enroll.
# Windows has no supported built-in New-CertificateTemplate cmdlet.

certutil.exe -setcatemplates +$TemplateName
certutil.exe -catemplates
Get-Service CertSvc | Format-List Name,Status,StartType
Write-Host "Verify $TemplateName through LDAP and Certipy before optional enrollment."
