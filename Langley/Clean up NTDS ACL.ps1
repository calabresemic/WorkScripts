$sddl="O:SYG:DUD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

$FolderToConfigure="E:\Windows\NTDS"

$securityDescriptor = Get-Acl -Path $FolderToConfigure
$securityDescriptor.SetSecurityDescriptorSddlForm($sddl)
Set-Acl -Path $FolderToConfigure -AclObject $securityDescriptor 