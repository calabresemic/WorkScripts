Remove-Item C:\Working\PatcherNew\Results\ADUserResults.csv -ErrorAction SilentlyContinue -Force
Remove-Item C:\Working\PatcherNew\Results\ADUserResults.csv -ErrorAction SilentlyContinue -Force

$user = "OU=Misawa AFB Users,OU=Misawa AFB,OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
Get-ADUser -Filter {SmartcardLogonRequired -eq "FALSE"} -Properties * -SearchBase $user | Select-Object Name, EmployeeID | Export-Csv -Path C:\Working\PatcherNew\Results\ADUserResults.csv -NoTypeInformation

$admin = "OU=Misawa AFB, OU=Administrative Accounts,OU=Administration,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
Get-ADUser -Filter {SmartcardLogonRequired -eq "FALSE"} -Properties * -SearchBase $admin | Select-Object Name, EmployeeID | Export-Csv -Path C:\Working\PatcherNew\Results\ADAdminResults.csv -NoTypeInformation