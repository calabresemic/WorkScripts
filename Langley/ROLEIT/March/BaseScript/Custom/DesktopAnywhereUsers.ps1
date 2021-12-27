
$ViewClientPath = 'HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\SessionData\*\'
$ViewClientKey = 'ViewClient_Broker_GatewayHost'
$ViewClientGateway = 'afrcdesktops.us.af.mil'
$Broker = Get-ItemProperty -Path $ViewClientPath

$Properties = 'SamAccountName','Date','ViewClient_Broker_URL','ViewClient_Broker_GatewayLocation','ViewClient_Broker_GatewayHost','ViewClient_Broker_DNS_Name','ViewClient_Machine_Name','ViewClient_Windows_Timezone','PSScriptRoot','VM_Name'
$List = gi "\\uhhz-fs-014\AFRC_SHARED\Scripts\DesktopAnywhereUsers\afrcdesktops.us.af.mil.log" -ErrorAction Stop

#if($Broker.$ViewClientKey -match $ViewClientGateway){
    $append                = $broker | select $Properties
    $append.SamAccountName = $env:USERNAME
    $append.Date           = (Get-Date).ToUniversalTime()
    $append.PSScriptRoot   = $PSScriptRoot
    $append.VM_Name        = $env:COMPUTERNAME
    $append | Export-Csv $list -NoTypeInformation -Append -ErrorAction Stop
#} # End If External

<#
###################
### Replace scripts
$HC = '52UHHZ-HC-003V','52UHHZ-HC-004V'
$AFB = 'ARPC_Logon','Carswell_Logon','Dobbins_Logon','Grissom_Logon','Homestead_Logon','March_Logon','Minneapolis_Logon','Niagara_Logon','Pittsburgh_Logon','Westover_Logon','Youngstown_Logon','LogonScripts'#HQ_AFRC_AFB

$OldScript = [System.Collections.ArrayList]@()
ForEach($dc in $HC){
    ForEach($base in $AFB){
        $OldScript.Add("\\$dc\$base\BaseScript\Custom\desktopanywhereusers.ps1") | Out-Null
    }
}

$OldScript | % { if(test-path $_){gi $_ | select lastwritetime,fullname}else{"$false | $_"} }
$Destination = $OldScript | % { gi $_ }

$Source = gi '\\uhhz-fs-014\AFRC_SHARED\Scripts\DesktopAnywhereUsers\DesktopAnywhereUsers.ps1'
$Destination | % { Copy-Item $Source $_ -verbose }
$gold = gi '\\uhhzic55-master\c$\Image Prep\Logon Scripts\DesktopAnywhereUsers.ps1'
copy-item $Source $Gold -Verbose

###################
### Replace old CSV
copy-item $NewList $OldList

#>

