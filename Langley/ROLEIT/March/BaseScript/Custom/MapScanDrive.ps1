
switch -regex ($env:COMPUTERNAME) {
    'UHHZ' {$ScanPath = "\\uhhz-fs-016\home" ; $DriveLetter = 'S:'}
    'ARTY' {$ScanPath = "\\Arpfs04\home"     ; $DriveLetter = 'S:'}
    'DDPK' {$ScanPath = "\\fwhfs01\home"     ; $DriveLetter = 'S:'}
    'FGWB' {$ScanPath = "\\fgwb-fs-010\home" ; $DriveLetter = 'S:'}
    'CTGC' {$ScanPath = "\\ctgc-fs-001\HOME" ; $DriveLetter = 'S:'}
    'KYJX' {$ScanPath = "\\hstfs05\home"     ; $DriveLetter = 'S:'}
    'PCZP' {$ScanPath = "\\rivfs22\home"     ; $DriveLetter = 'S:'}
    'QJKL' {$ScanPath = "\\mspfs04\HOME"     ; $DriveLetter = 'S:'}
    'RVKC' {$ScanPath = "\\iagfs01\HOME"     ; $DriveLetter = 'S:'}
    'THGC' {$ScanPath = "\\thgc-fs-005v\home"; $DriveLetter = 'N:'}
    'YUDZ' {$ScanPath = "\\yudz-fs-007\home" ; $DriveLetter = 'Q:'}
    'ZQEA' {$ScanPath = "\\yngfs05\home"     ; $DriveLetter = 'S:'}
}

function Map-Drive {
    Param(
        [Parameter(Mandatory=$True)][string]$DriveLetter,
        [Parameter(Mandatory=$True)][string]$FullPath,
        [Parameter(Mandatory=$False)][string]$FriendlyName
    )
    $ComObject = New-Object -ComObject Wscript.Network
    $ComObject.RemoveNetworkDrive($DriveLetter,$true,$true)
    $ComObject.MapNetworkDrive($DriveLetter,$FullPath,$true)
    if($FriendlyName){
        $sh = New-Object -ComObject shell.application
        $sh.NameSpace($DriveLetter).Self.Name = $FriendlyName
    }
}

Map-Drive -DriveLetter $DriveLetter -FullPath $ScanPath -FriendlyName "Scanned_Documents"

<#

$HC = '52UHHZ-HC-003V','52UHHZ-HC-004V'
$AFB = 'LogonScripts','ARPC_Logon','Carswell_Logon','Dobbins_Logon','Grissom_Logon','Homestead_Logon','March_Logon','Minneapolis_Logon','Niagara_Logon','Pittsburgh_Logon','Westover_Logon','Youngstown_Logon'

$Destination = ForEach($base in $AFB){
    ForEach($dc in $HC){
        "\\$dc\$base\BaseScript\Custom\"
    }
}

$Source = gi "\\uhhz-fs-014\AFRC_ALL_ADMINS_SHARED\Functional Areas\Automation\Scripts-Production\Logon Backup\LogonScripts\BaseScript\Custom\MapScanDrive.ps1"
$Destination | % {Copy-Item $Source $_ -Verbose}

#>