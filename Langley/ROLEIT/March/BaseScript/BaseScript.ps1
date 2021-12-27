# Functions to get nested groups of current user
function Get-Groups
{
    Param ( [string]$object )
	
    $name = $($($object.Split(','))[0]).Replace('CN=','')
	
    $strFilter = "(&(objectCategory=Group)(samAccountName=$name))"

    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.Filter = $strFilter

    $objPath = $objSearcher.FindOne()
    $objGroup = If ($objPath -ne $null) {$objPath.GetDirectoryEntry()} Else {$null}
	
    $objGroup.memberOf
}

Function Get-UserGroups
{
    Param ( [string]$object )

    $strName = $object

    $strFilter = "(&(objectCategory=User)(samAccountName=$strName))"

    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.Filter = $strFilter

    $objPath = $objSearcher.FindOne()
    $objUser = $objPath.GetDirectoryEntry()

    $AllGroups = @()

    foreach ($item in $objUser.memberOf)
    {	
        $AllGroups += $item
		
        [array]$Groups = Get-Groups $item
		
        While ($Groups -ne $null)
        {
            Foreach ($Group in $Groups)
            {
                If ($group -ne '')
                {
                    $AllGroups += $Group
                }
            }
			
            $Groups.Clear()
            [array]$Groups = Get-Groups $Group		
        }
    }
	
    Foreach ($item in $AllGroups)
    {
        $name = If ($item -ne '') {$($($item.Split(','))[0]).Replace('CN=','')} Else {$null}
        $name
    }
}

Function Remove-Shortcut
{
    Param ( [Parameter(Mandatory=$true)] [string]$Name )
    
    Remove-Item -Path "$UserProfile\desktop\$Name" -Force -ErrorAction SilentlyContinue
}

Function Copy-Shortcut
{
    Param ( 
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $false)] [array]$Groups,
        [Parameter(Mandatory = $false)] [array]$Users,
        [Parameter(Mandatory = $false)] [switch]$All
    )
    
    Begin
    { 
        $SourcePath = $currentdir + '\Shortcuts\' + $Name
        $DestPath = $UserProfile + '\Desktop\' + $Name
    }
    
    Process
    { 
        If ($Groups) 
        {
            Foreach ($Group in $Groups)
            {
                If ($GroupMembership -contains $Group)
                {
                    Remove-Item -Path $DestPath -Force -ErrorAction SilentlyContinue
                    Copy-Item -Path $SourcePath -Destination $DestPath -Force
                }
            }
        }
        ElseIf ($Users)
        {
            If ($Users -contains $env:USERNAME)
            {
                Remove-Item -Path $DestPath -Force -ErrorAction SilentlyContinue
                Copy-Item -Path $SourcePath -Destination $DestPath -Force
            }
        }
        ElseIf ($All)
        {
            Remove-Item -Path $DestPath -Force -ErrorAction SilentlyContinue
            Copy-Item -Path $SourcePath -Destination $DestPath -Force
        }
    } 
}

function Get-Shortcut 
{
    [CmdletBinding()]
    Param (
        $path = $null
    )

    $obj = New-Object -ComObject WScript.Shell

    if ($path -eq $null) 
    {
        $pathUser = [System.Environment]::GetFolderPath('StartMenu')
        $pathCommon = $obj.SpecialFolders.Item('AllUsersStartMenu')
        $path = dir $pathUser, $pathCommon -Filter *.lnk -Recurse 
    }
    
    if ($path -is [string]) 
    {
        $path = dir $path -Filter *.lnk
    }
    
    $path | ForEach-Object { 
        if ($_ -is [string]) 
        {
            $_ = dir $_ -Filter *.lnk
        }
        
        if ($_) 
        {
            $link = $obj.CreateShortcut($_.FullName)

            $info = @{}
            $info.Hotkey = $link.Hotkey
            $info.TargetPath = $link.TargetPath
            $info.LinkPath = $link.FullName
            $info.Arguments = $link.Arguments
            $info.Target = try {Split-Path $info.TargetPath -Leaf } catch { 'n/a'}
            $info.Link = try { Split-Path $info.LinkPath -Leaf } catch { 'n/a'}
            $info.WindowStyle = $link.WindowStyle
            $info.IconLocation = $link.IconLocation

            New-Object PSObject -Property $info
        }
    }
}

function Set-Shortcut 
{
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $LinkPath,
        $Hotkey,
        $IconLocation,
        $Arguments,
        $TargetPath
    )
    
    begin 
    {
        $shell = New-Object -ComObject WScript.Shell
    }

    process 
    {
        $link = $shell.CreateShortcut($LinkPath)

        $PSCmdlet.MyInvocation.BoundParameters.GetEnumerator() |
            Where-Object { $_.key -ne 'LinkPath' } |
            ForEach-Object { $link.$($_.key) = $_.value }
        $link.Save()
    }
}

Function Create-Shortcut
{
    Param (
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [string]$IconPath,
        [Parameter(Mandatory = $true)] [string]$TargetPath,
        [Parameter(Mandatory = $false)] [array]$Groups,
        [Parameter(Mandatory = $false)] [array]$Users,
        [Parameter(Mandatory = $false)] [switch]$All
    )
    
    Begin
    {
        $Appfolder = $env:USERPROFILE + '\AppData\Local\'
        $ShortcutPath = $env:USERPROFILE + '\Desktop\' + $Name
        
        $create = $false
        $set = $false
    }
    
    Process
    {
        If ($Groups) 
        {
            Foreach ($Group in $Groups)
            {
                If ($GroupMembership -contains $Group)
                {
                    $create = $true
                }
            }
        }
        ElseIf ($Users)
        {
            If ($Users -contains $env:USERNAME)
            {
                $create = $true
            }
        }
        ElseIf ($All)
        {
            $create = $true
        }
        
        If ($create)
        { 
            $old = Get-Shortcut -path $ShortcutPath -ErrorAction SilentlyContinue
            
            If (($old.TargetPath -ne $TargetPath) -or ($old.IconLocation -ne $IconPath))
            {
                # Copy icon to local machine
                If ($IconPath -notlike "C:\*")
                { 
                    $array = $IconPath.split('\')
                    $Icon = $array[$($array.count -1)]

                    Copy-Item -Path $IconPath -Destination $Appfolder -Force

                    $IconLocation = $Appfolder + $Icon
                }
        
                # Remove old shortcut
                Remove-Item $ShortcutPath -Force -ErrorAction SilentlyContinue
        
                # Create Shortcut
                Set-Shortcut -LinkPath $ShortcutPath -IconLocation $IconLocation -TargetPath $TargetPath
            }
        }
    }
}

###########################################
###########  Script Variables  ############
###########################################

# Get script directoy
$currentdir            = Split-Path $($MyInvocation.MyCommand.Path)

# Setting the script to ignore all errors and continue
$ErrorActionPreference = 'SilentlyContinue'

# Getting the current user login names
$currentUser           = $env:USERNAME
$eid = $env:username -replace '.*(\d{10}).*','$1' 
#$EID = Get-ADUser $env:USERNAME -Properties Employeeid | Select-Object -ExpandProperty EmployeeID

# Enumerating nested groups of current user
$GroupMembership       = Get-UserGroups $currentUser

# Define Path to User Profile
$UserProfile           = $env:USERPROFILE

# External Scripts
$Form4394              = $currentdir + '\FORM4394\MSP_Form4394_Logon_v1.0.vbs'
$ColComputing          = $currentdir + '\COLLABORATIVE_COMPUTING_AGREEMENT\MSP_COLLABORATIVE_COMPUTING_AGREEMENT_Logon_v1.0.vbs'
$McAfee                = $currentdir + '\McAfee\McAfeeUpdate.vbs'
$VPNFix                = $currentdir + '\VPNFIX\VPNFIX.ps1'
#$UpdateSharePaths      = $currentdir + '\Update-SharePaths\Update-SharePaths.ps1'
#$MigratePrinter        = $currentdir + '\Custom\remap_printers.vbs'
#$hp640                 = $currentdir + '\Custom\hp640.ps1'

#Map Scan Drives
$MapScanDrive = "$currentdir\custom\MapScanDrive.ps1"

###########################################
########  Setting Drive Mappings  #########
###########################################

If ($GroupMembership -contains 'MSP_DOMAIN USERS') {
	NET USE F: /d /Y
	NET USE R: /d /Y
    NET USE Q: /d /Y
	NET USE F: '\\QJKL-FS-003.AREA52.AFNOAPPS.USAF.MIL\F DRIVE 2'
	NET USE R: '\\QJKL-FS-004.AREA52.AFNOAPPS.USAF.MIL\R DRIVE'
    NET USE Q: "\\qjkl-fs-101\VDI_Profiles\$currentUser\Documents"
}

If ($GroupMembership -contains 'GLS_Minneapolis_CFP-CSA') {
	NET USE Z: /d /Y
	NET USE Z: '\\QJKL-FS-002.AREA52.AFNOAPPS.USAF.MIL\PROGRAMS'
}

If ($GroupMembership -contains 'GLS_934 CS_PROGRAMS_DRIVE') {
	NET USE Z: /d /Y
	NET USE Z: '\\QJKL-FS-002.AREA52.AFNOAPPS.USAF.MIL\PROGRAMS'
}

If ($GroupMembership -contains '934_NS Admins') {
	NET USE N: /d /Y
	NET USE N: '\\QJKL-FS-002.AREA52.AFNOAPPS.USAF.MIL\SCOO'
}

If ($GroupMembership -contains 'MSP_934ALPHA') {
	NET USE S: /d /Y
	NET USE S: '\\QJKL-FS-002.AREA52.AFNOAPPS.USAF.MIL\ALPHA'
}

If ($GroupMembership -contains 'GLS_934_ALPHA_RO') {
	NET USE S: /d /Y
	NET USE S: '\\QJKL-FS-002.AREA52.AFNOAPPS.USAF.MIL\ALPHA'
}

If ($GroupMembership -contains 'GLS_934OG_TacticsUsers') {
	NET USE P: /d /Y
	NET USE P: '\\QJKL-FS-004.AREA52.AFNOAPPS.USAF.MIL\PFPS'
}

If ($GroupMembership -contains 'GLS_934OG_TacticsUsers') {
	NET USE M: /d
	NET USE M: '\\QJKL-FS-004.AREA52.AFNOAPPS.USAF.MIL\Map Data'
}

If ($GroupMembership -contains '934_ASTS_Group') {
	NET USE F: /d /Y
	NET USE F: '\\QJKL-FS-003.AREA52.AFNOAPPS.USAF.MIL\F DRIVE'
}

If ($GroupMembership -contains '934_AW_Group') {
	NET USE F: /d /Y
	NET USE F: '\\QJKL-FS-003.AREA52.AFNOAPPS.USAF.MIL\F DRIVE'
}

If ($GroupMembership -contains '934_OG_Group') {
	NET USE F: /d /Y
	NET USE F: '\\QJKL-FS-003.AREA52.AFNOAPPS.USAF.MIL\F DRIVE'
}

If ($GroupMembership -contains 'MSP_934OSS') {
	NET USE F: /d /Y
	NET USE F: '\\QJKL-FS-003.AREA52.AFNOAPPS.USAF.MIL\F DRIVE'
}

If ($GroupMembership -contains 'MSP_934_MunitionsDocControl_RC') {
	NET USE F: /d /Y
	NET USE F: '\\QJKL-FS-003.AREA52.AFNOAPPS.USAF.MIL\F DRIVE'
}

If ($GroupMembership -contains 'MSP_Domain Users') {
	NET USE H: /d /Y
	NET USE H: \\QJKL-FS-001.AREA52.AFNOAPPS.USAF.MIL\USERS\$EID /Persistent:Yes
}

If ($GroupMembership -contains 'MSP_Domain Admins') {
	NET USE H: /d /Y
	NET USE H: \\QJKL-FS-001.AREA52.AFNOAPPS.USAF.MIL\USERS\$EID /Persistent:Yes
}
###########################################
#########  Collabortive Computing  ########
###########################################

# Collaborative Computer Awareness Popup
$msg = "(1)  Look at the wall areas the camera faces. Remove any sensitive information from those wall areas including anything sensitive that may be beyond the confines of the user's office.`n
    (2) Remove any sensitive information from the use'rs desktop area to preclude inadvertent remote viewing of such information should the webcam fall from its perch.`n
    (3) Alert employees in the immediate work area to suspend any sensitive conversations until the webcam conversation are completed.`n
    (4) Post a sign at the office or cubicle entrance to alert others that an unclassified webcam conversation is taking place`n
    (5) Follow incident-reporting procedures if transmission of classified material by visual or other means occurs over an unclassified webcam."

$wshell = New-Object -ComObject Wscript.Shell
$wshell.Popup("$msg",0,'Collaborative Computing Awareness$su',0x1000)

#If ($GroupMembership -contains 'GLS_934 CS_TEST') { 
#If ($GroupMembership -contains 'GLS_Minneapolis_AllUsers') {
#     cscript.exe $CCA
#}

###########################################
########  Create Desktop Shortcuts  #######
###########################################

# Network Dashboard Shortcut
#Create-Shortcut -Name 'Network Dashboard.lnk' -Icon 'c:\windows\system32\shell32.dll,93' -TargetPath "$($currentdir.Replace('\BaseScript',''))\MinneapolisLogonKicker.vbs" -All
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\desktop\Network Dashboard.lnk")
$Shortcut.TargetPath = "$($currentdir.Replace('\BaseScript',''))\MinneapolisLogonKicker.vbs"
$shortcut.IconLocation = "c:\windows\system32\shell32.dll,21"
$Shortcut.Save()

# Tier 0 Shortcut
Create-Shortcut -Name 'AFRC Tier 0.lnk' -Icon "$currentdir\tier0_logo.ico" -TargetPath 'https://afrc.eim.us.af.mil/sites/Tier0/BaseSites/Robins/SitePages/Home.aspx' -All

# WingmanToolkip Shortcut
Create-Shortcut -Name 'Wingman Toolkit.lnk' -Icon "$currentdir\WingmanToolkit.ico" -TargetPath 'http://afrc.wingmantoolkit.org' -All

###########################################
############  Software Audit  #############
###########################################

#$ezstart = '\\QJKL-FS-002\ezaudit$\ezstart.exe'
#$ezstartargs = '-a -o'
#& $ezstart $ezstartargs

###########################################
#########  Run External Scripts  ##########
###########################################

# Powershell Scripts
#. $VPNFix
#. $UpdateSharePaths
. $hp640
.  $MapScanDrive

###########################################
###########  Power Management  ############
###########################################

# These set the workstation to never go to sleep and instead turn off the display
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0

###########################################
#########  Other / Temp Scripts  ##########
###########################################

# TEMPORARY - Disable Adobe Office Addin - TEMPORARY

[int]$LoadBehaviour = 0

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\Excel\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Excel\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\MS Project\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\MS Project\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\OneNote\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\OneNote\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\Outlook\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Outlook\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\PowerPoint\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\PowerPoint\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\Word\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Word\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

<# 


$Source = '\\uhhz-fs-014\AFRC_ALL_ADMINS_SHARED\Functional Areas\Automation\Scripts-Production\Logon Backup\Minneapolis_Logon\BaseScript\basescript.ps1'
$Destination = '\\52UHHZ-HC-003V\March_Logon\BaseScript\BaseScript.ps1',
               '\\52UHHZ-HC-004V\March_Logon\BaseScript\BaseScript.ps1'
$Destination | % { Copy-Item $source $_ -verbose}



#>