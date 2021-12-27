###########################################
########  Functions / DO NOT EDIT  ########
###########################################

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

function Get-Location
{
    Param ( [string]$object )
	
    $name = $($($object.Split(','))[0]).Replace('CN=','')
	
    $strFilter = "(&(objectCategory=Group)(samAccountName=$name))"

    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.Filter = $strFilter

    $objPath = $objSearcher.FindOne()
    $objGroup = If ($objPath -ne $null) {$objPath.GetDirectoryEntry()} Else {$null}
	
    $location = ($objUser.distinguishedName -split ',')[2].Replace('OU=','')

    Return $location
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

# Getting the current user
$currentUser           = $env:USERNAME

# Enumerating nested groups of current user
$GroupMembership       = Get-UserGroups $currentUser

# External Scripts
$Form4394              = $currentdir + '\FORM4394\AFRC_Form4394_Logon_v1.0.vbs'
$VPNFix                = $currentdir + '\VPNFIX\VPNFIX.ps1'
$UpdateSharePaths      = $currentdir + '\Update-SharePaths\Update-SharePaths.ps1'
$hp640		       = $currentdir + '\Custom\hp640.ps1'

###########################################
########  Setting Drive Mappings  #########
###########################################

NET USE X: /D
NET USE X: \\RIVFS21.AREA52.AFNOAPPS.USAF.MIL\INFO

If ($GroupMembership -contains 'RIV COMMSQ') {
    NET USE V: /D
    NET USE Z: /D
    NET USE V: \\RIVFS21.AREA52.AFNOAPPS.USAF.MIL\CS
    NET USE Z: \\RIVFS21.AREA52.AFNOAPPS.USAF.MIL\APPS
}

# MAp V drive for admin IDs
If ($GroupMembership -contains 'RIV NCC Admins') {
    NET USE V: /D
    USE Z: /D
    NET USE V: \\RIVFS21.AREA52.AFNOAPPS.USAF.MIL\CS
    NET USE Z: \\RIVFS21.AREA52.AFNOAPPS.USAF.MIL\APPS
}

If ($GroupMembership -contains 'RIV MPF') {
    NET USE M: /D
    NET USE M: \\RIVFS01.AREA52.AFNOAPPS.USAF.MIL\MPF
}

If ($GroupMembership -contains 'RIV 4AF') {
    NET USE N: /D
    NET USE R: /D
    NET USE S: /D
    NET USE N: \\RIVFS06.AREA52.AFNOAPPS.USAF.MIL\PUBLIC
    NET USE R: '\\RIVFS06.AREA52.AFNOAPPS.USAF.MIL\PUBLIC\UTA INFO'
    NET USE S: \\RIVFS06.AREA52.AFNOAPPS.USAF.MIL\STAFFMGT
}

If ($GroupMembership -contains 'RIV MILITARY PAY') {
    NET USE P: /D
    NET USE P: '\\RIVFS03.AREA52.AFNOAPPS.USAF.MIL\452 FMFP'
}

If ($GroupMembership -contains 'RIV MICROBAS ADMINISTRATORS') {
    NET USE L: /D
    NET USE L: \\RIVFS03.AREA52.AFNOAPPS.USAF.MIL\MICROBAS
}

If ($GroupMembership -contains 'RIV FM') {
    NET USE Q: /D
    NET USE Q: '\\RIVFS03.AREA52.AFNOAPPS.USAF.MIL\452 FM'
}

#If ($GroupMembership -contains 'RIV FM MANAGERS') {
#	NET USE W: /D
#	NET USE W: "\\RIVFS03.AREA52.AFNOAPPS.USAF.MIL\452 WING SHARE" Share doesn't exit anymore
#}

If (($GroupMembership -contains 'RIV 701 ALL') -or ($GroupMembership -contains 'RIV 701 ALL USERS')) {
    NET USE Y: /D
    NET USE Y: '\\RIVFS03.AREA52.AFNOAPPS.USAF.MIL\701 COS'
}

If ($GroupMembership -contains 'RIV COVERTRAIN USERS') {
    NET USE T: /D
    NET USE T: '\\RIVFS07.AREA52.AFNOAPPS.USAF.MIL\CLIENT INSTALL'
}

If ($GroupMembership -contains 'RIV 452 MXG ALL USERS') {
    NET USE M: /D
    NET USE M: '\\RIVFS03.AREA52.AFNOAPPS.USAF.MIL\452 MAINTENANCE GP'
}

If ($GroupMembership -contains 'RIV MG AFCITA') {
    NET USE M: /D
    NET USE M: \\RIVMS07.AREA52.AFNOAPPS.USAF.MIL\ASIMS_SHARED
}

# Per Change Request Dated 20110711 from Daniel Melendrez

If ($GroupMembership -contains 'GLS_452 AMW_362RCSUSERS') {
    NET USE G: /D
    NET USE G: '\\RIVFS01.AREA52.AFNOAPPS.USAF.MIL\362RCS'
}


###########################################
########  Create Desktop Shortcuts  #######
###########################################


# Tier 0 Shortcut
Create-Shortcut -Name 'AFRC Tier 0.lnk' -Icon "$currentdir\tier0_logo.ico" -TargetPath 'https://afrc.eim.us.af.mil/sites/Tier0/BaseSites/Robins/SitePages/Home.aspx' -All

# WingmanToolkip Shortcut
Create-Shortcut -Name 'Wingman Toolkit.lnk' -Icon "$currentdir\WingmanToolkit.ico" -TargetPath 'http://afrc.wingmantoolkit.org' -All

# My IMR Shortcut
$lnkFile = 'My IMR.lnk'
Del "$Home\desktop\$lnkFile"
Copy-Item -Path "$currentdir\Custom\$lnkFile" -Destination "$Home\Desktop\$lnkFile" -Force

# ATAAPS Shortcut
$lnkFile = 'ATAAPS.lnk'
Del "$Home\desktop\$lnkFile"
Copy-Item -Path "$currentdir\Custom\$lnkFile" -Destination "$Home\Desktop\$lnkFile" -Force

# MICT Shortcut
$lnkFile = 'MICT.lnk'
Del "$Home\desktop\$lnkFile"
Copy-Item -Path "$currentdir\Custom\$lnkFile" -Destination "$Home\Desktop\$lnkFile" -Force


#Cyber StatusBoard Display
If ($GroupMemberShip -contains 'DLS_CYBER dashboard') { $lnkFile = 'Cyber Readiness StatusBoard.lnk'
Del "c:\users\$currentuser\desktop\$lnkfile"
Copy-Item -Path '\\rivfs21\cfp\dashboard\Cyber Readiness StatusBoard.lnk' -Destination "c:\users\$currentuser\desktop" -Force }

# Cyber StatusBoard Managment Console
If ($GroupMemberShip -contains 'DLS_cyber dashboard managers') { $lnkFile = 'Cyber Statusboard Management.lnk'
Del "c:\users\$currentuser\desktop\$lnkfile"
Copy-Item -Path '\\rivfs21\cfp\dashboard\Management\Cyber Statusboard Management.lnk' -Destination "c:\users\$currentuser\desktop" -Force }






###########################################
############  Software Audit  #############
###########################################

$ezstart = '\\rivfs21\ezaudit$\ezstart.exe'
$ezstartargs = '-a -o'
& $ezstart $ezstartargs

###########################################
#########  Run External Scripts  ##########
###########################################

# Powershell Scripts
#. $VPNFix
. $UpdateSharePaths
. $hp640

# VBS Scripts
If (-not($GroupMembership -contains 'GLS_4394_bypass')) { cscript.exe $Form4394 }

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