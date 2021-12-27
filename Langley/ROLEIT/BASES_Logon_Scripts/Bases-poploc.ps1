<# 
SCRIPT NAME:  popLoc.ps1
DATE CREATED:  20 Nov 09
CREATED BY:  Charlie Bolen, 83 NOS, DSN 575-1353
DESCRIPTION: Prompts user to enter their bldg and room number and populates that in the
    "location" attribute of the computer object. User will not be prompted to enter
    information again until 45 days have passed or if the "location" attribute value is empty.
    Logged on user's "o" attribute value is copied to the logged on computer's "o" attribute.
#>

<# Revision History
 Ver 1.1 - Changed differencing date to > 45 days per discussion with Cliff Goodnight.
 Ver 1.2 - Updated to include logic that takes the logged on user's "o" attribute value, if exists, and copies that value to the logged on computer's "o" attribute.
            Will not perform this action if the user account exist within the Administration OU or if the logged on user's "employeeType" attribute value is G or S. 	
 Ver 1.3 - Updated to include General Shelton and Lt General Basla within script exclusion portion of the script. Per High TT#1609979.
 Ver 1.4 - 15Feb17 - PELINO, FRANK - Corrected line 107 "CN=Administration" to read "OU=Administration" Backup located at \\52VEJX-AS-003\Software1\Documentation\Scripts... "Backup_popLoc.vbs"
 Ver 2.0 - 12Feb21 - Michael Calabrese (1468714589) - Converted to PS, added exclusion for Virtual Computers, removed exclusion for Administration OU because this is linked to 
                BASES OU or logon scripts. Removed General Shelton and Lt General Basla as their EDIs no longer exist but kept exclusions as an option.
 Ver 2.1 - 19Jul21 - Michael Calabrese (1468714589) - Changed to be used for bases if they want to add the popup back. Reduced the timeline so that this runs before the other script.
#>

Function Update-CompO ($NewO) {
    $DirectoryEntry = [adsi]$adobjComp.GetDirectoryEntry()
    $DirectoryEntry.o = $NewO
    $DirectoryEntry.CommitChanges()
}

Function Update-CompLocation ($NewLocation) {
    $DirectoryEntry = [adsi]$adobjComp.GetDirectoryEntry()
    $DirectoryEntry.location = $NewLocation
    $DirectoryEntry.CommitChanges()
}

#Collect info about logged in user
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$userDN= $adobj.Properties.distinguishedname
$UserCN = $adobj.Properties.cn
$UserEmployeeType = $adobj.Properties.employeetype
$userO = $adobj.Properties.o

#Collect info about computer
#================================
$adobjComp = ([adsisearcher]"Samaccountname=$($env:COMPUTERNAME)$").findone()
$CompDN = $adobjComp.Properties.distinguishedname
$CompLocation = $adobjComp.Properties.location
$CompO = $adobjComp.Properties.o
[datetime]$LastModifyDate=$CompLocation.split(' ')[-1]
$Date=Get-Date -Format 'MM/dd/yyyy'

#If virtual computer exit script.
if($CompDN -match 'Virtual Computers'){Exit}

#Exclude user accounts with employeeType value of G or S or on exclusion list
#================================
if( ($UserEmployeeType -eq 'G')  -or ($UserEmployeeType -eq 'S') -or ($env:Username -in $excludedUsers) ) {Exit}

#If o attribute is blank update it to users o
if( ($CompO -eq $null) -or ($CompO -eq '') ) {Update-CompO -NewO $userO}

#If last update is less than 45 days ago exit script.
if($LastModifyDate -gt $((get-date).AddDays(-40))){Exit}

#Routine to prompt users for building and room number information
Add-Type -AssemblyName Microsoft.VisualBasic
do {
    $Building=[Microsoft.VisualBasic.Interaction]::InputBox("Enter your building number. This information is required for system accountability and inventory.", "AFNET Workstation Validation")
    if ($Building -eq "") {
        "You did not enter anything for building."
    } else {
        $BConfirmed=$true
        do {
            $Room=[Microsoft.VisualBasic.Interaction]::InputBox("Enter your room number.  This information is required for system accountability and inventory.","AFNET Workstation Validation")
            if ($Room -eq "") {
                "You did not enter anything for room."
            } else {$RConfirmed=$true}
        } until ($RConfirmed)
    }
} until ($BConfirmed)

Update-CompLocation -NewLocation "BLDG: $Building; RM: $Room; ORGANIZATION: $userO; USER: $UserCN; LAST UPDATE: $Date"
if ($CompO -ne $userO){Update-CompO -NewO $userO}