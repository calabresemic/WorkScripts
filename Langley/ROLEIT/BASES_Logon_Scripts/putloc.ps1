<# 
SCRIPT NAME:  popLoc.ps1
DATE CREATED:  20 Nov 09
CREATED BY:  Charlie Bolen, 83 NOS, DSN 575-1353
DESCRIPTION: Populates user info and update time in the "location" attribute of the computer object every 45 days or if the "location" attribute value is empty.
    Logged on user's "o" attribute value is copied to the logged on computer's "o" attribute.
#>

<# Revision History
 Ver 1.1 - Changed differencing date to > 45 days per discussion with Cliff Goodnight.
 Ver 1.2 - Updated to include logic that takes the logged on user's "o" attribute value, if exists, and copies that value to the logged on computer's "o" attribute.
            Will not perform this action if the user account exist within the Administration OU or if the logged on user's "employeeType" attribute value is G or S. 	
 Ver 1.3 - Updated to include General Shelton and Lt General Basla within script exclusion portion of the script. Per High TT#1609979.
 Ver 1.4 - 15Feb17 - PELINO, FRANK - Corrected line 107 "CN=Administration" to read "OU=Administration" Backup located at \\52VEJX-AS-003\Software1\Documentation\Scripts... "Backup_popLoc.vbs"
 Ver 2.0 - 12Feb21 - Michael Calabrese (1468714589) - Converted to PS, added exclusion for Virtual Computers, removed exclusion for Administration OU because this is linked to 
                BASES OU or logon scripts. Removed General Shelton and Lt General Basla as their EDIs no longer exist but kept exclusinos as an option.
 Ver 3.0 - 24Jun21 - Michael Calabrese (1468714589) - No longer doing the popin because enterprise auditing office requires the o attribute. Will only populate o and location now.
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
$CompLocation = $adobjComp.Properties.location
$CompO = $adobjComp.Properties.o
[datetime]$LastModifyDate=$CompLocation.split(' ')[-1]
$Date=Get-Date -Format 'MM/dd/yyyy'

#Exclude user accounts with employeeType value of G or S
#================================
if( ($UserEmployeeType -eq 'G')  -or ($UserEmployeeType -eq 'S') ) {Exit}

#If o attribute is blank update it to users o
if( ($CompO -eq $null) -or ($CompO -eq '') ) {Update-CompO -NewO $userO}

#If last update is less than 45 days ago exit script.
if($LastModifyDate -gt $((get-date).AddDays(-45))){Exit}

Update-CompLocation -NewLocation "ORGANIZATION: $userO; USER: $UserCN; LAST UPDATE: $Date"
if ($CompO -ne $userO){Update-CompO -NewO $userO}