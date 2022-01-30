#This script gets the number of users and computers at a selected base
#Created by Michael Calabrese (1468714589)

#Does not require RSAT

function Get-ADSIOrganizationalUnit {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [String]$LDAPFilter,

        [Parameter(Mandatory)]
        [String]$SearchRoot,

        [Parameter(Mandatory)]
        [ValidateSet('OneLevel','Base','Subtree')]
        [String]$SearchScope
        )

    if(!($LDAPFilter -eq '*')){$Filter=$LDAPFilter}

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = "LDAP://$SearchRoot"
    $Searcher.SearchScope = $SearchScope
    $Searcher.PageSize = 10000
    $Searcher.Filter = "(&(objectCategory=organizationalUnit)$Filter)"
    $colresults=$Searcher.FindAll()

    foreach($objresult in $colresults){
        [pscustomobject]@{
            Name=[string]$objresult.Properties['Name']
            distinguishedname=[string]$objresult.Properties['distinguishedname']
            }
        }
    }

function Get-ADSIUser {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [String]$LDAPFilter,

        [Parameter(Mandatory)]
        [String]$SearchRoot
        )

    if(!($LDAPFilter -eq '*')){$Filter=$LDAPFilter}

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = "LDAP://$SearchRoot"
    $Searcher.PageSize = 10000
    $Searcher.Filter = "(&(objectCategory=user)$Filter)"
    $Searcher.FindAll()
    }

function Get-ADSIComputer {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [String]$LDAPFilter,

        [Parameter(Mandatory)]
        [String]$SearchRoot
        )

    if(!($LDAPFilter -eq '*')){$Filter=$LDAPFilter}

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = "LDAP://$SearchRoot"
    $Searcher.PageSize = 10000
    $Searcher.Filter = "(&(objectCategory=computer)$Filter)"
    $Searcher.FindAll()
    }

"Indexing Base Names"
$bases=@()
$bases+=$cent=(Get-ADSIOrganizationalUnit -LDAPFilter * -SearchRoot "OU=AFCONUSCENTRAL,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel).Name
$bases+=$east=(Get-ADSIOrganizationalUnit -LDAPFilter * -SearchRoot "OU=AFCONUSEAST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel).Name
$bases+=$west=(Get-ADSIOrganizationalUnit -LDAPFilter * -SearchRoot "OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel).Name

$i=1;while($i -eq 1){

    #Cleanup for repeats
    Remove-Variable totalusers,totaldevices -ErrorAction SilentlyContinue

    #Logic for selecting bases and counting
    $Selection=$bases | Sort-Object | Out-GridView -PassThru -Title 'Select A Base or Multiple Bases(CTRL+Click)'
    "Gathering Base Stats for $($Selection -join ',') (this may take a while)`n"
    $Selection.ForEach{
        $servers=@()
        if($_ -in $cent){$OU="AFCONUSCENTRAL"}
        elseif($_ -in $east){$OU="AFCONUSEAST"}
        elseif($_ -in $west){$OU="AFCONUSWEST"}
        else{exit}
    
        $Users=Get-ADSIUser -LDAPFilter * -SearchRoot "OU=$_ Users,OU=$_,OU=$OU,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
            "`n$_ $($Users.count) Users"
        $Workstations=Get-ADSIComputer -LDAPFilter * -SearchRoot "OU=$_,OU=$OU,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
        $ServerOUs=(Get-ADSIOrganizationalUnit -LDAPFilter "(Name=$_)" -SearchRoot "OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope Subtree).DistinguishedName
        foreach($ServerOU in $ServerOUs){$servers+=Get-ADSIComputer -LDAPFilter * -SearchRoot $ServerOU}
            $total=$Workstations.Count + $Servers.Count;"$_ $total WS and Servers"

        #If multiple bases selected this will total the users and computers
        if($Selection.count -gt 1){$totalusers+=$($Users.count);$totaldevices+=$total}
        }

    #Display the total of all bases selected
    if($Selection.count -gt 1){"$totalusers Total Users";"$totaldevices Total Devices"}

    #Ask to repeat
    $i=Read-Host "`nEnter 1 to try another base or enter to exit"
}