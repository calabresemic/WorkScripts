#Created by SrA Calabrese, Michael

# Imports information from CSV
$csv = Import-Csv '\\zhtx-bs-013v\CYOD\08--Personal Storage\Calabrese\DS_Scripts\Servers.csv'

ForEach($server in $csv)

    {

    # Creates Computer Object
    New-ADComputer -Name $server.Name -Path $server.OU -Enabled $true -Verbose

    # Adds join rights to the object
    & "\\zhtx-bs-013v\CYOD\08--Personal Storage\Calabrese\DS_Scripts\JoinRights.ps1" -Identity $server.JoinRights -Name $server.Name 
    
    # Creates a variable for the distinguished name of the server
    $DN="CN="+$server.Name+","+$server.OU

    # Checks for and adds security group to the object
    if(![string]::IsNullOrEmpty($server.SecurityGroups))
        {
        ForEach($group in $server.SecurityGroups)

            {
                Add-ADGroupMember -Identity $group -Members $DN
            }
        }
    }