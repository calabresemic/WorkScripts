#This script gets the number of users and computers at a selected base
#Created by Michael Calabrese (1468714589)

#Requires -Modules ActiveDirectory

"Indexing Base Names"
$bases=@()
$bases+=$cent=(Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AFCONUSCENTRAL,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel).Name
$bases+=$east=(Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AFCONUSEAST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel).Name
$bases+=$west=(Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -SearchScope OneLevel).Name

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
    
        $Users=get-aduser -filter * -SearchBase "OU=$_ Users,OU=$_,OU=$OU,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
            "`n$_ $($Users.count) Users"
        $Workstations=get-adcomputer -filter * -SearchBase "OU=$_,OU=$OU,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
        $ServerOUs=(Get-ADOrganizationalUnit -Filter {Name -eq $_} -SearchBase "OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL").DistinguishedName
        foreach($ServerOU in $ServerOUs){$servers+=Get-ADComputer -Filter * -SearchBase $ServerOU}
            $total=$Workstations.Count + $Servers.Count;"$_ $total WS and Servers"

        #If multiple bases selected this will total the users and computers
        if($Selection.count -gt 1){$totalusers+=$($Users.count);$totaldevices+=$total}
        }

    #Display the total of all bases selected
    if($Selection.count -gt 1){"$totalusers Total Users";"$totaldevices Total Devices"}

    #Ask to repeat
    $i=Read-Host "`nEnter 1 to try another base or enter to exit"
}