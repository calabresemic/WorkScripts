#get duplicate records
$allrecords = Get-Content 'C:\Users\1468714589A\OneDrive - United States Air Force\Desktop\dups.csv'
"$allrecords.count Records"

#sort to get unique names
$dups = $allrecords | sort -Unique
"$dups Duplicates"

#get Windows version
$OSversions=@()
foreach($DC in $DCs){$OSversions+=Get-ADComputer -identity $DC.Split(".")[0] -Properties OperatingSystem | select -Property Name,OperatingSystem}

#export csv
$OSversions | Export-Csv -NoTypeInformation 'C:\Users\1468714589A\OneDrive - United States Air Force\Desktop\OSVersions.csv'