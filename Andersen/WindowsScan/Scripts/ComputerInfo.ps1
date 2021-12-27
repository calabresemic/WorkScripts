$ErrorActionPreference="silentlycontinue"
# removes the old files
Remove-Item C:\WindowsScan\temp\ComputerInformation.csv -Force
Remove-Item C:\WindowsScan\temp\notupgradable.csv -Force
Remove-Item C:\WindowsScan\temp\needtoupgrade.csv -Force
Remove-Item C:\WindowsScan\temp\offline.csv -Force
Remove-Item C:\WindowsScan\temp\unknown.csv -Force
Remove-Item C:\WindowsScan\temp\win10.csv -Force

Write-Host "Getting computer list from Active Directory."

# Sources the computer list from AD
$time = (Get-Date).Adddays(-("60"))
$ou = "OU=Andersen AFB Computers,OU=Andersen AFB,OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
$computerlist=(Get-ADComputer -filter {LastLogonTimeStamp -gt $time} -Properties * -SearchBase $ou).name
Write-Host $computerlist.Count "Machines Found"
# Example of how to sort by a specific unit
# $computerlist=(Get-ADComputer -filter {o -eq "36 CS"} -Properties * -SearchBase $ou).name

Write-Host "Starting scans."

# function allows the script to be split up and run in multiple jobs
# modified from a script from Yokota
    Function RUN ($script, $int)
{
    $computers = $compute = @()
    $computers = $Computerlist
    $compute = $computers
    
    $count = $compute.count
    [int]$totalscriptcount = $int
    [int]$compeach = [math]::truncate($count/$totalscriptcount)
    $array = @()

    $array = 1..$totalscriptcount
    $currentscriptcount = 1
    $i = 1

    Foreach($entry in $array)
        {
        [int]$beginarray = $($compeach*($currentscriptcount-1))
        [int]$endarray = $($compeach*$currentscriptcount)
        If($currentscriptcount -eq 1){$compute = @($computers[$beginarray..$endarray])}
        Else{$compute = @($computers[($beginarray+1)..$endarray])}
        # script to be ran
        Start-Job $script -ArgumentList $compute
        $i++
        $currentscriptcount++
        }
        
} 

RUN C:\WindowsScan\Scripts\InfoScan.ps1 8

# information needed to calculate progress
$starttime = Get-Date
$runningjobs = (Get-Job -State Running).count
$total = $runningjobs

# tracks the progress and will stop the script after 3 hours
# allows enough time for all machines to complete but will end it if there are any hangs
while(($runningjobs -gt 0) -and ($elapsedTime.hours -lt 2)){
$elapsedTime = New-TimeSpan -Start $starttime -End (get-date)
$percent=[math]::Round((($total-$runningjobs)/$total * 100),2)
Write-Progress -Activity "Gathering Computer Information ---elapsed time $elapsedtime" -Status "Progress: $percent%" -PercentComplete (($total-$runningjobs)/$total*100)
$runningjobs = (Get-Job -State Running).Count
}

Get-Job | Stop-Job

Write-Host "Scan complete. Sorting the data."

# This section will sort and output all of the data collected from the scan

# sorts between windows 10 and windows 7 systems
$all=Import-Csv 'C:\WindowsScan\temp\ComputerInformation.csv'
$win10=Import-Csv 'C:\WindowsScan\temp\ComputerInformation.csv' | Where-Object {($_."OS Version" -eq "5.3.x") -and ($_."Clone" -ne "$true")}
$win10 | Export-Csv -NoTypeInformation -Force C:\WindowsScan\temp\win10.csv
$win7=Import-Csv 'C:\WindowsScan\temp\ComputerInformation.csv' | Where-Object "Operating System" -NotLike "Windows 10 Enterprise*"

# List of machines that are upgradable... Based on QEB approved machines
$valuestolookfor=@(
    'HP EliteBook 840 G1',
    'HP EliteBook 840 G2',
    'HP EliteBook 840 G3',
    'HP ProBook 640 G1',
    'HP ProBook 640 G2',
    'HP ZBook 15',
    'HP ZBook 15 G2',
    'HP ZBook 15 G3',
    'HP ZBook 14',
    'HP ZBook 17',
    'HP Z230 Tower Workstation',
    'HP Z240 Tower Workstation',
    'HP Z420 Workstation',
    'HP Z820 Workstation',
    'HP Z840 Workstation',
    'HP EliteDesk 705 G1 SFF',
    'HP EliteDesk 705 G1 MT',
    'HP EliteDesk 705 G1 MINI',
    'HP EliteDesk 705 G2 SFF',
    'HP EliteDesk 705 G2 MT',
    'HP EliteDesk 705 G2 MINI',
    'HP EliteDesk 705 G3 SFF',
    'HP EliteDesk 705 G3 MT',
    'HP EliteDesk 705 G3 DESKTOP MINI',
    'HP EliteOne 800 G2 23-in Non-Touch AiO',
    'HP EliteDesk 800 G2 SFF',
    'HP EliteDesk 800 G2 TWR',
    'HP EliteBook 2570p',
    'HP Pro x2 612 G1',
    'Precision 7710'
    )

# Finishes sorting the upgradable and non-upgradable machines
$upgradable=$all | Where-Object {($valuestolookfor -contains $_.Model) -or ($_.Model -like "B300*" -and "*V110G2*")}
$needtoupgrade=$upgradable | Where-Object {($_."OS Architecture" -eq "32-bit") -or ($_."OS Version" -ne "5.3.x") -or ($_.Clone -eq $true)}
$needtoupgrade | Export-Csv -NoTypeInformation -Force C:\WindowsScan\temp\needtoupgrade.csv
$notupgradable=$win7 | Where-Object {($valuestolookfor -notcontains $_.Model) -and ($_.Model -notlike "B300*" -and "*V110G2*") -and ($_.IP -ne "Offline") -and ($_.IP -ne "Unknown") -and ($_."OS Version" -ne "5.3.x")}
$notupgradable | Export-Csv -NoTypeInformation -Force C:\WindowsScan\temp\notupgradable.csv
$offline=$all | Where-Object "IP" -EQ "Offline"
$offline | Export-Csv -NoTypeInformation -Force C:\WindowsScan\temp\offline.csv
$unknown=$win7 | Where-Object "IP" -EQ "Unknown"
$unknown | Export-Csv -NoTypeInformation -Force C:\WindowsScan\temp\unknown.csv

# This section creates an .XLS sheet that combines all the results into one workbook with multiple worksheets
$date=Get-Date -f MM_dd_yyyy
Remove-Item "C:\WindowsScan\Computerinfo_$date.xls"

# Create Excel COM Object
$excel = New-Object -ComObject excel.application
$excel.visible=$true
# Pause while Excel opens
Start-Sleep -Seconds 2

# Create a "blank" workbook
$reportOut = $excel.Workbooks.Add()

# Open workbook and copy into $reportOut
$wb = $excel.WorkBooks.Open("C:\WindowsScan\temp\offline.csv")
$wb.Worksheets.Item(1).Name = "Offline"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:N").EntireColumn.AutoFit() | out-null
$wb.Close(0)

# Open workbook and copy into $reportOut
$wb = $excel.WorkBooks.Open("C:\WindowsScan\temp\unknown.csv")
$wb.Worksheets.Item(1).Name = "Unknown"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:N").EntireColumn.AutoFit() | out-null
$wb.Close(0)

# Open workbook and copy into $reportOut
$wb = $excel.WorkBooks.Open("C:\WindowsScan\temp\win10.csv")
$wb.Worksheets.Item(1).Name = "Current Version"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:N").EntireColumn.AutoFit() | out-null
$wb.Close(0)

# Open workbook and copy into $reportOut
$wb = $excel.WorkBooks.Open("C:\WindowsScan\temp\notupgradable.csv")
$wb.Worksheets.Item(1).Name = "Not Upgradable"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:N").EntireColumn.AutoFit() | out-null
$wb.Close(0)

# Open workbook and copy into $reportOut
$wb = $excel.WorkBooks.Open("C:\WindowsScan\temp\needtoupgrade.csv")
$wb.Worksheets.Item(1).Name = "Need to Upgrade"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:N").EntireColumn.AutoFit() | out-null
$wb.Close(0)

# Open workbook and copy into $reportOut
$wb = $excel.WorkBooks.Open("C:\WindowsScan\temp\ComputerInformation.csv")
$wb.Worksheets.Item(1).Name = "All Computers"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:N").EntireColumn.AutoFit() | out-null
$wb.Close(0)

# Delete "Sheet1"
$reportOut.WorkSheets.Item(7).Delete() 

# Saves and quits Excel
$reportOut.SaveAs("C:\WindowsScan\Computerinfo_$date.xls",1)
$excel.Quit()  

# Places a copy in the Windows 10 directory on the share drive
xcopy /y /e /i "C:\WindowsScan\Computerinfo_$date.xls" "\\ajjy-fs-022v\36 MSG\36 CS\SCOO\Windows 10\"

# Prevents excel from staying running in the background
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel)

# Exports a quick count of numbers
$allcount=$all.Count
$win10count=$win10.count
$needtoupgradecount=$needtoupgrade.count
$notupgradablecount=$notupgradable.count
$offlinecount=$offline.count
$unknowncount=$unknown.count
Write-Output "$allcount - All Machines","$win10count - Windows 10", "$needtoupgradecount - Need to Upgrade", "$notupgradablecount - Not Upgradable", "$offlinecount - Offline", "$unknowncount - Unknown" | Out-File -Force C:\WindowsScan\"Quick Numbers".txt
