#Requires -Version 5.0
<#
Title           :Extract Scan Results
Description     :This script will take a zip file with ACAS results and create a spreadsheet with compare table, missing assets and bad access.
Author		    :Michael Calabrese (1468714589)
Date            :6/21/2021
Version         :2.5

Change Log:
Added service account info to missing/bad access report
added ipv4 address for missing/bad access

==============================================================================#>

#Script Setup
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.Office.Interop.Excel

Function ConvertTo-CSV ($ExcelFile) {
    $Excel = New-Object -ComObject Excel.Application
    $Excel.Visible = $false
    $excel.DisplayAlerts = $false
    $WB = $Excel.Workbooks.Open($ExcelFile)
    $WS = $WB.Worksheets | where {$_.name -ne "Compare"}
    if ($WS){$WS.SaveAs("$workingDir\Unzip\$($WS.Name).csv",6)}
    $WB.close($false)
    $Excel.Quit()
    Stop-Process -ProcessName EXCEL
}

Function Calculate-CCRIScore ($NetBiosName) {

    $Name=$NetBiosName.Split("\")[1]

    $presort=$csv | Where-Object {$_."Netbios Name" -like "$NetBiosName"} #Only grab one name at a time

    #Count each category of vuln
    $CAT1=($presort.severity | Where-Object {$_ -match 'Critical' -or $_ -match 'High'}).count
    $CAT2=($presort.severity | Where-Object {$_ -match 'Medium'}).count
    $CAT3=($presort.severity | Where-Object {$_ -match 'Low'}).count

    $Score = [math]::round((($CAT1 * 10) + ($CAT2 * 4) + $CAT3) / 15,2) #These are the scores that DISA uses

    return [pscustomobject]@{"DNS Name"=$Name;"CCRI Score"=$Score;Updated="";Assigned="";Notes="";"Last Updated"=$date} #Export to results array
}

#Variables

$csv=@()     #This array is used to collect all rows that we want to keep
$results=@() #This array is used to calculate CCRI score
$missing=@() #This array is used to gather missing and bad access results
$date=Get-Date -Format "MM/dd/yyyy"
$ignoredate=(Get-Date).AddDays(-30)
$workingDir = $PSScriptRoot
#$workingDir = "$([Environment]::GetFolderPath("Desktop"))\ACAS" #Uncomment this line to use in ISE
$requiredcolumns=@('Plugin','Plugin Name','Severity','NetBIOS Name','Plugin Text','Plugin Publication Date') #These are colums we need at a minimum to be able to use the scans

#Location of NIPR/SIPR Asset Lists

$localassets=@('MUHJ-DC-005P','MUHJ-DC-006P','MUHJ-HC-003P','MUHJ-HC-004P') #83d NOS Local Assets
$assets= Import-Csv '\\zhtx-bs-013v\cyod\07--Cyber 365\07--83NOS Assets List\LATEST Official Asset list.csv' | where {$_.Name -notin $localassets} #83d NOS Enterprise Assets
$MAJCOMReference = Import-Csv "\\zhtx-bs-013v\CYOD\07--Cyber 365\07--83NOS Assets List\MAJCOM-Bases.csv"

#==============================================================================
#Import information

#Open File Dialog for selecting scan results
do{
    $resultselector = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = $workingDir
        Filter = 'SCANZ|*.zip'
        Title = "Select Scan Results file to import"
    }
    
    $resultselector.ShowDialog() | Out-Null

} until ( ($resultselector.FileName -match 'Enterprise') -or ($resultselector.FileName -match 'NOS') )

#Extract Results

Expand-Archive $resultselector.FileName -DestinationPath "$workingDir\Unzip"

"Organizing Data"

Get-ChildItem "$workingDir\Unzip\*" -Include *.pdf,*BITI*,*ACAS*,*EITSM*,*Forescout*,*HBSS*,*SAMP*,*SCE*,*VPS*,*Workstations*,*Failed*,*19506*,*Compliance*,*'S&V'* -Recurse | Remove-Item #Remove clutter from results

if($xlsx=Get-ChildItem "$workingDir\Unzip" -Recurse -Include *.xlsx){$xlsx.FullName.foreach{ConvertTo-Csv $_}} #If results are xlsx format, convert to csv for easy import

$Import = (Get-ChildItem "$workingDir\Unzip" -Recurse -Include *.csv).FullName | Import-Csv #Import all csv files

#==============================================================================
#This is where all the filtering happens

#Abort script if the results don't contain the required columns

if($requiredcolumns.ForEach{($Import | Get-Member -MemberType NoteProperty).Name -contains $_} -contains $false) {

    "The results are missing some/all of the required columns($($requiredcolumns -join ',')). Aborting.";pause #Jumps to cleanup section

} else {
    
    $DSResults = $Import | Where-Object { ($assets.name -contains $_."NetBIOS Name".split("\")[1]) -or ($localassets -contains $_."NetBIOS Name".split("\")[1])} #Take only our assets from the original import

    if($DSResults) { 
        #If our assets are in the results
        $GoodAccess=($DSResults | Where-Object {$_.port -eq '445'}).'NetBios Name' | Select-Object -Unique   #This is a guess at what good access should look like based on the results
        $BadAccess=$DSResults.'NetBios Name' | Where-Object {$_ -notin $GoodAccess} | Select-Object -Unique | %{$_.split("\")[1]}    #If access is not good it must be bad?
        $scannedAssets=$DSResults."NetBIOS Name" | Select-Object -Unique | %{$_.split("\")[1]}    #This is for calculating the missing assets

        "Sorting the results`n"

        foreach($row in $DSResults){

            if($row.'NetBios Name' -in $GoodAccess) { 
                #We only want the data from good access

                if($row.'Plugin Publication Date' -eq $null){
                    
                    $csv+=$row #If Publication Date is blank, move it over by default. It's probably just SSL

                } else {

                    #This section removes the results that are within 30 days. They don't count and SCCM should deal with them.

                    $row.'Plugin Publication Date'=$row.'Plugin Publication Date'.TrimEnd(' EST').TrimEnd(' EDT').TrimEnd(' UTC') #Trim EST, EDT, UTC notation from end of date

                    if([datetime]$row.'Plugin Publication Date' -lt $ignoredate){

                        $csv+=$row #The Plugin Publication Date is older than 30 days we want this
                    }
                }
            }
        }

        #Calculate CCRI Score based on severity of plugins

        $GoodAccess | % {"Calculating CCRI score for $($_.Split("\")[1])";$results+=Calculate-CCRIScore $_ }

        "`nDone";"`nExporting"

        #Exports the temp CSVs
        $csv | Export-Csv "$workingDir\$($date.replace('/','')) EnterpriseAssets.csv" -NoTypeInformation               #This array is used to collect all rows that we want to keep
        $results | Sort-Object "CCRI Score" -Descending | Export-Csv "$workingDir\CCRI SCORES.csv" -NoTypeInformation  #This array is used to calculate CCRI score

        if($resultselector.FileName -match 'Enterprise'){ $missingAssets=$assets.Name | Where-Object {$scannedAssets -notcontains $_} | Sort-Object #Calculate based on enterprise asset list

        } else { $missingAssets=$localassets | Where-Object {$scannedAssets -notcontains $_} | Sort-Object } #Calculate based on the local asset list

        foreach ($comp in $missingAssets) {
            $sitecode=$comp.replace('52','').split('-')[0]
            $assettype=$comp.split('-')[1]
            $MAJCOM=($MAJCOMReference | where geocode -eq $sitecode).MAJCOM
            $IPv4Addr=($assets | Where-Object {$_.Name -eq $comp}).IPv4Address

            if($sitecode.Length -eq 5) {

                $name='$svc.afnoapps.va'
                Try{
                    $svcacct=Get-ADUser $name -Properties Enabled,LockedOut,PasswordLastSet -Server afnoapps.usaf.mil -ErrorAction Stop
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Missing";'Service Account'=$svcacct.Name;'Lockout Status'=$svcacct.LockedOut;Enabled=$svcacct.Enabled;'Password Last Set'=$svcacct.PasswordLastSet}
                }
                Catch{
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Missing";'Service Account'=$_;'Lockout Status'='N/A';Enabled='N/A';'Password Last Set'='N/A'}
                }

            } else {

                Switch ($assettype) {
                    DC      {$name='$svc.'+$MAJCOM+'.ACAS-T0'}
                    Default {$name='$svc.area52.'+$sitecode+'83va'}
                }

                Try{
                    $svcacct=Get-ADUser $name -Properties Enabled,LockedOut,PasswordLastSet -ErrorAction Stop
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Missing";'Service Account'=$svcacct.Name;'Lockout Status'=$svcacct.LockedOut;Enabled=$svcacct.Enabled;'Password Last Set'=$svcacct.PasswordLastSet}
                }
                Catch{
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Missing";'Service Account'=$_;'Lockout Status'='N/A';Enabled='N/A';'Password Last Set'='N/A'}
                }
            }

        }

        foreach ($comp in $BadAccess) {
            $sitecode=$comp.replace('52','').split('-')[0]
            $assettype=$comp.split('-')[1]
            $MAJCOM=($MAJCOMReference | where geocode -eq $sitecode).MAJCOM
            $IPv4Addr=($assets | Where-Object {$_.Name -eq $comp}).IPv4Address

            if($sitecode.Length -eq 5) {

                $name='$svc.afnoapps.va'
                Try{
                    $svcacct=Get-ADUser $name -Properties Enabled,LockedOut,PasswordLastSet -Server afnoapps.usaf.mil -ErrorAction Stop
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Bad Access";'Service Account'=$svcacct.Name;'Lockout Status'=$svcacct.LockedOut;Enabled=$svcacct.Enabled;'Password Last Set'=$svcacct.PasswordLastSet}
                }
                Catch{
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Bad Access";'Service Account'=$_;'Lockout Status'='N/A';Enabled='N/A';'Password Last Set'='N/A'}
                }

            } else {

                Switch ($assettype) {
                    DC      {$name='$svc.'+$MAJCOM+'.ACAS-T0'}
                    Default {$name='$svc.area52.'+$sitecode+'83va'}
                }

                Try{
                    $svcacct=Get-ADUser $name -Properties Enabled,LockedOut,PasswordLastSet -ErrorAction Stop
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Bad Access";'Service Account'=$svcacct.Name;'Lockout Status'=$svcacct.LockedOut;Enabled=$svcacct.Enabled;'Password Last Set'=$svcacct.PasswordLastSet}
                }
                Catch{
                    $missing+=[pscustomobject]@{'Asset Name'=$comp;'Asset IP'=$IPv4Addr;'Asset Status'="Bad Access";'Service Account'=$_;'Lockout Status'='N/A';Enabled='N/A';'Password Last Set'='N/A'}
                }
            }

        }

        $missing | Export-Csv "$workingDir\missing.csv" -NoTypeInformation  #This array is used to gather missing and bad access results

    } else {

        #There were no DS Assets in the import

        "The results are missing all of our assets. Aborting.";pause

        if($resultselector.FileName -match 'Enterprise'){$assets.Name | Where-Object {$scannedAssets -notcontains $_} | Sort-Object | Out-File "$workingDir\MissingEnterpriseAssets.txt"} #Calculate based on enterprise asset list

        else{$localassets | Where-Object {$scannedAssets -notcontains $_} | Sort-Object | Out-File "$workingDir\MissingLocalAssets.txt"} #Calculate based on the local asset list

    }

#Use the CSVs to create the XLSX report

# Create Excel COM Object

$xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlWorkbookDefault
$excel = New-Object -ComObject excel.application
$excel.EnableEvents = $false #This prevents the addins on SIPR from breaking the process
$excel.visible=$true         #This allows the user to see the process

# Create a blank workbook

$reportOut = $excel.Workbooks.Add()

# Open missing.csv and copy into $reportOut

$wb = $excel.WorkBooks.Open("$workingDir\missing.csv")
$wb.Worksheets.Item(1).Name = "Missing-Bad Access"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:F").EntireColumn.AutoFit() | Out-Null
$wb.Close(0)

# Open CCRI SCORES.csv and copy into $reportOut

$wb = $excel.WorkBooks.Open("$workingDir\CCRI SCORES.csv")
$wb.Worksheets.Item(1).Name = "CCRI SCORES"
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.columns.item("A:F").EntireColumn.AutoFit() | Out-Null
$wb.Close(0)

# Open EnterpriseAssets.csv and copy into $reportOut

$wb = $excel.WorkBooks.Open("$workingDir\$($date.replace('/','')) EnterpriseAssets.csv")
if($resultselector.FileName -match 'Enterprise') { $wb.Worksheets.Item(1).Name = "$($date.replace('/','')) EnterpriseAssets" }
else { $wb.Worksheets.Item(1).Name = "$($date.replace('/','')) LocalAssets" }
$wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
$excel.Rows.RowHeight = 15
$wb.Close(0)

# Delete "Sheet1"

$reportOut.WorkSheets.Item(4).Delete() 

# Saves Excel

if($resultselector.FileName -match 'Enterprise') { $reportOut.SaveAs("$workingDir\$($date.replace('/','')) EnterpriseAssets.xlsx",$xlFixedFormat) } #Save XLSX as Enterprise 

else { $reportOut.SaveAs("$workingDir\$($date.replace('/','')) LocalAssets.xlsx",$xlFixedFormat) } #Save XLSX as Local

[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null #Close Excel background process

}

#==============================================================================
#Cleans up regardless of what script does

Remove-Item "$workingDir\Unzip" -Force -Recurse #Removes the unzip folder

Get-ChildItem $workingDir -Filter *.csv | Remove-Item #Removes any leftover CSV files