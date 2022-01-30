#Requires -Version 5.0
#Author: Michael Calabrese (1468714589)
#This script will import the results of the ACAS SCAP scans and save a new checklist in the same directory

Add-Type -AssemblyName System.Windows.Forms

#This is the location of the checklist
$checklistold = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
    Filter = 'Checklists (*.ckl)|*.ckl'
    Title = "Select checklist file to import"
}
$null = $checklistold.ShowDialog()

#This is the location of the ACAS SCAP results
$Results = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
    Filter = 'Scan Results (*.csv)|*.csv'
    Title = "Select scan results file to import"
}
$null = $Results.ShowDialog()

#Open the checklist file
[xml]$checklist = Get-Content $checklistold.FileName

#Import the ACAS resuls to variable
$ACAS = Import-Csv $Results.FileName
                        
#Creates variables to parse the XML file (thanks Chris)
$STIGS = $checklist.CHECKLIST.stigs.iSTIG.vuln

@"
Vuln_Num
Group_Title
Rule_ID
Rule_Title
Rule_Ver
Weight
Fix_Text
STIGRef
"@.split("`n") | foreach {
    New-Variable -Name ($_.trim() + "_index") -Value $STIGs[0].STIG_DATA.VULN_ATTRIBUTE.IndexOf($_.trim()) -Force
    }

#This part gets the acas results and puts them in the checklist
for ($STIG_index = 0; $STIG_index -lt $STIGs.count; $STIG_index++) {

[string]$vulnNumber=$STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]

"Checking Vuln Number: $vulnNumber"

$vuln=$ACAS | Where-Object {$_.vulns -eq $vulnNumber}

if($vuln.Status -eq "NotAFinding"){$ActualStatus = "NotAFinding"}
elseif($vuln.Status -eq "Finding"){$ActualStatus = "Open"}

if ($ActualStatus -ne $null) {
            #$STIGs[$STIG_index].STATUS = $ActualStatus
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].STATUS = $ActualStatus}

        #reset our flag
        Remove-Variable ActualStatus -EA SilentlyContinue
}

$savedir=$checklistold.FileName.TrimEnd($checklistold.SafeFileName)
$filename=$checklistold.SafeFileName.TrimEnd(".ckl")+".new.ckl"

Out-File -InputObject $checklist.Innerxml -Encoding default "$savedir\$filename"

"Saved to: $savedir\$filename"
pause