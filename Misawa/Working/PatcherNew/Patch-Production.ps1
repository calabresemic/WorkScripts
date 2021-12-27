<#
==========================================================================
Modified for use in Misawa AB by A1C Calabrese, Michael K
==========================================================================
#>

#Checks for PSTools in System Directory and copys if missing
If((Test-Path C:\Windows\System32\Pslist.exe -PathType Leaf) -eq $False){Copy-Item -Force -Recurse C:\Working\PSTools\*.exe C:\Windows\System32}

#Removes results left from previous runs
Remove-Item -Force C:\Working\PatcherNew\Results\results.csv -ErrorAction SilentlyContinue
Remove-Item -Path C:\Working\PatcherNew\Results\GoodPings.txt -ErrorAction SilentlyContinue
Remove-Item -Path C:\Working\PatcherNew\Results\BadPings.txt -ErrorAction SilentlyContinue

#loads the functions
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
Import-Module C:\Working\PatcherNew\Scripts\Internal\Invoke-Ping.ps1

#Location of where the script pulls the target computers
$Masterlist = Get-Content C:\Working\PatcherNew\list.txt

#Pings the list of machines
Write-host Pinging machines... Please wait...
$MasterList | Invoke-Ping -Quiet | Out-File C:\Working\PatcherNew\Results\GoodPings.txt
$list = Get-Content C:\Working\PatcherNew\Results\GoodPings.txt
$Masterlist | ?{$list -notcontains $_} | Out-File C:\Working\PatcherNew\Results\BadPings.txt

#Restarts the script until the user exits
do{

    [int]$batch = 0

    while ( $batch -lt 1 -or $batch -gt 1000 )
    {
    
    #Edit menu in Scripts\Internal\Functions.ps1
    Menu
    
    }

    #Full Patcher
    if($batch -eq "1"){
    PromptRestart
       If($list.count -lt 7){
	        If($restart -eq $true){
                ForEach ($Computer in $list){
                xcopy /y /e /i /j C:\Working\PatcherNew\Patches\Updates \\$computer\c$\PatcherNew\Patches\Updates
                PSUpdate
                LOG
                Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
                Restart}
            }
            Else{
                ForEach ($Computer in $list){
                xcopy /y /e /i /j C:\Working\PatcherNew\Patches\Updates \\$computer\c$\PatcherNew\Patches\Updates
                PSUpdate
                LOG
                Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue}
            }
        }
       Else{
       #Runs the patch in multiple windows. The number at the end is the number of windows.
        If($restart -eq $true){RUN $updatesRps1 6}
        Else{Run $updatesps1 6}
        }
    }

    #Install Office Patches
    if($batch -eq "2"){
    PromptRestart
       If($list.count -lt 7){
            If($restart -eq $true){
	            ForEach ($Computer in $list){
                    xcopy /y /e /i C:\Working\PatcherNew\Patches\Updates \\$computer\c$\PatcherNew\Patches\Updates
                    PSOffice
                    LOG
                    Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
                    Restart}
            }
            Else{
                ForEach ($Computer in $list){
                xcopy /y /e /i C:\Working\PatcherNew\Patches\Updates \\$computer\c$\PatcherNew\Patches\Updates
                PSOffice
                LOG
                Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue}
            }
        }
       Else{
            If($restart -eq $true){RUN $officeRps1 6}
            Else{RUN $officeps1 6}
        }
    }

    #Install 3rd Party
    if($batch -eq "3"){
    PromptRestart
    $folders = (dir -Path C:\Working\PatcherNew\Patches\3rdParty).Name
       If($list.count -lt 7){
            If($restart -eq $true){
                ForEach ($Computer in $list){
                xcopy /y /e /i C:\Working\PatcherNew\Patches\3rdParty \\$computer\c$\PatcherNew\Patches\3rdParty
                    ForEach($folder in $folders){
                        If((Test-Path C:\Working\PatcherNew\Patches\3rdParty\$folder\runthis.bat) -eq $True){PsExec /s \\$computer C:\PatcherNew\Patches\3rdParty\$folder\runthis.bat}
                        Else {PsExec -accepteula /s \\$computer C:\PatcherNew\Patches\3rdParty\$folder\Install.cmd}
                        LOG
                        Remove-Item -Recurse -Force \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
                        Restart}
                    }
            }
            Else{
                ForEach ($Computer in $list){
                xcopy /y /e /i C:\Working\PatcherNew\Patches\3rdParty \\$computer\c$\PatcherNew\Patches\3rdParty
                    ForEach($folder in $folders){
                        If((Test-Path C:\Working\PatcherNew\Patches\3rdParty\$folder\runthis.bat) -eq $True){PsExec /s \\$computer C:\PatcherNew\Patches\3rdParty\$folder\runthis.bat}
                        Else {PsExec -accepteula /s \\$computer C:\PatcherNew\Patches\3rdParty\$folder\Install.cmd}
                        LOG
                        Remove-Item -Recurse -Force \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue}
                 }
            }
        }
       Else{
            If($restart -eq $true){RUN $3rdpartyRps1 6}
            Else{RUN $3rdpartyps1 6}
        }
    }

    #Report Patches
    If ($batch -eq "4"){
       Write-Host "Collecting patch reports... results will be available at Results\InstallResults.csv"
       #Removes old results
       Remove-Item C:\Working\PatcherNew\Results\InstallResults.csv -Force -ErrorAction SilentlyContinue
       If ($list.count -lt 7){
	        ForEach ($Computer in $list){
                Try{$hotfix = Get-WmiObject win32_quickfixengineering -ComputerName $Computer -ErrorAction Stop -WarningAction Stop -InformationAction Stop | Select CSName,Description,HotFixID,InstalledBy,InstalledOn | Where {$_.InstalledOn -gt ((Get-Date).adddays(-30))}
                Export-Hotfix}
                Catch{New-Object PSObject -Property @{ Description=$_; CSName=$computer } | Export-Csv -NoTypeInformation -Append C:\Working\PatcherNew\Results\InstallResults.csv }
             }
        }
       Else{RUN $reportps1 12}
    }

    #Check Installed Programs
    If($batch -eq "5"){
       Write-Host "Checking installed programs... Please Wait..."
       ForEach ($Computer in $list){
            GetInstalledPrograms
       }
    }

    #Uninstall Programs
    If ($batch -eq "6"){
       If ($list.count -lt 7){
	    ForEach ($Computer in $list){
            PsExec -accepteula /s \\$computer wmic product where "name like '$program'" call uninstall
            LOG
         }
       }
       Else{#Outputs the variable so it can be opened by the external scripts   
            $program | Out-File -Force C:\Working\PatcherNew\Var\program.txt
            RUN $uninstallps1 6}
    }

    #View Uptime and additional remote system information
    If ($batch -eq "7"){
       Remove-Item C:\Working\PatcherNew\Results\SysInfo.txt -Force -ErrorAction SilentlyContinue
       "System Information as of:" >> C:\Working\PatcherNew\Results\SysInfo.txt
       Get-Date >> C:\Working\PatcherNew\Results\SysInfo.txt
       "----------" >> C:\Working\PatcherNew\Results\SysInfo.txt
       " " >> C:\Working\PatcherNew\Results\SysInfo.txt
       If ($list.count -lt 7){
	    ForEach ($Computer in $list){
          If ((Test-Path \\$Computer\c$) -eq $True){
            $line1 = PsInfo -d \\$Computer
            $line2 = "----------" 
            $line3 = " "
            $line1, $line2, $line3 | Out-File -Append C:\Working\PatcherNew\Results\SysInfo.txt
          } 
          Else{
            $line1 = " "
            $line2 = "Could not connect to $Computer..."
            $line3 = "----------"
            $line4 = " "
            $line1, $line2, $line3, $line4 | Out-File -Append C:\Working\PatcherNew\Results\SysInfo.txt
          }
       Write-Host "Check the following location for the results: C:\Working\PatcherNew\Results\SysInfo.txt"
       }
      }
       Else{RUN $sysinfops1 6}
    }

    #View Logged On Users
    If ($batch -eq "8"){
        #Removes old results
        Remove-Item C:\Working\PatcherNew\Results\LoggedOn.txt -Force -ErrorAction SilentlyContinue
        ForEach ($Computer in $list){
            If((Test-Path \\$Computer\C$) -eq $True){
                start powershell "PsLoggedOn \\$Computer >> C:\Working\PatcherNew\Results\LoggedOn.txt" -Wait
                "----------" >> C:\Working\PatcherNew\Results\LoggedOn.txt
                " " >> C:\Working\PatcherNew\Results\LoggedOn.txt
            }
            Else{
                " Could not connect to $Computer..." >> C:\Working\PatcherNew\Results\LoggedOn.txt
                "----------" >> C:\Working\PatcherNew\Results\LoggedOn.txt
                " " >> C:\Working\PatcherNew\Results\LoggedOn.txt
            }
        }
        Write-Host "Check the following location for the results: C:\Working\PatcherNew\Results\LoggedOn.txt"
    }

    #Update McAfee
    If ($batch -eq "9"){
       If ($list.count -lt 7){
	    ForEach ($Computer in $list){
            PsExec -accepteula \\$computer /s /f /c 'C:\Working\PatcherNew\Scripts\External\McUpdate.bat'
            LOG
        }
       }
       Else{RUN $mcupdateps1 6}
    }

    #ReInstall McAfee Agent
    If ($batch -eq "10"){
       If ($list.count -lt 7){
	    ForEach ($Computer in $list){
            xcopy /y /e /i "C:\Working\PatcherNew\Patches\Agent" \\$computer\c$\PatcherNew\Patches\Agent
	        PsExec -accepteula \\$computer /s /f /c 'C:\Working\PatcherNew\Scripts\External\Agent.bat'
            LOG
         }
       }
       Else{RUN $agentps1 6}
    }
    
    #Update McAfee DAT file
    If ($batch -eq "11"){
       If ($list.count -lt 7){
	    ForEach ($Computer in $list){
            xcopy /y /e /i "C:\Working\PatcherNew\Patches\DAT" \\$computer\c$\PatcherNew\Patches\DAT
	        PsExec -accepteula \\$computer /s /f /c 'C:\Working\PatcherNew\Scripts\External\DAT.bat'
            LOG
         }
       }
       Else{ RUN $datps1 6}   
    }
    #View McAfee Engine and DAT version
    If ($batch -eq "12"){
       Remove-Item C:\Working\PatcherNew\Results\McAfeeInfo.txt -Force -ErrorAction SilentlyContinue
       "McAfee DAT and Engine version as of:" >> C:\Working\PatcherNew\Results\McAfeeInfo.txt
       Get-Date >> C:\Working\PatcherNew\Results\McAfeeInfo.txt
       "----------" >> C:\Working\PatcherNew\Results\McAfeeInfo.txt
       If ($list.count -lt 7){
	    ForEach ($Computer in $list){
            $line1 = $Computer
            $line2 = PsExec \\$Computer /S "C:\Program Files\Common Files\McAfee\SystemCore\csscan.exe" -Versions 
            $line3 = "----------"
            $line4 = " "
            $line1, $line2, $line3, $line4 | Out-File -Append C:\Working\PatcherNew\Results\McAfeeInfo.txt
         }
       }
       Else{RUN $mcafeeinfops1 6} 
    }
    #Start A Service
    If ($batch -eq "13"){
       #Removes old results
       Remove-Item C:\Working\PatcherNew\Results\ServceResults.csv -Force -ErrorAction SilentlyContinue
       #Prompts for name of service then outputs variable for the external scripts
       $name = Read-Host "What Service?"
       $name | Out-File -Force C:\Working\PatcherNew\Var\service.txt  
       If ($list.count -lt 100){
        $results = @()
        foreach($computer in $list){
           Try{
                Set-Service -ComputerName $computer -Name $Name -StartupType Automatic -Status Running -WarningAction Stop -ErrorAction Stop -InformationAction Stop
                $o = New-Object PSObject -Property @{ Result="Started"; Computer=$computer }
                $results += ,$o
                }
           Catch{
                $o = New-Object PSObject -Property @{ Result=$_.Exception.message; Computer=$computer }
                $results += ,$o
                }}
         $results | Export-Csv -NoTypeInformation -Append C:\Working\PatcherNew\Results\ServceResults.csv
       }
       Else{RUN $servicestarterps1 10}
    }
    #Adds a count of the good-pings list
    write-host $list.count "Machines Patched"
    #Restarts the script until the user types "2 or more"
    $repeat = read-host "1 = Rerun Script | Enter to Exit Script"
}


while ($repeat -eq "1")

#pauses script
Write-Host "Press any key to exit"
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")