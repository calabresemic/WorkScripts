#Requires -Version 5.0
#Created by Michael Calabrese (1468714589)
#This is designed to patch workstations and collect computer and user information
#This maybe doesn't require PSv5 but I don't want weird issues when commandlets don't exist on older versions 

<# Revision History
1/11/21 : Michael Calabrese (1468714589) - Converting from static "Working folder" design to unified package
#>

#Set working directory and start logging
$workingdir=$PSScriptRoot
$workingdir=C:\Users\1468714589.adm\Desktop\working
#Start-Transcript -Path "$workingdir\patch-production.log" -Append
$resultspath="$workingdir\Results\$(Get-Date -Format ddMMMyy)"

#Prep the folder structure
New-Item $resultspath -ItemType Directory -ErrorAction SilentlyContinue
New-Item $workingdir\Patches\Updates -ItemType Directory -ErrorAction SilentlyContinue
New-Item $workingdir\Patches\3rdParty -ItemType Directory -ErrorAction SilentlyContinue
New-Item $workingdir\Patches\Agent -ItemType Directory -ErrorAction SilentlyContinue
New-Item $workingdir\list.txt -ItemType File -ErrorAction SilentlyContinue

#Checks prereqs
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
If(!(Get-Module ActiveDirectory)){"RSAT Tools are required for this script to function and could not be found.";Pause;Exit}

#region Functions
"Loading Functions"
[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms") | Out-Null

Function Show-Starter{
# Create the form
$start = New-Object Windows.Forms.Form
$start.StartPosition = "CenterScreen"
$start.AutoSize = $True
$start.AutoSizeMode = "GrowAndShrink"
$start.KeyPreview = $True
$start.topmost = $true

#Set the dialog title
$start.text = "Master Patch Script"

# Create the label control and set text, size and location
$startFont = New-Object System.Drawing.Font("Times New Roman",18)
$start.Font = $startFont
$startLabel = New-Object System.Windows.Forms.Label
$startLabel.Text = "Select the Options Below:"
$startLabel.AutoSize = $True
$start.controls.add($startlabel)

# Create Button and set text and location
$startbutton1 = New-Object Windows.Forms.Button
$startbutton1.text = "Check Stale AD Computers"
$startbutton1.Location = New-Object Drawing.Point 0,55
$startbutton1.size = new-object drawing.point 380,40
$start.controls.add($startbutton1)
$startbutton1.add_click({

    $popup = New-Object Windows.Forms.Form
    $popup.StartPosition = "CenterScreen"
    $popup.text = "Stale Computers"
    $popup.AutoSize = $True
    $popup.AutoSizeMode = "GrowAndShrink"
    $popup.TopMost = $True
        
    $pFont = New-Object System.Drawing.Font("Times New Roman",12)
    $popup.Font = $pFont
    $pLabel = New-Object System.Windows.Forms.Label
    $pLabel.Text = "Select Options Below:"
    $pLabel.AutoSize = $True
    $popup.controls.add($plabel)
        
    $pbutton1 = New-Object Windows.Forms.Button
    $pbutton1.text = "$l"
    $pbutton1.Location = New-Object Drawing.Point 0,35
    $pbutton1.size = new-object drawing.point 130,30
    $popup.controls.add($pbutton1)
    $pbutton1.add_click({
    Check-StaleComps $l
    $popup.close()
    })

    $pbutton2 = New-Object Windows.Forms.Button
    $pbutton2.text = "Select From List"
    $pbutton2.Location = New-Object Drawing.Point 140,35
    $pbutton2.size = new-object drawing.point 180,30
    $popup.controls.add($pbutton2)
    $pbutton2.add_click({
    $BaseName=$bases | Out-GridView -PassThru
    Check-StaleComps $BaseName
    $popup.Close()
    })
     
    $popup.showDialog()

$start.Close()})

$startbutton2 = New-Object Windows.Forms.Button
$startbutton2.text = "Check AD Accounts for 1FA"
$startbutton2.Location = New-Object Drawing.Point 0,95
$startbutton2.size = new-object drawing.point 380,40
$start.controls.add($startbutton2)
$startbutton2.add_click({

    $popup = New-Object Windows.Forms.Form
    $popup.StartPosition = "CenterScreen"
    $popup.text = "1FA Accounts"
    $popup.AutoSize = $True
    $popup.AutoSizeMode = "GrowAndShrink"
    $popup.TopMost = $True
        
    $pFont = New-Object System.Drawing.Font("Times New Roman",12)
    $popup.Font = $pFont
    $pLabel = New-Object System.Windows.Forms.Label
    $pLabel.Text = "Select From the Options Below:"
    $pLabel.AutoSize = $True
    $popup.controls.add($plabel)
        
    $pbutton1 = New-Object Windows.Forms.Button
    $pbutton1.text = "$l"
    $pbutton1.Location = New-Object Drawing.Point 0,35
    $pbutton1.size = new-object drawing.point 130,30
    $popup.controls.add($pbutton1)
    $pbutton1.add_click({
    Check-1FA $l
    $popup.close()
    })

    $pbutton2 = New-Object Windows.Forms.Button
    $pbutton2.text = "Select From List"
    $pbutton2.Location = New-Object Drawing.Point 140,35
    $pbutton2.size = new-object drawing.point 180,30
    $popup.controls.add($pbutton2)
    $pbutton2.add_click({
    $BaseName=$bases | Out-GridView -PassThru
    Check-1FA $BaseName
    $popup.Close()
    })
     
    $popup.showDialog()

$start.Close()})

$startbutton3 = New-Object Windows.Forms.Button
$startbutton3.text = "Ping and Continue"
$startbutton3.Location = New-Object Drawing.Point 0,135
$startbutton3.size = new-object drawing.point 380,40
$start.controls.add($startbutton3)
$startbutton3.add_click({
$Script:continue = $true 
$start.Close()})

$startbutton3 = New-Object Windows.Forms.Button
$startbutton3.text = "Exit"
$startbutton3.Location = New-Object Drawing.Point 0,175
$startbutton3.size = new-object drawing.point 380,40
$start.controls.add($startbutton3)
$startbutton3.add_click({
$Script:continue = $False 
$start.Close()})

# Display the dialog
$start.showDialog() | Out-Null
} #DONE

Function Show-Menu{
# Create the form
$form = New-Object Windows.Forms.Form
$Form.StartPosition = "CenterScreen"
$Form.AutoSize = $True
$Form.AutoSizeMode = "GrowAndShrink"
$form.KeyPreview = $True
$form.topmost = $true

#Set the dialog title
$form.text = "Master Patch Script"

# Create the label control and set text, size and location
$Font = New-Object System.Drawing.Font("Times New Roman",16)
$Form.Font = $Font
$Label = New-Object System.Windows.Forms.Label
$Label.Text = "Select From the Options Below:"
$Label.AutoSize = $True
$form.controls.add($label)

# Create Button and set text and location
$button1 = New-Object Windows.Forms.Button
$button1.text = "Install ALL Patches"
$button1.Location = New-Object Drawing.Point 0,55
$button1.size = new-object drawing.point 380,35
$form.controls.add($button1)
$button1.add_click({
$script:batch = 1
$form.close()
})

$button2 = New-Object Windows.Forms.Button
$button2.text = "Taskkill/Install Office Patches"
$button2.Location = New-Object Drawing.Point 0,90
$button2.size = new-object drawing.point 380,35
$form.controls.add($button2)
$button2.add_click({
$script:batch = 2
$form.close()
})

$button3 = New-Object Windows.Forms.Button
$button3.text = "Install 3rd Party"
$button3.Location = New-Object Drawing.Point 0,125
$button3.size = new-object drawing.point 380,35
$form.controls.add($button3)
$button3.add_click({
$script:batch = 3
$form.close()
})

$button4 = New-Object Windows.Forms.Button
$button4.text = "Report Installed Patches"
$button4.Location = New-Object Drawing.Point 0,160
$button4.size = new-object drawing.point 380,35
$form.controls.add($button4)
$button4.add_click({
$script:batch = 4
$form.close()
})

$button5 = New-Object Windows.Forms.Button
$button5.text = "Report Installed Programs"
$button5.Location = New-Object Drawing.Point 0,195
$button5.size = new-object drawing.point 380,35
$form.controls.add($button5)
$button5.add_click({
$script:batch = 5
$form.close()
})

$button6 = New-Object Windows.Forms.Button
$button6.text = "Report Uptime and Disk Size"
$button6.Location = New-Object Drawing.Point 0,230
$button6.size = new-object drawing.point 380,35
$form.controls.add($button6)
$button6.add_click({
$script:batch = 6
$form.close()
})

$button7 = New-Object Windows.Forms.Button
$button7.text = "(Re)Install McAfee Agent"
$button7.Location = New-Object Drawing.Point 0,265
$button7.size = new-object drawing.point 380,35
$form.controls.add($button7)
$button7.add_click({
$script:batch = 7
$form.close()
})

#Adds the escape key to close the form
$form.add_KeyDown({
if ($_.KeyCode -eq "Escape"){
$script:exit = $true
$form.close()}
})

# Display the dialog
$form.showDialog() | Out-Null
} #DONE

Function Check-1FA ($BaseName){
if($BaseName -in $cent){$OU="AFCONUSCENTRAL"}
elseif($BaseName -in $east){$OU="AFCONUSEAST"}
elseif($BaseName -in $west){$OU="AFCONUSWEST"}

$user = "OU=$BaseName Users,OU=$BaseName,OU=$OU,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
Get-ADUser -Filter {SmartcardLogonRequired -eq "FALSE"} -Properties Name,EmployeeID,SmartcardLogonRequired -SearchBase $user | Select-Object Name,EmployeeID,SmartcardLogonRequired | Export-Csv -Path "$resultspath\$($BaseName)_1FA_User_Results.csv" -NoTypeInformation

$admin = "OU=$BaseName, OU=Administrative Accounts,OU=Administration,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
Get-ADUser -Filter {SmartcardLogonRequired -eq "FALSE"} -Properties Name,EmployeeID,SmartcardLogonRequired -SearchBase $admin | Select-Object Name,EmployeeID,SmartcardLogonRequired | Export-Csv -Path "$resultspath\$($BaseName)_1FA_Admin_Results.csv" -NoTypeInformation
} #DONE

Function Check-StaleComps ($BaseName){
if($BaseName -in $cent){$OU="AFCONUSCENTRAL"}
elseif($BaseName -in $east){$OU="AFCONUSEAST"}
elseif($BaseName -in $west){$OU="AFCONUSWEST"}

$date=Get-Date
$DaysInactive = "60"
$time = $date.Adddays(-($DaysInactive))
Get-ADComputer -Filter {lastLogonTimestamp -lt $time} -SearchBase "OU=$BaseName Computers,OU=$BaseName,OU=$OU,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -Properties Name,OperatingSystem,lastLogonTimestamp | Select-Object Name,OperatingSystem,@{N="Last Logon Date"; E={[DateTime]::FromFileTime($_.lastLogonTimestamp)}},@{N='Days Stale';E={($date-[DateTime]::FromFileTime($_.lastLogonTimestamp)).Days}} | Sort-Object 'Days Stale' -Descending | Export-CSV "$resultspath\$($BaseName)_Stale_Comps.csv" –NoTypeInformation
} #DONE

Function Run-Script ($script, $int){
    $computers = $compute = @()
    $computers = $list
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
        "List $($i) has $($compute.count) computers in it"
        "First computer is $($compute[0]), last computer is $($compute[-1])"
        #script to be ran
        Start-Process powershell.exe "$script $compute"
        $i++
        $currentscriptcount++
        }
        
}

Function Schedule-Restart ($Computer){
#Schedules a restart on the target computer with a prompt that warns user of restart in 10 minutes
#you can change the location of the .bat file to somewhere else if you would like.
schtasks /create /s $Computer /sc once /ru SYSTEM /tn "Scheduled Reboot" /tr “shutdown /r /t 0" /st 23:59 /f
} #DONE

Function PS-Update ($Computer){
    $officecabs=Get-ChildItem $workingdir\patches\Updates | Where-Object { ($_.BaseName -like "*-x-none_*") -and ($_.Extension -eq '.cab') }
    foreach($cab in $officecabs){Extract-CAB $_}
    xcopy /y /e /i /j $workingdir\patches\Updates \\$computer\c$\PatcherNew
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Get-ChildItem C:\PatcherNew\*.exe | %{& $_.FullName /norestart /q}
        Get-ChildItem C:\PatcherNew\*.cab | %{& Dism.exe /online /add-package /packagepath:$($_.FullName) /quiet /norestart}
        Get-ChildItem C:\PatcherNew\*.msp | %{& $_.FullName /norestart /q}
        Get-ChildItem C:\PatcherNew\*.msu | %{& wusa.exe $_.FullName /norestart /quiet}}
    Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
} #TESTING

Function PS-Office ($Computer){
    $officecabs=Get-ChildItem $workingdir\patches\Updates | Where-Object { ($_.BaseName -like "*-x-none_*") -and ($_.Extension -eq '.cab') }
    foreach($cab in $officecabs){Extract-CAB $_}
    xcopy /y /e /i /j $workingdir\patches\Updates \\$computer\c$\PatcherNew
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        taskkill /IM EXCEL.EXE /F
        taskkill /IM OUTLOOK.EXE /F
        taskkill /IM WINWORD.EXE /F
        taskkill /IM LYNC.EXE /F
        taskkill /IM POWERPNT.EXE /F
        taskkill /IM MSACCESS.EXE /F
        Get-ChildItem C:\PatcherNew\*.exe | %{& $_.FullName /norestart /q}
        Get-ChildItem C:\PatcherNew\*.msp | %{& $_.FullName /norestart /q}}
    Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
} #TESTING

Function PS-MCAgent ($Computer){
    xcopy /y /e /i /j $workingdir\patches\Agent \\$computer\c$\PatcherNew
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Get-ChildItem C:\PatcherNew\*.exe | %{& $_.FullName /forceuninstall}
        Get-ChildItem C:\PatcherNew\*.exe | %{& $_.FullName /install=agent /forceinstall}}
    Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
} #TESTING

Function PS-3rdParty ($Computer){
    $folders=(Get-ChildItem $workingdir\patches\3rdParty -Directory).Name
    xcopy /y /e /i $workingdir\patches\3rdParty \\$computer\c$\PatcherNew
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        $folders=(Get-ChildItem C:\PatcherNew -Directory).FullName
        ForEach($folder in $folders){
        & "$folder\install.cmd"}
        }
    Remove-Item -Recurse -Force \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
} #TESTING

Function Extract-CAB ($File){
    New-Item $workingdir\patches\unpack -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
    expand.exe -F:*.msp $file.FullName $workingdir\patches\unpack | Out-Null
    $update=Get-ChildItem $workingdir\patches\unpack
    $name=$File.BaseName+'.msp'
    Move-Item $update.FullName $workingdir\patches\updates\$name -Force
    Remove-Item $File.FullName
} #DONE

Function Prompt-Restart{
#Opens a window to allow user to select if they want to schedule restart on client machines
$fp = New-Object Windows.Forms.Form
$fp.StartPosition = "CenterScreen"
$fp.AutoSize = $True
$fp.AutoSizeMode = "GrowAndShrink"
$fp.KeyPreview = $True
$fp.topmost = $true
$fp.text = "Full Patcher"
$Font = New-Object System.Drawing.Font("Times New Roman",16)
$fp.Font = $Font
$fpl = New-Object System.Windows.Forms.Label
$fpl.Text = "Schedule Restart?"
$fpl.AutoSize = $True
$fp.controls.add($fpl)

$button1 = New-Object Windows.Forms.Button
$button1.text = "Yes"
$button1.Location = New-Object Drawing.Point 0,35
$button1.size = new-object drawing.point 250,30
$fp.controls.add($button1)
$button1.add_click({
$script:restart = $true
$fp.close()})

$button2 = New-Object Windows.Forms.Button
$button2.text = "No"
$button2.Location = New-Object Drawing.Point 0,65
$button2.size = new-object drawing.point 250,30
$fp.controls.add($button2)
$button2.add_click({
$script:restart = $false
$fp.Close()})
$fp.showDialog() | Out-Null
} #DONE

Function Get-InstalledPrograms ($Computer){
$InstalledPrograms=Get-WmiObject -Class Win32Reg_AddRemovePrograms64 -ComputerName $computer
$InstalledPrograms | Select DisplayName,Version,InstallDate,PSComputerName | Export-Csv -NoTypeInformation -Force "$resultspath\Installed_Programs_Report.csv" -Append
} #DONE

Function Get-InstalledPatches ($Computer){
$InstalledPatches=Get-HotFix -ComputerName $computer
$InstalledPatches | Select HotFixID,InstalledBy,InstallOn,Source | Export-Csv -NoTypeInformation -Force "$resultspath\Installed_Patches_Report.csv" -Append
} #DONE

Function Get-ComputerInformation ($Computer){
$OSInfo=Get-WmiObject Win32_OperatingSystem -ComputerName $Computer
$CompInfo=Get-WmiObject Win32_ComputerSystem -ComputerName $Computer
$NetworkInfo=Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $Computer | Where-Object {$_.IPEnabled -and $_.MACAddress -ne $null}
$UpTime= (Get-Date) - $OSInfo.ConverttoDateTime($OSInfo.LastBootUpTime)
$UpTimeString="$($UpTime.Days):$($UpTime.Hours):$($UpTime.Minutes):$($UpTime.Seconds)"

$disks=Get-CimInstance Win32_LogicalDisk -ComputerName $Computer
$Driveinfo=@()
foreach($Drive in $disks){
    Switch($Drive.drivetype){
0 {$DriveValue = "Unknown Drive"}
1 {$DriveValue = "No Root Directory"}
2 {$DriveValue = "Removable Drive"}
3 {$DriveValue = "Fixed Drive"}
4 {$DriveValue = $Drive.ProviderName}
5 {$DriveValue = "Optical Drive"}
6 {$DriveValue = "RAM Drive"}
}
    $Driveinfo+="$($Drive.DeviceID.trim(':'))=$($Drivevalue)($([math]::Round( ($drive.FreeSpace)/($drive.Size),2)*100)% Free)"
    }
$Drives=$Driveinfo -join ","

[PSCustomObject]@{Computer=$Computer;IP=$NetworkInfo.IPAddress;Uptime=$UpTimeString;LoggedOnUser=$CompInfo.UserName;DiskInfo=$Drives;PCMake=$CompInfo.Manufacturer;PCModel=$CompInfo.Model;OSName=$OSInfo.Caption;OSVersion=$OSInfo.Version} | Export-Csv -NoTypeInformation "$resultspath\Computer_Info.csv" -Append
} #DONE

Function Invoke-Ping {
<#
.SYNOPSIS
    Ping or test connectivity to systems in parallel
    
.DESCRIPTION
    Ping or test connectivity to systems in parallel

    Default action will run a ping against systems
        If Quiet parameter is specified, we return an array of systems that responded
        If Detail parameter is specified, we test WSMan, RemoteReg, RPC, RDP and/or SMB

.PARAMETER ComputerName
    One or more computers to test

.PARAMETER Quiet
    If specified, only return addresses that responded to Test-Connection

.PARAMETER Detail
    Include one or more additional tests as specified:
        WSMan      via Test-WSMan
        RemoteReg  via Microsoft.Win32.RegistryKey
        RPC        via WMI
        RDP        via port 3389
        SMB        via \\ComputerName\C$
        *          All tests

.PARAMETER Timeout
    Time in seconds before we attempt to dispose an individual query.  Default is 20

.PARAMETER Throttle
    Throttle query to this many parallel runspaces.  Default is 100.

.PARAMETER NoCloseOnTimeout
    Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out

    This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

.EXAMPLE
    Invoke-Ping Server1, Server2, Server3 -Detail *

    # Check for WSMan, Remote Registry, Remote RPC, RDP, and SMB (via C$) connectivity against 3 machines

.EXAMPLE
    $Computers | Invoke-Ping

    # Ping computers in $Computers in parallel

.EXAMPLE
    $Responding = $Computers | Invoke-Ping -Quiet
    
    # Create a list of computers that successfully responded to Test-Connection

.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a

.FUNCTIONALITY
    Computers

#>
    [cmdletbinding(DefaultParameterSetName='Ping')]
    param(
        [Parameter( ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    Position=0)]
        [string[]]$ComputerName,
        
        [Parameter( ParameterSetName='Detail')]
        [validateset("*","WSMan","RemoteReg","RPC","RDP","SMB")]
        [string[]]$Detail,
        
        [Parameter(ParameterSetName='Ping')]
        [switch]$Quiet,
        
        [int]$Timeout = 20,
        
        [int]$Throttle = 100,

        [switch]$NoCloseOnTimeout
    )
    Begin
    {

        #http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
        function Invoke-Parallel {
            [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
            Param (   
                [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
                    [System.Management.Automation.ScriptBlock]$ScriptBlock,

                [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
                [ValidateScript({test-path $_ -pathtype leaf})]
                    $ScriptFile,

                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [Alias('CN','__Server','IPAddress','Server','ComputerName')]    
                    [PSObject]$InputObject,

                    [PSObject]$Parameter,

                    [switch]$ImportVariables,

                    [switch]$ImportModules,

                    [int]$Throttle = 20,

                    [int]$SleepTimer = 200,

                    [int]$RunspaceTimeout = 0,

			        [switch]$NoCloseOnTimeout = $false,

                    [int]$MaxQueue,

                [validatescript({Test-Path (Split-Path $_ -parent)})]
                    [string]$LogFile = "C:\temp\log.log",

			        [switch] $Quiet = $false
            )
    
            Begin {
                
                #No max queue specified?  Estimate one.
                #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
                if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
                {
                    if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
                    else{ $script:MaxQueue = $Throttle * 3 }
                }
                else
                {
                    $script:MaxQueue = $MaxQueue
                }

                Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

                #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
                if ($ImportVariables -or $ImportModules)
                {
                    $StandardUserEnv = [powershell]::Create().addscript({

                        #Get modules and snapins in this clean runspace
                        $Modules = Get-Module | Select -ExpandProperty Name
                        $Snapins = Get-PSSnapin | Select -ExpandProperty Name

                        #Get variables in this clean runspace
                        #Called last to get vars like $? into session
                        $Variables = Get-Variable | Select -ExpandProperty Name
                
                        #Return a hashtable where we can access each.
                        @{
                            Variables = $Variables
                            Modules = $Modules
                            Snapins = $Snapins
                        }
                    }).invoke()[0]
            
                    if ($ImportVariables) {
                        #Exclude common parameters, bound parameters, and automatic variables
                        Function _temp {[cmdletbinding()] param() }
                        $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                        Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                        # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                        # One of the veriables that we pass is '$?'. 
                        # There could be other variables with such problems.
                        # Scope 2 required if we move to a real module
                        $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                        Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"

                    }

                    if ($ImportModules) 
                    {
                        $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                        $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
                    }
                }

                #region functions
            
                    Function Get-RunspaceData {
                        [cmdletbinding()]
                        param( [switch]$Wait )

                        #loop through runspaces
                        #if $wait is specified, keep looping until all complete
                        Do {

                            #set more to false for tracking completion
                            $more = $false

                            #Progress bar if we have inputobject count (bound parameter)
                            if (-not $Quiet) {
						        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
							        -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
							        -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
					        }

                            #run through each runspace.           
                            Foreach($runspace in $runspaces) {
                    
                                #get the duration - inaccurate
                                $currentdate = Get-Date
                                $runtime = $currentdate - $runspace.startTime
                                $runMin = [math]::Round( $runtime.totalminutes ,2 )

                                #set up log object
                                $log = "" | select Date, Action, Runtime, Status, Details
                                $log.Action = "Removing:'$($runspace.object)'"
                                $log.Date = $currentdate
                                $log.Runtime = "$runMin minutes"

                                #If runspace completed, end invoke, dispose, recycle, counter++
                                If ($runspace.Runspace.isCompleted) {
                            
                                    $script:completedCount++
                        
                                    #check if there were errors
                                    if($runspace.powershell.Streams.Error.Count -gt 0) {
                                
                                        #set the logging info and move the file to completed
                                        $log.status = "CompletedWithErrors"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                        foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                            Write-Error -ErrorRecord $ErrorRecord
                                        }
                                    }
                                    else {
                                
                                        #add logging details and cleanup
                                        $log.status = "Completed"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    }

                                    #everything is logged, clean up the runspace
                                    $runspace.powershell.EndInvoke($runspace.Runspace)
                                    $runspace.powershell.dispose()
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null

                                }

                                #If runtime exceeds max, dispose the runspace
                                ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            
                                    $script:completedCount++
                                    $timedOutTasks = $true
                            
							        #add logging details and cleanup
                                    $log.status = "TimedOut"
                                    Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                                    #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                                    if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null
                                    $completedCount++

                                }
                   
                                #If runspace isn't null set more to true  
                                ElseIf ($runspace.Runspace -ne $null ) {
                                    $log = $null
                                    $more = $true
                                }

                                #log the results if a log file was indicated
                                if($logFile -and $log){
                                    ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                                }
                            }

                            #Clean out unused runspace jobs
                            $temphash = $runspaces.clone()
                            $temphash | Where { $_.runspace -eq $Null } | ForEach {
                                $Runspaces.remove($_)
                            }

                            #sleep for a bit if we will loop again
                            if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                        #Loop again only if -wait parameter and there are more runspaces to process
                        } while ($more -and $PSBoundParameters['Wait'])
                
                    #End of runspace function
                    }

                #endregion functions
        
                #region Init

                    if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
                    {
                        $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
                    }
                    elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
                    {
                        #Start building parameter names for the param block
                        [string[]]$ParamsToAdd = '$_'
                        if( $PSBoundParameters.ContainsKey('Parameter') )
                        {
                            $ParamsToAdd += '$Parameter'
                        }

                        $UsingVariableData = $Null
                

                        # This code enables $Using support through the AST.
                        # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
                
                        if($PSVersionTable.PSVersion.Major -gt 2)
                        {
                            #Extract using references
                            $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    

                            If ($UsingVariables)
                            {
                                $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                                ForEach ($Ast in $UsingVariables)
                                {
                                    [void]$list.Add($Ast.SubExpression)
                                }

                                $UsingVar = $UsingVariables | Group Parent | ForEach {$_.Group | Select -First 1}
        
                                #Extract the name, value, and create replacements for each
                                $UsingVariableData = ForEach ($Var in $UsingVar) {
                                    Try
                                    {
                                        $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                        $NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        [pscustomobject]@{
                                            Name = $Var.SubExpression.Extent.Text
                                            Value = $Value.Value
                                            NewName = $NewName
                                            NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        }
                                        $ParamsToAdd += $NewName
                                    }
                                    Catch
                                    {
                                        Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                                    }
                                }
    
                                $NewParams = $UsingVariableData.NewName -join ', '
                                $Tuple = [Tuple]::Create($list, $NewParams)
                                $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                                $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
        
                                $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                                $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                                Write-Verbose $StringScriptBlock
                            }
                        }
                
                        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
                    }
                    else
                    {
                        Throw "Must provide ScriptBlock or ScriptFile"; Break
                    }

                    Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
                    Write-Verbose "Creating runspace pool and session states"

                    #If specified, add variables and modules/snapins to session state
                    $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                    if ($ImportVariables)
                    {
                        if($UserVariables.count -gt 0)
                        {
                            foreach($Variable in $UserVariables)
                            {
                                $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                            }
                        }
                    }
                    if ($ImportModules)
                    {
                        if($UserModules.count -gt 0)
                        {
                            foreach($ModulePath in $UserModules)
                            {
                                $sessionstate.ImportPSModule($ModulePath)
                            }
                        }
                        if($UserSnapins.count -gt 0)
                        {
                            foreach($PSSnapin in $UserSnapins)
                            {
                                [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                            }
                        }
                    }

                    #Create runspace pool
                    $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
                    $runspacepool.Open() 

                    Write-Verbose "Creating empty collection to hold runspace jobs"
                    $Script:runspaces = New-Object System.Collections.ArrayList        
        
                    #If inputObject is bound get a total count and set bound to true
                    $global:__bound = $false
                    $allObjects = @()
                    if( $PSBoundParameters.ContainsKey("inputObject") ){
                        $global:__bound = $true
                    }

                    #Set up log file if specified
                    if( $LogFile ){
                        New-Item -ItemType file -path $logFile -force | Out-Null
                        ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                    }

                    #write initial log entry
                    $log = "" | Select Date, Action, Runtime, Status, Details
                        $log.Date = Get-Date
                        $log.Action = "Batch processing started"
                        $log.Runtime = $null
                        $log.Status = "Started"
                        $log.Details = $null
                        if($logFile) {
                            ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                        }

			        $timedOutTasks = $false

                #endregion INIT
            }

            Process {

                #add piped objects to all objects or set all objects to bound input object parameter
                if( -not $global:__bound ){
                    $allObjects += $inputObject
                }
                else{
                    $allObjects = $InputObject
                }
            }

            End {
        
                #Use Try/Finally to catch Ctrl+C and clean up.
                Try
                {
                    #counts for progress
                    $totalCount = $allObjects.count
                    $script:completedCount = 0
                    $startedCount = 0

                    foreach($object in $allObjects){
        
                        #region add scripts to runspace pool
                    
                            #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                            $powershell = [powershell]::Create()
                    
                            if ($VerbosePreference -eq 'Continue')
                            {
                                [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                            }

                            [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                            if ($parameter)
                            {
                                [void]$PowerShell.AddArgument($parameter)
                            }

                            # $Using support from Boe Prox
                            if ($UsingVariableData)
                            {
                                Foreach($UsingVariable in $UsingVariableData) {
                                    Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                                    [void]$PowerShell.AddArgument($UsingVariable.Value)
                                }
                            }

                            #Add the runspace into the powershell instance
                            $powershell.RunspacePool = $runspacepool
    
                            #Create a temporary collection for each runspace
                            $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                            $temp.PowerShell = $powershell
                            $temp.StartTime = Get-Date
                            $temp.object = $object
    
                            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                            $temp.Runspace = $powershell.BeginInvoke()
                            $startedCount++

                            #Add the temp tracking info to $runspaces collection
                            Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                            $runspaces.Add($temp) | Out-Null
            
                            #loop through existing runspaces one time
                            Get-RunspaceData

                            #If we have more running than max queue (used to control timeout accuracy)
                            #Script scope resolves odd PowerShell 2 issue
                            $firstRun = $true
                            while ($runspaces.count -ge $Script:MaxQueue) {

                                #give verbose output
                                if($firstRun){
                                    Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                                }
                                $firstRun = $false
                    
                                #run get-runspace data and sleep for a short while
                                Get-RunspaceData
                                Start-Sleep -Milliseconds $sleepTimer
                    
                            }

                        #endregion add scripts to runspace pool
                    }
                     
                    Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
                    Get-RunspaceData -wait

                    if (-not $quiet) {
			            Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
		            }

                }
                Finally
                {
                    #Close the runspace pool, unless we specified no close on timeout and something timed out
                    if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
	                    Write-Verbose "Closing the runspace pool"
			            $runspacepool.close()
                    }

                    #collect garbage
                    [gc]::Collect()
                }       
            }
        }

        Write-Verbose "PSBoundParameters = $($PSBoundParameters | Out-String)"
        
        $bound = $PSBoundParameters.keys -contains "ComputerName"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$AllComputers = @()
        }
    }
    Process
    {

        #Handle both pipeline and bound parameter.  We don't want to stream objects, defeats purpose of parallelizing work
        if($bound)
        {
            $AllComputers = $ComputerName
        }
        Else
        {
            foreach($Computer in $ComputerName)
            {
                $AllComputers.add($Computer) | Out-Null
            }
        }

    }
    End
    {

        #Built up the parameters and run everything in parallel
        $params = @($Detail, $Quiet)
        $splat = @{
            Throttle = $Throttle
            RunspaceTimeout = $Timeout
            InputObject = $AllComputers
            parameter = $params
        }
        if($NoCloseOnTimeout)
        {
            $splat.add('NoCloseOnTimeout',$True)
        }

        Invoke-Parallel @splat -ScriptBlock {
        
            $computer = $_.trim()
            $detail = $parameter[0]
            $quiet = $parameter[1]

            #They want detail, define and run test-server
            if($detail)
            {
                Try
                {
                    #Modification of jrich's Test-Server function: https://gallery.technet.microsoft.com/scriptcenter/Powershell-Test-Server-e0cdea9a
                    Function Test-Server{
                        [cmdletBinding()]
                        param(
	                        [parameter(
                                Mandatory=$true,
                                ValueFromPipeline=$true)]
	                        [string[]]$ComputerName,
                            [switch]$All,
                            [parameter(Mandatory=$false)]
	                        [switch]$CredSSP,
                            [switch]$RemoteReg,
                            [switch]$RDP,
                            [switch]$RPC,
                            [switch]$SMB,
                            [switch]$WSMAN,
                            [switch]$IPV6,
	                        [Management.Automation.PSCredential]$Credential
                        )
                            begin
                            {
	                            $total = Get-Date
	                            $results = @()
	                            if($credssp -and -not $Credential)
                                {
                                    Throw "Must supply Credentials with CredSSP test"
                                }

                                [string[]]$props = write-output Name, IP, Domain, Ping, WSMAN, CredSSP, RemoteReg, RPC, RDP, SMB

                                #Hash table to create PSObjects later, compatible with ps2...
                                $Hash = @{}
                                foreach($prop in $props)
                                {
                                    $Hash.Add($prop,$null)
                                }

                                function Test-Port{
                                    [cmdletbinding()]
                                    Param(
                                        [string]$srv,
                                        $port=135,
                                        $timeout=3000
                                    )
                                    $ErrorActionPreference = "SilentlyContinue"
                                    $tcpclient = new-Object system.Net.Sockets.TcpClient
                                    $iar = $tcpclient.BeginConnect($srv,$port,$null,$null)
                                    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
                                    if(-not $wait)
                                    {
                                        $tcpclient.Close()
                                        Write-Verbose "Connection Timeout to $srv`:$port"
                                        $false
                                    }
                                    else
                                    {
                                        Try
                                        {
                                            $tcpclient.EndConnect($iar) | out-Null
                                            $true
                                        }
                                        Catch
                                        {
                                            write-verbose "Error for $srv`:$port`: $_"
                                            $false
                                        }
                                        $tcpclient.Close()
                                    }
                                }
                            }

                            process
                            {
                                foreach($name in $computername)
                                {
	                                $dt = $cdt= Get-Date
	                                Write-verbose "Testing: $Name"
	                                $failed = 0
	                                try{
	                                    $DNSEntity = [Net.Dns]::GetHostEntry($name)
	                                    $domain = ($DNSEntity.hostname).replace("$name.","")
	                                    $ips = $DNSEntity.AddressList | %{
                                            if(-not ( -not $IPV6 -and $_.AddressFamily -like "InterNetworkV6" ))
                                            {
                                                $_.IPAddressToString
                                            }
                                        }
	                                }
	                                catch
	                                {
		                                $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
		                                $rst.name = $name
		                                $results += $rst
		                                $failed = 1
	                                }
	                                Write-verbose "DNS:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
	                                if($failed -eq 0){
	                                    foreach($ip in $ips)
	                                    {
	    
		                                    $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
	                                        $rst.name = $name
		                                    $rst.ip = $ip
		                                    $rst.domain = $domain
		            
                                            if($RDP -or $All)
                                            {
                                                ####RDP Check (firewall may block rest so do before ping
		                                        try{
                                                    $socket = New-Object Net.Sockets.TcpClient($name, 3389) -ErrorAction stop
		                                            if($socket -eq $null)
		                                            {
			                                            $rst.RDP = $false
		                                            }
		                                            else
		                                            {
			                                            $rst.RDP = $true
			                                            $socket.close()
		                                            }
                                                }
                                                catch
                                                {
                                                    $rst.RDP = $false
                                                    Write-Verbose "Error testing RDP: $_"
                                                }
                                            }
		                                Write-verbose "RDP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                        #########ping
	                                    if(test-connection $ip -count 2 -Quiet)
	                                    {
	                                        Write-verbose "PING:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                $rst.ping = $true
			    
                                            if($WSMAN -or $All)
                                            {
                                                try{############wsman
				                                    Test-WSMan $ip -ErrorAction stop | Out-Null
				                                    $rst.WSMAN = $true
				                                }
			                                    catch
				                                {
                                                    $rst.WSMAN = $false
                                                    Write-Verbose "Error testing WSMAN: $_"
                                                }
				                                Write-verbose "WSMAN:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    if($rst.WSMAN -and $credssp) ########### credssp
			                                    {
				                                    try{
					                                    Test-WSMan $ip -Authentication Credssp -Credential $cred -ErrorAction stop
					                                    $rst.CredSSP = $true
					                                }
				                                    catch
					                                {
                                                        $rst.CredSSP = $false
                                                        Write-Verbose "Error testing CredSSP: $_"
                                                    }
				                                    Write-verbose "CredSSP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    }
                                            }
                                            if($RemoteReg -or $All)
                                            {
			                                    try ########remote reg
			                                    {
				                                    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ip) | Out-Null
				                                    $rst.remotereg = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.remotereg = $false
                                                    Write-Verbose "Error testing RemoteRegistry: $_"
                                                }
			                                    Write-verbose "remote reg:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($RPC -or $All)
                                            {
			                                    try ######### wmi
			                                    {	
				                                    $w = [wmi] ''
				                                    $w.psbase.options.timeout = 15000000
				                                    $w.path = "\\$Name\root\cimv2:Win32_ComputerSystem.Name='$Name'"
				                                    $w | select none | Out-Null
				                                    $rst.RPC = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.rpc = $false
                                                    Write-Verbose "Error testing WMI/RPC: $_"
                                                }
			                                    Write-verbose "WMI/RPC:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($SMB -or $All)
                                            {

                                                #Use set location and resulting errors.  push and pop current location
                    	                        try ######### C$
			                                    {	
                                                    $path = "\\$name\c$"
				                                    Push-Location -Path $path -ErrorAction stop
				                                    $rst.SMB = $true
                                                    Pop-Location
			                                    }
			                                    catch
				                                {
                                                    $rst.SMB = $false
                                                    Write-Verbose "Error testing SMB: $_"
                                                }
			                                    Write-verbose "SMB:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"

                                            }
	                                    }
		                                else
		                                {
			                                $rst.ping = $false
			                                $rst.wsman = $false
			                                $rst.credssp = $false
			                                $rst.remotereg = $false
			                                $rst.rpc = $false
                                            $rst.smb = $false
		                                }
		                                $results += $rst	
	                                }
                                }
	                            Write-Verbose "Time for $($Name): $((New-TimeSpan $cdt ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                }
                            }
                            end
                            {
	                            Write-Verbose "Time for all: $((New-TimeSpan $total ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                return $results
                            }
                        }
                    
                    #Build up parameters for Test-Server and run it
                        $TestServerParams = @{
                            ComputerName = $Computer
                            ErrorAction = "Stop"
                        }

                        if($detail -eq "*"){
                            $detail = "WSMan","RemoteReg","RPC","RDP","SMB" 
                        }

                        $detail | Select -Unique | Foreach-Object { $TestServerParams.add($_,$True) }
                        Test-Server @TestServerParams | Select -Property $( "Name", "IP", "Domain", "Ping" + $detail )
                }
                Catch
                {
                    Write-Warning "Error with Test-Server: $_"
                }
            }
            #We just want ping output
            else
            {
                Try
                {
                    #Pick out a few properties, add a status label.  If quiet output, just return the address
                    $result = $null
                    if( $result = @( Test-Connection -ComputerName $computer -Count 2 -erroraction Stop ) )
                    {
                        $Output = $result | Select -first 1 -Property Address,
                                                                      IPV4Address,
                                                                      IPV6Address,
                                                                      ResponseTime,
                                                                      @{ label = "STATUS"; expression = {"Responding"} }

                        if( $quiet )
                        {
                            $Output.address
                        }
                        else
                        {
                            $Output
                        }
                    }
                }
                Catch
                {
                    if(-not $quiet)
                    {
                        #Ping failed.  I'm likely making inappropriate assumptions here, let me know if this is the case : )
                        if($_ -match "No such host is known")
                        {
                            $status = "Unknown host"
                        }
                        elseif($_ -match "Error due to lack of resources")
                        {
                            $status = "No Response"
                        }
                        else
                        {
                            $status = "Error: $_"
                        }

                        "" | Select -Property @{ label = "Address"; expression = {$computer} },
                                              IPV4Address,
                                              IPV6Address,
                                              ResponseTime,
                                              @{ label = "STATUS"; expression = {$status} }
                    }
                }
            }
        }
    }
} #DONE

#endregion Functions

#Gather User information
$adobj = ([adsisearcher]"SamAccountname=$env:USERNAME").findone()
$l = $adobj.Properties.l
$Domain=Get-ADDomain
$bases=@()

Switch($domain.Name){
    AREA52     {$bases+=$cent=(Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AFCONUSCENTRAL,OU=Bases,$($Domain.DistinguishedName)" -SearchScope OneLevel).Name
                $bases+=$east=(Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AFCONUSEAST,OU=Bases,$($Domain.DistinguishedName)" -SearchScope OneLevel).Name
                $bases+=$west=(Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AFCONUSWEST,OU=Bases,$($Domain.DistinguishedName)" -SearchScope OneLevel).Name}

    ACC        {}
    AFMC       {}
    DEFAULT    {}
}

#First menu to allow reports or patching
do{Show-Starter}
until($continue -ne $null)
if(!($continue)){Exit} #If only running reports don't continue

#Check prereqs for advanced tools 
If(!(Get-Content $workingdir\list.txt)){"List of computers not found.";Pause;Exit}

#Pings the list of machines
"Pinging machines... please wait"
$Masterlist = Get-Content $workingdir\list.txt
$MasterList | Invoke-Ping -Quiet | Out-File "$resultspath\GoodPings.txt"
$list = Get-Content "$resultspath\GoodPings.txt"
$Masterlist | ?{$list -notcontains $_} | Out-File "$resultspath\BadPings.txt"

#Restarts the script until the user exits
do{
    Show-Menu

    #Install ALL Patches
    if($batch -eq "1"){
    Prompt-Restart
       If($list.count -lt 7){
	        If($restart -eq $true){
                ForEach ($Computer in $list){
                    PS-Update -Computer $Computer
                    Schedule-Restart -Computer $Computer}
            }
            Else{
                ForEach ($Computer in $list){
                    PS-Update -Computer $Computer}
            }
        }
       Else{
       #Runs the patch in multiple windows. The number at the end is the number of windows.
        If($restart -eq $true){RUN $updatesRps1 6}
        Else{Run $updatesps1 6}
        }
    }

    #Taskkill/Install Office Patches
    if($batch -eq "2"){
    Prompt-Restart
       If($list.count -lt 7){
            If($restart -eq $true){
	            ForEach ($Computer in $list){
                    PS-Office -Computer $Computer
                    Schedule-Restart -Computer $Computer}
            }
            Else{
                ForEach ($Computer in $list){
                    PS-Office -Computer $Computer}
            }
        }
       Else{
       #Runs the patch in multiple windows. The number at the end is the number of windows.
            If($restart -eq $true){RUN $officeRps1 6}
            Else{RUN $officeps1 6}
        }
    }

    #Install 3rd Party
    if($batch -eq "3"){
    Prompt-Restart
       If($list.count -lt 7){
            If($restart -eq $true){
                ForEach ($Computer in $list){
                    PS-3rdParty -Computer $Computer
                    Schedule-Restart}
            }
            Else{
                ForEach ($Computer in $list){
                    PS-3rdParty -Computer $Computer}
            }
        }
       Else{
       #Runs the patch in multiple windows. The number at the end is the number of windows.
            If($restart -eq $true){RUN $3rdpartyRps1 6}
            Else{RUN $3rdpartyps1 6}
        }
    }

    #Report Installed Patches
    If ($batch -eq "4"){
        Write-Host "Collecting Installed Patches... please wait"
        ForEach ($Computer in $list){
            Get-InstalledPatches $Computer
        }
    }

    #Report Installed Programs
    If($batch -eq "5"){
       Write-Host "Collecting Installed Programs... please wait"
       ForEach ($Computer in $list){
            Get-InstalledPrograms $Computer
       }
    }

    #Report OS and Disk Info
    If ($batch -eq "6"){
        Write-Host "Collecting Computer Information... please wait"
       ForEach ($Computer in $list){
            Get-ComputerInformation $Computer
       }
    }

    #(Re)Install McAfee Agent
    If ($batch -eq "7"){
    Prompt-Restart
       If($list.count -lt 7){
            If($restart -eq $true){
                ForEach ($Computer in $list){
                    PS-MCAgent -Computer $Computer
                    Schedule-Restart}
            }
            Else{
                ForEach ($Computer in $list){
                    PS-MCAgent -Computer $Computer}
            }
        }
       Else{
       #Runs the patch in multiple windows. The number at the end is the number of windows.
            If($restart -eq $true){RUN $3rdpartyRps1 6}
            Else{RUN $3rdpartyps1 6}
        }
    }

    #Adds a count of the good-pings list
    "$($list.count) Machines Patched"
}
until ($exit)

#Stop-Transcript