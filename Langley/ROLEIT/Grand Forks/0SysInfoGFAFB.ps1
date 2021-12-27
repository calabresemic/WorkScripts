#ASHOKAS USER AND SYSTEM INFORMATIONS SCRIPT
Import-Module ActiveDirectory
$erroractionpreference = "silentlycontinue"
$env = gci env:
$sdc = (Get-ItemProperty -Path HKLM:\SOFTWARE\USAF\SDC\ImageRev -Name CurrentBuild).CurrentBuild
$sdc = $sdc.imagerevision
$usb = wmic diskdrive get PNPDeviceID
$com = Get-WMIObject Win32_ComputerSystem 
$computer = $com.name 
$model = (Get-wmiobject win32_computersystem).model
$man = (Get-wmiobject win32_computersystem).manufacturer
$count = 0
$NetAddapter = Get-WmiObject win32_networkadapterconfiguration | select-object *
foreach ($int in $NetAddapter) {
    $nics = 0
    if ($int.IpEnabled -like "True"){
        $nics++
        $mac =  $int.macaddress
        $ipv4 = ($int.ipaddress)[0]
        if ($nics -gt 1){
            $ipv4 = $ipv4 + ("," + $ipv4)
            $mac = $mac + ("," + $mac)            
        }
    }
}
$ip1 = $ip[1]
$ipv4 = get-netipaddress -AddressFamily IPv4 | where interfaceAlias -like Ethernet | select IPAddress 
$ipv42 = $ipv4.ipaddress
$log = Get-EventLog -logname system -instanceID 7001 -newest 1
$logon = $log.timewritten
$BIOS = gwmi Win32_BIOS -ComputerName $computer
$Serial = $BIOS.SerialNumber
$EDIPI = $env:username
$disks = gwmi Win32_LogicalDisk -ComputerName $computer
$monitors = gwmi WmiMonitorID -ComputerName $computer -Namespace root\wmi |
 Select @{n="Serial Number";e={[System.Text.Encoding]::ASCII.GetString($_.SerialNumberID -ne 00)}}  
$monitorsinfo = format-list -InputObject $monitors
   foreach ($item in $disks) {
    if ($item.DeviceID -eq "C:") {
    $C = $item.freespace/1GB   
    
   }
        }

<# $SysLog = (Get-EventLog -logname system -instanceID 1073748869 -Newest 3)
foreach ($item in $SysLog){
$item.message
    if ($item.message -like "*scan*"){
        $Date = ($item.timegenerated)
        $ScanDate = $date.ToString("MM/dd/yyyy HHMM")
        
        
    }
}
#>

$sysName2 = $Serial
$sysName = $Serial + " " + $env:COMPUTERNAME
try {$2 = get-aduser -Identity $EDIPI -properties displayName
        $3 = $2.displayName 
        }catch{$Global:User = "0"}

if ($3 -ne $null){
        $Global:User = "$3"
        }
$file = New-Item -path "\\132.10.1.22\ConnectToComply\Hit List Database\Workstations\$sysname.txt" -type file -force          
        add-content "Serial=$Serial" -path $file
        add-content "Computer Name=$computer" -path $file  
        add-content "Computer Model=$man $model" -path $file                           
        add-content "IP Address=$ipv42" -path $file
        add-content "MAC Address=$MAC" -path $file       
        add-content "SDC=$sdc" -path $file                  
        add-content "HD Space=$C" -path $file         
        add-content "User=$EDIPI;$User" -path $file   
        add-content "Last Logon=$logon" -path $file    
        ####################################################
    

If ("*$env:COMPUTERNAME*" -like "*RKMFL-L6461FNC*"){
$list = gci "\\132.10.1.22\ConnectToComply\Hit List Database\Workstations\"
$write = $list.lastwritetime 
$listname = $list.name
$date = get-date 
foreach($item in $list){$days = $date - $item.lastwritetime
$name = $item.name
If($days.days -gt 30){
Remove-Item "\\132.10.1.22\ConnectToComply\Hit List Database\Workstations\$name"}}}