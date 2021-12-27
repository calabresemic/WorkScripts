$computers = $args[0..($args.count -1)]
$acctlst=Import-Csv C:\WindowsScan\Scripts\Accounts.csv
Foreach($computer in $computers)
{  
    # pings the computerand to determine if it's online
    If((Test-Connection -ComputerName $computer -Quiet -Count 1) -eq $true)
    {
        # retrieves ip address from any enabled network adapter
        Try{$IP = Get-WMIObject win32_NetworkAdapterConfiguration -ComputerName $computer -ErrorAction Stop | where {$_.dnsdomain -eq "AREA52.AFNOAPPS.USAF.MIL"} | Foreach-Object { $_.IPAddress }}
        Catch{$IP = "Unknown"}

        # retrieves the last user to log in to the system and checks AD for identity
        Try{$username = Get-ChildItem "\\$computer\c$\Users" | Sort-Object LastWriteTime -Descending -ErrorAction Stop | Select-Object -First 1 | Select Name, LastWriteTime
            $displayname = (Get-ADUser -Identity $username.name -ErrorAction Stop).name}
        Catch{$displayname = "Unknown"}

        # retrieves the manufacturer of the computer
        Try{$pcMake = (Get-WmiObject -Class:Win32_ComputerSystem -ComputerName $computer -ErrorAction Stop).Manufacturer}
        Catch{$pcMake = "Unknown"}

        # retrieves the model of the computer
        Try{$pcModel = (Get-WmiObject -Class:Win32_ComputerSystem -ComputerName $computer -ErrorAction Stop).Model}
        Catch{$pcModel = "Unknown"}

        # retrieves the serial number of the computer
        Try{$serial = (Get-WmiObject -Class:Win32_BIOS -ComputerName $computer -ErrorAction Stop).SerialNumber}
        Catch{$serial = "Unknown"}

        # matches the serial number to ADPE account numbers
        $account=$acctlst | Where-Object {$_.SerialNumber -eq $Serial}
        [string]$accountnum=$account.acct

        # retrieves the OS architechture
        Try{$osarch = (Get-WmiObject -Class:Win32_OperatingSystem -ComputerName $computer -ErrorAction Stop).OSArchitecture}
        Catch{$osarch = "Unknown"}

        # checks the clone tag
        $reg=$null,$key=$null,$CloneTag=$null,$ct=$null
            Try{$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$computer)
                $key = $reg.OpenSubKey('SYSTEM\Setup')
                $CloneTag = $key.GetValue('CloneTag')}
            Catch{}
        Switch ($CloneTag){
            "Fri Jul 22 20:46:22 2016" {
                $ct = $false
            }            
            "Wed Mar 23 18:20:12 2016" {
                $ct = $false
            } 
            "Sat Mar 25 19:04:44 2017" {
                $ct = $false
            }
            "Fri Jul 28 17:36:46 2017" {
                $ct = $false
            }
            $null {
                $ct = "Unknown"
            }
            default {
                $ct = $true
            }
        }
        # retrieves the last restart time and calculates uptime
        Try{$reboot = (Get-WmiObject -Class:Win32_OperatingSystem -ComputerName $computer -ErrorAction Stop)
            $uptime = ((get-date) - $reboot.ConvertToDateTime($reboot.LastBootUpTime))
            $uptimeres = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) mins"}
        Catch{$uptimeres = "Unknown"}
        
        # gets SDC Version
        $OSV=$null
        Try{$OSV = (Get-WmiObject -Class Win32_OperatingSystem -computername $computer -ErrorAction Stop).Version}
        Catch{}
         Switch ($OSV){
            "10.0.10240"{
                $OSV = "5.1"  
            }
            "10.0.10586"{
                $OSV = "5.2"
            }
            "10.0.14393"{
                $OSV ="5.3.x"
            }
            "6.1.7601"{
                $OSV = "3.x"
            }
            $null {
                $OSV="Unknown"
            }
            default{
                $OSV = "Not SDC"
            }
        }

        # gets OS name
        Try{$OS = (Get-WmiObject -Class Win32_OperatingSystem -computername $computer -ErrorAction Stop).Caption}
        Catch{$OS="Unknown"}

        # checks AD for information on the computer    
        $ou = "OU=Andersen AFB Computers,OU=Andersen AFB,OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
        $result=Get-ADComputer -Filter {cn -eq $computer} -SearchBase $ou -Properties * | Select-Object o,LastLogonDate,location

            # what to do if it fails to pull info
            If($result.o -eq $null){
            $Unit = "Unknown"}
            Else{$Unit = $result.o}

            If($result.LastLogonDate -eq $null){
            $Date="Unknown"}
            Else{$Date=$result.LastLogonDate}

            If($result.location -eq $null){
            $location = "Unknown"}
            Else{$location = $result.location -replace "; ORGANIZATION.*",""}

      # organizes the information to output to csv
      $line = [Ordered] @{"Computer Name"="$Computer";IP="$IP";"Account Number"="$accountnum";Unit="$Unit";Building="$Location";Manufacturer="$PCMake";Model="$PCModel";Serial="$Serial";"Operating System"="$OS";"OS Architecture"="$osarch";"OS Version"="$OSV";"Last User"="$Displayname";"Time of Login"="$Date";Uptime="$uptimeres";Clone="$ct"}
    }

    Else{ # the machine fails to reply to ping

        # also checks AD for information on the computer    
        $ou = "OU=Andersen AFB Computers,OU=Andersen AFB,OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
        $result=Get-ADComputer -Filter {cn -eq $computer} -SearchBase $ou -Properties * | Select-Object o,location,operatingsystem,operatingsystemversion

            # what to do if it fails to pull info
            If($result.o -eq $null){
            $Unit = "Unknown"}
            Else{$Unit = $result.o}

            If($result.LastLogonDate -eq $null){
            $Date="Unknown"}
            Else{$Date=$result.LastLogonDate}

            If($result.location -eq $null){
            $location = "Unknown"}
            Else{$location = $result.location -replace "; ORGANIZATION.*",""}

            If($result.operatingsystem -eq $null){
            $OS = "Unknown"}
            Else{$OS = $result.operatingSystem}

            If($result.operatingsystemversion -eq $null){
            $OSV = "Unknown"}
            Else{$OSV = $result.operatingSystemVersion}

       Switch ($OSV){
            "10.0 (10240)"{
                $OSV = "5.1"  
            }
            "10.0 (10586)"{
                $OSV = "5.2"
            }
            "10.0 (14393)"{
                $OSV ="5.3.x"
            }
            "6.1 (7601)"{
                $OSV = "3.x"
            }
            default{
                $OSV = "Not SDC"
            }
        }

    # organizes the information to output to csv
    $line = [Ordered] @{"Computer Name"="$computer";IP="Offline";"Account Number"="unknown";Unit="$Unit";Building="$Location";Manufacturer="$null";Model="$null";Serial="$null";"Operating System"="$OS";"OS Architecture"="$null";"OS Version"="$OSV";"Last User"="$null";"Time of Login"="$null";Uptime="$null";Clone="$null"}
    }

    # exports to csv includes failover for multiple processes writing to the csv at the same time
    $export = New-Object -TypeName psobject -Property $line
do{
    $done = $true
    Try{
    $export | Export-csv -NoTypeInformation -Append C:\WindowsScan\temp\ComputerInformation.csv
    }
    Catch{
    $done = $false
    Start-Sleep -Milliseconds $(Get-Random -Minimum 100 -Maximum 1000)
    }
   }Until($done)

}