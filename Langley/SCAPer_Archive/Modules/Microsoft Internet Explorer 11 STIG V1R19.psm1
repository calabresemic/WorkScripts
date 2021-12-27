<#
Module Created by Michael Calabrese (1468714589)
Designed to be used with SCAPer script v5+

Microsoft Internet Explorer 11 Security Technical Implementation Guide :: Version 1, Release: 19 Benchmark Date: 24 Jul 2020
#>

#V-46473
#Turn off Encryption Support must be enabled.
Function SV-59337r8_rule {
    #TLS 1.1 and 1.2 only
    #SSL 2.0 - 8
    #SSL 3.0 - 32
    #TLS 1.0 - 128
    #TLS 1.1 - 512
    #TLS 1.2 - 2048
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\" "SecureProtocols" "SilentlyContinue"
    if ($Value -eq "2560") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46475
#The Internet Explorer warning about certificate address mismatch must be enforced.
Function SV-59339r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Turn on certificate address mismatch warning : Enabled
    $ValueName = "WarnOnBadCertRecving"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46477
#Check for publishers certificate revocation must be enforced.
Function SV-59341r4_rule {
    #NA if SIPR
    if ($Global:IsNIPR) {
        $ValueName = "State"
        $Value = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "146432") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            } #0x23C00
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-46481
#The Download signed ActiveX controls property must be disallowed (Internet zone).
Function SV-59345r1_rule {
    $ValueName = "1001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46483
#The Download unsigned ActiveX controls property must be disallowed (Internet zone).
Function SV-59347r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #Download unsigned ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box
    $ValueName = "1004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46501
#The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone).
Function SV-59365r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Initialize and script ActiveX controls not marked as safe' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46505
#Font downloads must be disallowed (Internet zone).
Function SV-59369r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow font downloads' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "1604"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46507
#The Java permissions must be disallowed (Internet zone).
Function SV-59371r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46509
#Accessing data sources across domains must be disallowed (Internet zone).
Function SV-59373r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #"Access data sources across domains" will be set to "Enabled" and "Disable"
    $ValueName = "1406"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46511
#Functionality to drag and drop or copy and paste files must be disallowed (Internet zone).
Function SV-59375r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1802"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46513
#Launching programs and files in IFRAME must be disallowed (Internet zone).
Function SV-59377r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1804"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46515
#Navigating windows and frames across different domains must be disallowed (Internet zone).
Function SV-59379r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Navigate windows and frames across different domains' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "1607"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46517
#Userdata persistence must be disallowed (Internet zone).
Function SV-59381r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1606"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        } 
    }

#V-46521
#Clipboard operations via script must be disallowed (Internet zone).
Function SV-59385r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1407"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46523
#Logon options must be configured to prompt (Internet zone).
Function SV-59387r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #"Logon options" to "Enabled", and select "Prompt for user name and password" from the drop-down box. 
    $ValueName = "1A00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 65536) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46525
#Java permissions must be configured with High Safety (Intranet zone).
Function SV-59389r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Intranet Zone
    #"Java permissions" will be set to “Enabled” and "High Safety".
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 65536) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46543
#Java permissions must be configured with High Safety (Trusted Sites zone).
Function SV-59407r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Trusted Sites Zone
    #"Java permissions" will be set to “Enabled” and "High Safety".
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 65536) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46545
#Dragging of content from different domains within a window must be disallowed (Internet zone).
Function SV-59409r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone
    #'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box. 
    $ValueName = "2708"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46547
#Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).
Function SV-59411r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone
    #'Enable dragging of content from different domains across windows' to 'Enabled', and select 'Disabled' from the drop-down box.
    $ValueName = "2709"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46549
#Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer).
Function SV-59413r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
    #“Internet Explorer Processes” must be “Enabled”. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 1) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46553
#Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore).
Function SV-59417r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
    #“Internet Explorer Processes” must be “Enabled”. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 1) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46555
#Dragging of content from different domains within a window must be disallowed (Restricted Sites zone).
Function SV-59419r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone
    #'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box. 
    $ValueName = "2708"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46573
#The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).
Function SV-59437r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Download signed ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46575
#The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone).
Function SV-59439r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #"Download unsigned ActiveX controls" to "Enabled", and select "Disable" from the drop-down box.
    $ValueName = "1004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46577
#The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone).
Function SV-59441r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Initialize and script ActiveX controls not marked as safe' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46579
#ActiveX controls and plug-ins must be disallowed (Restricted Sites zone).
Function SV-59443r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Run ActiveX controls and plugins' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1200"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46581
#ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone).
Function SV-59445r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Script ActiveX controls marked safe for scripting' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1405"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46583
#File downloads must be disallowed (Restricted Sites zone).
Function SV-59447r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1803"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46585
#Font downloads must be disallowed (Restricted Sites zone).
Function SV-59449r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow font downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1604"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else {return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}}
    }

#V-46587
#Java permissions must be disallowed (Restricted Sites zone).
Function SV-59451r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46589
#Accessing data sources across domains must be disallowed (Restricted Sites zone).
Function SV-59453r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Access data sources across domains' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1406"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46591
#The Allow META REFRESH property must be disallowed (Restricted Sites zone).
Function SV-59455r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow META REFRESH' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1608"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46593
#Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone).
Function SV-59457r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1802"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46597
#Launching programs and files in IFRAME must be disallowed (Restricted Sites zone).
Function SV-59461r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1804"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46599
#Navigating windows and frames across different domains must be disallowed (Restricted Sites zone).
Function SV-59463r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Navigate windows and frames across different domains' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1607"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46601
#Userdata persistence must be disallowed (Restricted Sites zone).
Function SV-59465r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box 
    $ValueName = "1606"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46603
#Active scripting must be disallowed (Restricted Sites Zone).
Function SV-59467r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow active scripting' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1400"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46605
#Clipboard operations via script must be disallowed (Restricted Sites zone).
Function SV-59469r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1407"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46607
#Logon options must be configured and enforced (Restricted Sites zone).
Function SV-59471r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Logon options' to 'Enabled', and select 'Anonymous logon' from the drop-down box. 
    $ValueName = "1A00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "196608") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46609
#Configuring History setting must be set to 40 days.
Function SV-59473r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History
    #'Disable Configuring History' to 'Enabled', and enter '40' in 'Days to keep pages in History'. 
    $ValueName1 = "History"
    $Value1 = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Control Panel" -Name $ValueName1 | select -ExpandProperty $ValueName1
    $ValueName2 = "DaysToKeep"
    $Value2 = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" -Name $ValueName2 | select -ExpandProperty $ValueName2
    if ($Value1 -eq "1" -and $Value2 -eq "40") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46615
#Internet Explorer must be set to disallow users to add/delete sites.
Function SV-59479r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components
    #Internet Explorer "Security Zones: Do not allow users to add/delete sites" to "Enabled". 
    $ValueName = "Security_zones_map_edit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName -EA SilentlyContinue | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46617
#Internet Explorer must be configured to disallow users to change policies.
Function SV-59481r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components
    #Internet Explorer 'Security Zones: Do not allow users to change policies' to 'Enabled'. 
    $ValueName = "Security_options_edit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName -EA SilentlyContinue | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46619
#Internet Explorer must be configured to use machine settings.
Function SV-59483r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components
    #Internet Explorer 'Security Zones: Use only machine settings' to 'Enabled'. 
    $ValueName = "Security_HKLM_only"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46621
#Security checking features must be enforced.
Function SV-59485r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #'Turn off the Security Settings Check feature' to 'Disabled'.
    $ValueName = "DisableSecuritySettingsCheck"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Security" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46625
#Software must be disallowed to run or install with invalid signatures.
Function SV-59489r2_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
    #'Allow software to run or install even if the signature is invalid' to 'Disabled'. 
    $ValueName = "RunInvalidSignatures"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Download" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46629
#Checking for server certificate revocation must be enforced.
Function SV-59493r2_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
    #'Check for server certificate revocation' to 'Enabled'. 
    $ValueName = "CertificateRevocation"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46633
#Checking for signatures on downloaded programs must be enforced.
Function SV-59497r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
    #'Check for signatures on downloaded programs' to 'Enabled'. 
    $ValueName = "CheckExeSignatures"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Download" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "yes") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46635
#All network paths (UNCs) for Intranet sites must be disallowed.
Function SV-59499r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #'Intranet Sites: Include all network paths (UNCs)' to 'Disabled'. 
    $ValueName = "UNCAsIntranet"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46637
#Script-initiated windows without size or position constraints must be disallowed (Internet zone).
Function SV-59501r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2102"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46639
#Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone).
Function SV-59503r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2102"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46641
#Scriptlets must be disallowed (Internet zone).
Function SV-59505r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1209"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46643
#Automatic prompting for file downloads must be disallowed (Internet zone).
Function SV-59507r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Automatic prompting for file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2200"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46645
#Java permissions must be disallowed (Local Machine zone).
Function SV-59509r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Local Machine Zone
    #"Java permissions" to "Enabled", and "Disable Java" selected from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46647
#Java permissions must be disallowed (Locked Down Local Machine zone).
Function SV-59511r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Local Machine Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46649
#Java permissions must be disallowed (Locked Down Intranet zone).
Function SV-59513r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Intranet Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46653
#Java permissions must be disallowed (Locked Down Trusted Sites zone).
Function SV-59517r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Trusted Sites Zone
    #"Java permissions" to "Enabled", and select "Disable Java" from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46663
#Java permissions must be disallowed (Locked Down Restricted Sites zone).
Function SV-59527r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46665
#XAML files must be disallowed (Internet zone).
Function SV-59529r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2402"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46669
#XAML files must be disallowed (Restricted Sites zone).
Function SV-59533r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2402"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}}
    }

#V-46681
#Protected Mode must be enforced (Internet zone).
Function SV-59545r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "2500"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46685
#Protected Mode must be enforced (Restricted Sites zone).
Function SV-59549r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "2500"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46689
#Pop-up Blocker must be enforced (Internet zone).
Function SV-59553r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "1809"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46691
#Pop-up Blocker must be enforced (Restricted Sites zone).
Function SV-59555r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "1809"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
                
    }

#V-46693
#Websites in less privileged web content zones must be prevented from navigating into the Internet zone.
Function SV-59557r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2101"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46695
#Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone.
Function SV-59559r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2101"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46701
#Allow binary and script behaviors must be disallowed (Restricted Sites zone).
Function SV-59565r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #"Allow binary and script behaviors" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "2000"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46705
#Automatic prompting for file downloads must be disallowed (Restricted Sites zone).
Function SV-59569r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Automatic prompting for file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2200"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46709
#Internet Explorer Processes for MIME handling must be enforced. (Reserved)
Function SV-59573r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46711
#Internet Explorer Processes for MIME handling must be enforced (Explorer).
Function SV-59575r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46713
#Internet Explorer Processes for MIME handling must be enforced (iexplore).
Function SV-59577r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46715
#Internet Explorer Processes for MIME sniffing must be enforced (Reserved).
Function SV-59579r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46717
#Internet Explorer Processes for MIME sniffing must be enforced (Explorer).
Function SV-59581r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46719
#Internet Explorer Processes for MIME sniffing must be enforced (iexplore).
Function SV-59583r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46721
#Internet Explorer Processes for MK protocol must be enforced (Reserved).
Function SV-59585r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
    #"Internet Explorer Processes" to "Enabled". 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46723
#Internet Explorer Processes for MK protocol must be enforced (Explorer).
Function SV-59587r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
    #"Internet Explorer Processes" to "Enabled". 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46725
#Internet Explorer Processes for MK protocol must be enforced (iexplore).
Function SV-59589r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
    #"Internet Explorer Processes" to "Enabled". 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46727
#Internet Explorer Processes for Zone Elevation must be enforced (Reserved).
Function SV-59591r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46729
#Internet Explorer Processes for Zone Elevation must be enforced (Explorer).
Function SV-59593r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46731
#Internet Explorer Processes for Zone Elevation must be enforced (iexplore).
Function SV-59595r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46733
#Internet Explorer Processes for Restrict File Download must be enforced (Reserved).
Function SV-59597r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download
    #'Internet Explorer Processes' to 'Enabled'.
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46779
#Internet Explorer Processes for Restrict File Download must be enforced (Explorer).
Function SV-59645r1_rule {
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46781
#Internet Explorer Processes for Restrict File Download must be enforced (iexplore).
Function SV-59647r1_rule {
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46787
#Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved).
Function SV-59653r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46789
#Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer).
Function SV-59655r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46791
#Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore).
Function SV-59657r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46797
#.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone).
Function SV-59663r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if($Value -eq "3"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46799
#.NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone).
Function SV-59665r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "2001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46801
#Scripting of Java applets must be disallowed (Restricted Sites zone).
Function SV-59667r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #"Scripting of Java applets" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "1402"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46807
#AutoComplete feature for forms must be disallowed.
Function SV-59673r1_rule {
    #User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #'Disable AutoComplete for forms' to 'Enabled'. 
    $ValueName = "Use FormSuggest"
    $Value = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "no") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46811
#Crash Detection management must be enforced.
Function SV-59677r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #'Turn off Crash Detection' to 'Enabled'.
    $ValueName = "NoCrashDetection"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46815
#Turn on the auto-complete feature for user names and passwords on forms must be disabled.
Function SV-59681r1_rule {
    #User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #"Turn on the auto-complete feature for user names and passwords on forms" to "Disabled". 
    $ValueName1 = "FormSuggest Passwords"
    $Value1 = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName1 | select -ExpandProperty $ValueName1
    $ValueName2 = "FormSuggest PW Ask"
    $Value2 = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName2 | select -ExpandProperty $ValueName2
    if ($Value1 -eq "no" -and $Value2 -eq "no") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46819
#Managing SmartScreen Filter use must be enforced.
Function SV-59685r3_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #"Prevent Managing SmartScreen Filter" to "Enabled", and select "On" from the drop-down box. 
    if (!$Global:IsNIPR) {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    $ValueName = "EnabledV9"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46829
#Browser must retain history on exit.
Function SV-59695r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History
    #“Configure Delete Browsing History on exit” to “Disabled”.
    $ValueName = "ClearBrowsingHistoryOnExit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46841
#Deleting websites that the user has visited must be disallowed.
Function SV-59707r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History"
    #Prevent Deleting Web sites that the User has Visited" to "Enabled". 
    $ValueName = "CleanHistory"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46847
#InPrivate Browsing must be disallowed.
Function SV-59713r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Privacy
    #'Turn off InPrivate Browsing' to 'Enabled'
    $ValueName = "EnableInPrivateBrowsing"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46849
#Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone).
Function SV-59715r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1206"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46853
#When uploading files to a server, the local directory path must be excluded (Internet zone).
Function SV-59719r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #"Include local path when user is uploading files to a server" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "160A"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46857
#Internet Explorer Processes for Notification Bars must be enforced (Reserved).
Function SV-59723r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46859
#Security Warning for unsafe files must be set to prompt (Internet zone).
Function SV-59725r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Show security warning for potentially unsafe files' to 'Enabled', and select 'Prompt' from the drop-down box. 
    $ValueName = "1806"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46861
#Internet Explorer Processes for Notification Bars must be enforced (Explorer).
Function SV-59727r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
    #'Internet Explorer Processes' to 'Enabled'.
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46865
#ActiveX controls without prompt property must be used in approved domains only (Internet zone).
Function SV-59729r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "120b"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46869
#Internet Explorer Processes for Notification Bars must be enforced (iexplore).
Function SV-59735r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
    #'Internet Explorer Processes' to 'Enabled'.  
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46879
#Cross-Site Scripting Filter must be enforced (Internet zone).
Function SV-59745r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box.  
    $ValueName = "1409"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46883
#Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone).
Function SV-59749r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1206"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46885
#When uploading files to a server, the local directory path must be excluded (Restricted Sites zone).
Function SV-59751r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Include local path when user is uploading files to a server' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "160A"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46889
#Security Warning for unsafe files must be disallowed (Restricted Sites zone).
Function SV-59755r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Show security warning for potentially unsafe files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1806"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46893
#ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone).
Function SV-59759r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "120b"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46895
#Cross-Site Scripting Filter property must be enforced (Restricted Sites zone).
Function SV-59761r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "1409"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46897
#Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved).
Function SV-59763r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46903
#Status bar updates via script must be disallowed (Internet zone).
Function SV-59769r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Internet Zone 'Allow updates to status bar via script' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2103"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46907
#.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).
Function SV-59773r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Internet Zone 'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46921
#.NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone).
Function SV-59787r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Internet Zone 'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46927
#Scriptlets must be disallowed (Restricted Sites zone).
Function SV-59793r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Restricted Sites Zone 'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1209"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46939
#Status bar updates via script must be disallowed (Restricted Sites zone).
Function SV-59805r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Restricted Sites Zone "Allow updates to status bar via script" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "2103"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46975
#When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode.
Function SV-59841r2_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 
    #'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' to 'Enabled'. 
    $ValueName = "DisableEPMCompat"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46981
#Dragging of content from different domains across windows must be disallowed (Internet zone).
Function SV-59847r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone 
    #"Enable dragging of content from different domains across windows" to "Enabled", and select "Disabled". 
    $ValueName = "2709"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46987
#Enhanced Protected Mode functionality must be enforced.
Function SV-59853r3_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page
    #"Turn on Enhanced Protected Mode" to "Enabled". 
    $ValueName = "Isolation"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "PMEM") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46995
#The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on.
Function SV-59861r2_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Advanced Page 
    #'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' to 'Enabled'. 
    $ValueName = "Isolation64Bit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46997
#Anti-Malware programs against ActiveX controls must be run for the Internet zone.
Function SV-59863r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Internet Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46999
#Anti-Malware programs against ActiveX controls must be run for the Intranet zone.
Function SV-59865r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Intranet Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-47003
#Anti-Malware programs against ActiveX controls must be run for the Local Machine zone.
Function SV-59869r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Local Machine Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-47005
#Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone.
Function SV-59871r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-47009
#Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone.
Function SV-59875r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64711
#Prevent bypassing SmartScreen Filter warnings must be enabled.
Function SV-79201r2_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #”Prevent bypassing SmartScreen Filter warnings” to ”Enabled”. 
    if($Global:IsNIPR -eq $false){return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else{
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -regValueName "PreventOverride"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-64713
#Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled.
Function SV-79203r2_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #”Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet” to ”Enabled”. 
    if($Global:IsNIPR -eq $false){return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else{
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -regValueName "PreventOverrideAppRepUnknown"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-64715
#Prevent per-user installation of ActiveX controls must be enabled.
Function SV-79205r1_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #”Prevent per-user installation of ActiveX controls” to ”Enabled”. 
    $ValueName = "BlockNonAdminActiveXInstall"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64717
#Prevent ignoring certificate errors option must be enabled.
Function SV-79207r2_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel
    #”Prevent ignoring certificate errors” to ”Enabled”. 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -regValueName "PreventIgnoreCertErrors"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64719
#Turn on SmartScreen Filter scan option for the Internet Zone must be enabled.
Function SV-79209r1_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone
    #”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box. 
    $ValueName = "2301"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64721
#Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled.
Function SV-79211r1_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
    #”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box. 
    $ValueName = "2301"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64723
#The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone).
Function SV-79213r1_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
    #”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box. 
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64725
#The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone).
Function SV-79215r1_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
    #”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box. 
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-64729
#Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled.
Function SV-79219r3_rule {
    #Computer Configuration >> Administrative Templates >> Internet Explorer >> Security Features
    #"Allow fallback to SSL 3.0 (Internet Explorer)" to "Enabled", and select "No Sites" from the drop-down box. 
    $ValueName = "SecureProtocols"
    $Value = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "2688") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }
#V-72757
#Run once selection for running outdated ActiveX controls must be disabled.
Function SV-87395r2_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management
    #"Remove the Run this time button for outdated ActiveX controls in IE" to "Enabled". 
    $ValueName = "RunThisTimeEnabled"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-72759
#Enabling outdated ActiveX controls for Internet Explorer must be blocked.
Function SV-87397r2_rule {
    #(User Configuration? >>) Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management
    #"Turn off blocking of outdated ActiveX controls for IE" to "Disabled". 
    $ValueName = "VersionCheckEnabled"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-72761
#Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone.
Function SV-87399r2_rule {
    #Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
    #"Allow only approved domains to use the TDC ActiveX control" to "Enabled". 
    if($Global:OS -eq "Microsoft Windows Server 2016 Standard"){
        $ValueName = "120c"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-72763
#Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone.
Function SV-87401r2_rule {
    #Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
    #"Allow only approved domains to use the TDC ActiveX control" to "Enabled". 
    if($Global:OS -eq "Microsoft Windows Server 2016 Standard"){
        $ValueName = "120c"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-75169
#VBScript must not be allowed to run in Internet Explorer (Internet zone).
Function SV-89849r1_rule { #Only applies to Win 10 Redstone 2 and higher.  I assume we are.
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone
    #"Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box. 
    if($Global:OS -eq "Microsoft Windows 10 Enterprise"){
        $ValueName = "140C"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-75171
#VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone).
Function SV-89851r1_rule { #Only applies to Win 10 Redstone 2 and higher.  I assume we are.
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
    #"Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box. 
    if($Global:OS -eq "Microsoft Windows 10 Enterprise"){
        $ValueName = "140C"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-97527
#Internet Explorer Development Tools Must Be Disabled.
Function SV-106631r1_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Toolbars
    #“Turn off Developer Tools” must be “Enabled”.
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools" -regValueName "Disabled" -EA SilentlyContinue
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }