on error resume next
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'                              PACAF Logon Script
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Authors: Chase Hayase, SrA John Gill                                                                                   
' Version Date: 7 Oct 2009
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Change Log:
'	Name			Date		Change Made
'	Dodd, Alexander		10OCT12		Launch IE and navigate to Andersen SharePoint Home Page
'	Torres, Ignacio		10OCT12	    Added code to create desktop icon on users desktop
'	Dodd, Alexander		29NOV12		Modified Andersen Sharepoint URL in both IE Auto-Launch and WaterCooler.LNK creation
'	Dodd, Alexander		22FEB13		Added additional desktop icon creation code for CUI Prep site for IG
'	Dodd, Alexander		28FEB13		Corrected icon for CUI Prep link
'	Dodd, Alexander		29MAY13		Added code to remove CUI Prep link and commented the link creation code
'	Dodd, Alexander		06JUN13		Added a call for PaperBoy.ps1 to change desktop backgrounds on systems deemed out of compliance (see WallpaperList.txt)
'	Dodd, Alexander		28Aug13		Changed URL of Andersen InfoPage and WaterCooler Link
'   Savage, Matthew     08Oct13     Changed URL of Andersen InfoPage and WaterCooler Link  
'	Dodd, Alexander		18Oct13		Commented PaperBoy.ps1 pointer(s)
'	Dodd, Alexander		18Oct13		UN-Commented PaperBoy.ps1 pointer(s)
'	Savage, Matthew		15Nov13		Changed URL of Andersen InfoPage and WaterCooler Link
'	Dodd, Alexander		19NOV13		Commented paperboy.ps1 code and removed all applicable files from folder
'	Nguyen,Julian		10SEP14		Changed URL of Andersen InfoPage and WaterCooler Link
'	Carsner, Alexander	08JAN16		Changed URL of Andersen InfoPage and WaterCooler Link
'	Carsner, Alexander	11JAN16		Added trigger for AAFB_ALL_USER_LOGON.ps1 script
'	Carsner, Alexander	05FEB16		Changed trigger for AAFB_ALL_USER_LOGON.ps1 script.
'	Cruz, Michael		12DEC16		Watercooler desktop shortcut removed per PA, Updated popup to show main page instead
'	Cruz, Michael		19JAN17		Updated 36WG shortcut to point to WG sharepoint
'	Cruz, Michael		19JAN17		Added code to remove old 36WG.lnk
'	Ada, Raymond		02MAR17		Added code to run MDG login script & cleaned up old code.
'   Ada, Raymond        04SEP18     Cleaned up old code; removed logging, AAFB_ALL_USER_LOGON, and old functions.
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'Set Script variables
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

DIM StrCopyLoc, fso, oShell

Set oShell = CreateObject( "WScript.Shell" )
Set fso = CreateObject("Scripting.FileSystemObject")
Set oPower = CreateObject("Shell.Application") 
Set adSys = CreateObject("AdSystemInfo")
Set xDoc = CreateObject("Microsoft.XMLDOM")

Const ForAppending = 8

StrRunPath = "\\area52.afnoapps.usaf.mil\andersen_afb\Logon_Scripts\" 
StrCopyTo = oShell.ExpandEnvironmentStrings("%public%") & "\"
StrUserDomain = ucase(adSys.username)
StrCompDomain = ucase(adSys.DomainShortName)
StrLogonLog = StrCopyTo & "logonlog.txt"


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Creates log on Public folder
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

'IF fso.fileExists(StrLogonLog) THEN
'	Set objFile = fso.GetFile(StrLogonLog)
'	IF objFile.Size > 512000 THEN
'		fso.DeleteFile(StrLogonLog)
'		Set oLogonLog = fso.CreateTextFile(StrLogonLog)
'	ELSE
'		Set oLogonLog = fso.OpenTextFile(StrLogonLog,ForAppending)
'	END IF
'ELSE
'	Set oLogonLog = fso.CreateTextFile(StrLogonLog)
'END IF	

'oLogonLog.WriteLine("***Starting Logon Script Log File***")
'oLogonLog.WriteLine("Started On: " & Date & "," & Time & vbCrlf)


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Creates 36WG.lnk on current users desktop on logon
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Set SysInfo = CreateObject("WScript.Network" )
Set WScriptShell = WScript.CreateObject("WScript.Shell")

strshortcut = WScriptShell.SpecialFolders("Desktop") & "\36 Wing SharePoint.lnk" 

'No IF statement here will FORCE updates

	SET oUrlLink = WScriptShell.CreateShortcut(strshortcut)
	oUrlLink.TargetPath = "https://andersen.eis.pacaf.af.mil/Pages/default.aspx"

	oUrlLink.IconLocation = "\\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\36WG.ico"
	oUrlLink.Save 

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'If the user account is not from the same domain as the computer account exit script
'This is for NOSC admins logging into child sites.
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

IF StrCompDomain = "PACAF" Then
	StrCompDomain = "NOSC"
END IF

StrCompDomain = "DC=" & StrCompDomain

IF instr(StrUserDomain,StrCompDomain) = 0 THEN
	'oLogonLog.WriteLine("***User domain doesn't equal computer domain. Exiting script.***")
	wscript.quit
END IF

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'Login Database
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'oShell.run("powershell.exe -noexit -command ""Unblock-File -Path \\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\AutoReporting\DBUpdater.ps1;robocopy \\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\AutoReporting\ C:\Temp\AutoReporting /XO"""),0,false
'oshell.run("C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -noexit -command ""C:\temp\AutoReporting\DBUpdate.ps1"" "),0,false

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'Drive Mappings
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
oshell.run("powershell.exe -noexit -windowstyle hidden -command ""Unblock-File -Path \\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\Mapper\Drive_Mapper.ps1;robocopy \\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\Mapper\ C:\Temp\ /XO"""),0,false
WScript.Sleep 5000
oshell.run("powershell.exe -noexit -windowstyle hidden -command ""C:\temp\Drive_Mapper.ps1"" "),0,false


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'Call MDG script prompt for all users in 36MDG.All Users
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
Set ts = fso.OpenTextFile("\\52ajjy-hc-001v\LogonScripts\36_mdg\MDG_DMHRSi_prompt.vbs")
body = ts.ReadAll
Execute body
ts=nothing
'oLogonLog.WriteLine("Ran MDG DMHRSi script")

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Call Team Andersen Notification Popup
' modify the message.txt file with the message text
' remove the apostrophe from each line below to make the commands run 
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'dim fso, file, content, checkr
'checkr = "\\52ajjy-hc-001v\LogonScripts\message.txt"
'set fso = CreateObject("Scripting.FileSystemObject")
    'IF fso.fileExists(checkr) THEN
        'IF fso.GetFile(checkr).size <> 0 then
            'set file = fso.OpenTextFile(checkr, 1)
            'content = file.ReadAll
            'file.close
            'MsgBox content, vbInformation or vbOKOnly, "Team Andersen Notification Message" 
        'END IF
    'END IF

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Call Team Andersen Notification Popup (Picture Version)
' modify the message.JPG under .\NOTAM\ to the desired slide/picture/etc
' remove the apostrophe from each line below to make the commands run 
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'dim slide
'slide = "\\52ajjy-hc-001v\LogonScripts\NOTAM\message.hta"
'CreateObject("WScript.Shell").Run slide, 1, True
