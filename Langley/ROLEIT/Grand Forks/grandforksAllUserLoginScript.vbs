' FileName:   GrandForksAllUserLoginScript.vbs
' Usage:       for login by all Grand Forks AFB to Area52 domain
'edited 2/28/2012 by A1C Joshua Alldredge: Added Audit Logon
'edited 8/11/2014 by A1C Jacob Ware : Added Excel PII config file placer
'edited 7/30/2015 by SSgt Stephen Cherry: Changed Admin/CSA paths to 132.10.1.35
'edited 7/6/2017  by A1C Justin Nguyen: Changed Water Cooler to Event Calendar
'edited 9/17/2018 by SrA Delgado William: Changed SAN to JFSL-FS-002V, replacing 132.10.1.35
'edited 1/10/2020 by SrA Kyle Gates: Removed old "S" Drives
'edited 7/02/2020 by SrA Gates. Changed drives names to reflect bases transition to 319 RW
'edited 2/5/2021 by Mr. Craig Danula: Changed login splash page to Coronavirus info page per PA request

'----------------------------------------------------------------------------------------
' Variable declaration/definition
'----------------------------------------------------------------------------------------
'Option Explicit

On Error Resume Next

Dim blnIsMember		'Boolean for group membership TRUE/FALSE
Dim objSysInfo		'Returns AD System Information
Dim objUser		'Sets user object variable
Dim objUser2		'Sets user object variable
Dim objWSH
Dim objShell		'Creates Windows Shell Object
Dim objFSO		'Creates Windows File System Object
Dim objNet
Dim objNetwork
Dim objGroup
Dim strUserDN		'Variable to hold user Distinguished Name
Dim strUserID
Dim strUserCN		'String representing users CN
Dim strDomain
Dim strGroupName
Dim strLetter
Dim strUNC
Dim strIP		'IP of PC
Dim strOSVer		'PC OS Version
Dim strOSCaption	'PC OS Caption (Friendly Name)
Dim strFilename1	'Sets file path for Computer Logon
Dim strFilename2	'Sets file path for User Logon

'----------------------------------------------------------------------------------------
' Collect user account information
'----------------------------------------------------------------------------------------
Set objSysInfo = CreateObject("ADSystemInfo")
strUserDN = objSysInfo.UserName
strUserDN = Replace(strUserDN, "/", "\/")
Set objUser = GetObject("LDAP://" & strUserDN)
strUserCN = objUser.cn

' Initialize system objects
set objWSH = createobject("WScript.shell")
set objFSO = createobject("Scripting.FileSystemObject")
Set objNetwork = CreateObject("WScript.Network")

If IsMemberOf ("GF JFSD Server Shop") Then
	MapDrive "H:", "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
	MapDrive "L:", "\\jfsl-fs-001v\servershop"
	mapdrive "S:","\\jfsl-fs-01pv\GrandForks_319_RW_S"
	MapDrive "T:", "\\jfsl-fs-001v\servershop\servershop\software"
	MapDrive "W:", "\\jfsl-fs-001v\servershop\csa"

' Creates Tier 0.lnk on current user's desktop on logon
Set SysInfo = CreateObject("WScript.Network" )
Set WScriptShell = WScript.CreateObject("WScript.Shell")
strshortcut = WScriptShell.SpecialFolders("Desktop") & "\Tier 0.lnk"
SET oUrlLink = WScriptShell.CreateShortcut(strshortcut)
oUrlLink.TargetPath = "https://eim.amc.af.mil/org/319arw/Tier0/default.aspx"
oUrlLink.IconLocation = "https://eim.amc.af.mil/org/319arw/Tier0/Picture%20Library/Stock%20Photos/tier0_icon_red.ico"
oUrlLink.Save

End IF

If IsMemberOf ("gls_grand forks_CFP-CSA") Then
	MapDrive "H:", "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
	mapdrive "S:","\\jfsl-fs-01pv\GrandForks_319_RW_S"
	MapDrive "W:", "\\jfsl-fs-001v\serversop\csa"
End IF

If IsMemberOf ("319 CS_SCOI") Then
   	MapDrive "L:", "\\jfsl-fs-001v\SCOI$"
	MapDrive "W:", "\\jfsl-fs-001v\servershop\CSA"
End IF

If IsMemberOf ("GF CS CSA") Then
	MapDrive "H:", "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
	MapDrive "W:", "\\jfsl-fs-001v\servershop\CSA"
End IF

If IsMemberOf ("GF CSA ALL") Then
   	MapDrive "W:", "\\jfsl-fs-001v\servershop\CSA"
End IF

' Run CA Removale 
Set objShell = WScript.CreateObject("WScript.Shell")
cmd = "\\jfsl-fs-01pv\319-msg-g\319-CS\SCO\Software\CA_Removal\FBCA_crosscert_remover_v108.exe /SILENT"
Set objExecObject = objShell.Exec(cmd)

cmd1 = "REG DELETE HKCU\Software\Microsoft\SystemCertificates\CA\Certificates /f "
Set objExecObject = objShell.Exec(cmd1)

'Place Excel PII configuration file in users' APPDATA folder
Set oShell = CreateObject("Wscript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strUserProfile = oShell.ExpandEnvironmentStrings("%USERPROFILE%")

objFSO.Copyfile "c:\ExcelPII\a.crc", strUserProfile & "\AppData\Roaming\Microsoft\AddIns\a.crc", TRUE

If IsMemberOf ("Domain Users") Then
' Launch IE and navigate to Base Home Page
Set objIE = CreateObject("InternetExplorer.Application")
objIE.Visible = 0
objIE.Height = 800
objIE.Width = 1000
objIE.Left = 0
objIE.Top = 15
objIE.Navigate  "https://www.grandforks.af.mil/Coronavirus/"

'Launch CHES PPT
'CreateObject("WScript.Shell").Run("""\\jfsl-HC-001v\Logon_Scripts\Slide\CHES.ppsx""")

' Creates WaterCooler.lnk on current user's desktop on logon
Set SysInfo = CreateObject("WScript.Network" )
Set WScriptShell = WScript.CreateObject("WScript.Shell")
strshortcut = WScriptShell.SpecialFolders("Desktop") & "\Events-Calendar.lnk"
SET oUrlLink = WScriptShell.CreateShortcut(strshortcut)
oUrlLink.TargetPath = "http://www.grandforks.af.mil/Home/Events-Calendar"
oUrlLink.IconLocation = "\\jfsdns20vdm1\319-arw-g$\PA\WaterCoolerSlides\Sven.ico"
oUrlLink.Save

End If

'----------------------------------------------------------------------------------------
' Collect system information
'----------------------------------------------------------------------------------------

strComputer = "." 
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2") 

'----------------------------------------------------------------------------------------
' Audit Logon (Logs Computer and User logons)
'----------------------------------------------------------------------------------------
'PC Name

	Set wshNetwork = WScript.CreateObject( "WScript.Network" )
	strComputerName = wshNetwork.ComputerName

'Username

	Set wshNetwork = WScript.CreateObject( "WScript.Network" )
	strUser = wshNetwork.UserName

'IP Address

	strComputer = "."
	Set objWMIService = GetObject( _ 
	    "winmgmts:\\" & strComputer & "\root\cimv2")
	Set IPConfigSet = objWMIService.ExecQuery _
	    ("Select IPAddress from Win32_NetworkAdapterConfiguration ")
 
	For Each IPConfig in IPConfigSet
	    If Not IsNull(IPConfig.IPAddress) Then 
	        For i=LBound(IPConfig.IPAddress) _
 	           to UBound(IPConfig.IPAddress)
 	               strIP = IPConfig.IPAddress(i)
 	       Next
  	  End If
	Next

'MAC Address

	intCount = 0
	strMAC   = ""
	' We're interested in MAC addresses of physical adapters only
	strQuery = "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID > ''"

	Set objWMIService = GetObject( "winmgmts://./root/CIMV2" )
	Set colItems      = objWMIService.ExecQuery( strQuery, "WQL", 48 )

	For Each objItem In colItems
	    If InStr( strMAC, objItem.MACAddress ) = 0 Then
	        strMAC   = strMAC & "," & objItem.MACAddress
	        intCount = intCount + 1
	    End If
	Next

	' Remove leading comma
	If intCount > 0 Then strMAC = Mid( strMAC, 2 )

	Select Case intCount
	    Case 0
	       strMACAddress = "No MAC Addresses were found"
	    Case 1
 	       strMACAddress = strMAC
 	   Case Else
 	       strMACAddress = strMAC
	End Select

'Version of Windows

	strComputer = "."
	Set objWMIService = GetObject("winmgmts:" _
	    & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")

	Set colOperatingSystems = objWMIService.ExecQuery _
	    ("Select * from Win32_OperatingSystem")

	For Each objOperatingSystem in colOperatingSystems
	    strOSCaption = objOperatingSystem.Caption
	    strOSVer = objOperatingSystem.Version
	Next

'----Save Log files----

Dim objFolder, objTextFile, objFile
Dim strDirectory, strFile, strText, strNewText, strNewFile, strUsersDirectory, strUsersFile, strNewUsersFile
strDirectory = "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
strFile = "\Computers\" & strComputerName & ".csv"
strUsersFile = "\Users\" & strUser & "-" & strUserCN & ".csv"
strNewText = "Date,Time,Username,Display Name,Computer Name,OS Name,OS Version,MAC Address,IP Address"
strText = Date & "," & Time & "," & strUser & "," & strUserCN & "," & strComputerName & "," & strOSCaption & "," & strOSVer & "," & strMACAddress & "," & strIP

' Create the File System Object
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Check that the strDirectory folder exists
If objFSO.FolderExists(strDirectory) Then
   Set objFolder = objFSO.GetFolder(strDirectory)
Else
   Set objFolder = objFSO.CreateFolder(strDirectory)
End If

'Check that the strFile file exists
If objFSO.FileExists(strDirectory & strFile) Then
   Set objFolder = objFSO.GetFolder(strDirectory)
Else
   Set objFile = objFSO.CreateTextFile(strDirectory & strFile)
   strNewFile = 1
End If

'Check that the strUsersFile file exists
If objFSO.FileExists(strDirectory & strUsersFile) Then
   Set objFolder = objFSO.GetFolder(strDirectory)
Else
   Set objFile = objFSO.CreateTextFile(strDirectory & strUsersFile)
   strNewUsersFile = 1
End If

set objFile = nothing
set objFolder = nothing
' OpenTextFile Method needs a Const value
' ForAppending = 8 ForReading = 1, ForWriting = 2
Const ForAppending = 8

'Write the Computer Audit log
Set objTextFile = objFSO.OpenTextFile (strDirectory & strFile, ForAppending, True)

If strNewFile = 1 Then
  objTextFile.WriteLine(strNewText)
  objTextFile.WriteLine(strText)
  objTextFile.Close
  strNewFile = ""
Else
  objTextFile.WriteLine(strText)
  objTextFile.Close
End if

'Write the User Audit log
Set objTextFile = objFSO.OpenTextFile (strDirectory & strUsersFile, ForAppending, True)

If strNewUsersFile = 1 Then
  objTextFile.WriteLine(strNewText)
  objTextFile.WriteLine(strText)
  objTextFile.Close
  strNewFile = ""
Else
  objTextFile.WriteLine(strText)
  objTextFile.Close
End if

'----------------------------------------------------------------------------------------
' End of Audit Logon (Logs Computer and User logons)
'----------------------------------------------------------------------------------------

' quit script
Cleanup
WScript.quit 0

'--------------------------------------------
' SUBROUTINES & FUNCTIONS
'--------------------------------------------

sub Cleanup()
' release memory
	set blnIsMember	  = Nothing
	set strUserID     = Nothing
	set strDomain     = Nothing
	set strGroupName  = Nothing
	set strLetter     = Nothing
	set strUNC        = Nothing
	set intWSHVersion = Nothing
        set objWSH        = Nothing
        set objFSO        = Nothing
        set objNet        = Nothing
        set objNetwork    = Nothing
        set objUser       = Nothing
        set objUser2      = Nothing
        set objGroup      = Nothing
end sub

Sub MapDrive(strLetter, strUNC)
  Set objNet = WScript.CreateObject("WScript.Network")
  
  If objFSO.DriveExists(strLetter) Then
    objNet.RemoveNetworkDrive strLetter, True, True
    objNet.MapNetworkDrive strLetter, strUNC
  Else
    objNet.MapNetworkDrive strLetter, strUNC
  End If
End Sub

Function IsMemberOf(strGroupName)
  Set objNetwork = CreateObject("WScript.Network")
  strDomain = objNetwork.UserDomain
  strUserID = objNetwork.UserName
  blnIsMember = False
  Set objUser2 = GetObject("WinNT://" & strDomain & "/" & strUserID & ",user")
  For Each objGroup In objUser2.Groups
    If LCase(objGroup.Name) = LCase(strGroupName) Then
      blnIsMember = True
      Exit For
    End If
  Next
  IsMemberOf = blnIsMember
End Function