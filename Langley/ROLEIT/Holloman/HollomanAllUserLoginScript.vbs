' FileName:   BASEAllUserLoginScript.vbs
' Usage:       for login by all BASE AFB to Area52 domain

'----------------------------------------------------------------------------------------
' Variable declaration/definition
'----------------------------------------------------------------------------------------
Option Explicit

'On Error Resume Next


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
Dim intWSHVersion


'----------------------------------------------------------------------------------------
' Collect user account information
'----------------------------------------------------------------------------------------
Set objSysInfo = CreateObject("ADSystemInfo")
strUserDN = objSysInfo.UserName
strUserDN = Replace(strUserDN, "/", "\/")
Set objUser = GetObject("LDAP://" & strUserDN)
strUserCN = objUser.cn

' Initialize system objects
Set objShell = CreateObject("Wscript.Shell")
set objFSO = createobject("Scripting.FileSystemObject")
Set objNetwork = CreateObject("WScript.Network")

'on error resume next

'***Shared Drive Mappings For all Base Users***

'MapDrive "x:","\\xxxxxx\xxxxx"


'Is only need to restrict drive mapping
'If IsMemberOf("xxxxxx") Then		
    ' Mapdrive "X:","\\xxxxxxx\xxxxxx"	
'End If

'--------------------------------------------------------------------------------
' Print all user related messages and advertisments
'--------------------------------------------------------------------------------
'Dim objshell
'Set objShell = CreateObject("Wscript.Shell")
'objShell.Run "powerpnt /s ""\\kwrd-fs-03pv\Holloman_DFS\49 CS\Electronic Bulletin Board\Slides.pptx"""
objShell.Run "WScript ""\\area52.afnoapps.usaf.mil\holloman_afb\Logon_Scripts\Slides.vbs"""

'--------------------------------------------------------------------------------
' Records user logon
'--------------------------------------------------------------------------------
objShell.Run "WScript ""\\area52.afnoapps.usaf.mil\holloman_afb\Logon_Scripts\LogonRecord.vbs"""


'--------------------------------------------------------------------------------
' Run Base Inventory Functions
'--------------------------------------------------------------------------------
'objShell.Run "wscript ""\\area52.afnoapps.usaf.mil\holloman_afb\Logon_Scripts\49_cs\BaseInventory.vbs"""

'--------------------------------------------------------------------------------
' Run RSSD Client
'--------------------------------------------------------------------------------
'objShell.Run "wscript ""\\area52.afnoapps.usaf.mil\holloman_afb\Logon_Scripts\49_cs\USBFound.vbs"""


'MsgBox("END ALL USER SCRIPT")

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
  End If
    
    objNet.MapNetworkDrive strLetter, strUNC, True
  
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

'----------------------------------------
' GPUPDATE
'----------------------------------------

Set objShell = CreateObject("WScript.Shell")
objShell.Run "gpupdate /force", 0, True
'----------------------------------------------------------------------------------
'----------------------------------------
' MCAFEE UPDATE
'----------------------------------------

Set WshShellMU = WScript.Createobject("WScript.Shell")
WshShellMU.Run ("cmd /c CD C:\Program Files (x86)\McAfee\VirusScanEnterprise\ & mcupdate.exe /update /quiet"), 0, false 

