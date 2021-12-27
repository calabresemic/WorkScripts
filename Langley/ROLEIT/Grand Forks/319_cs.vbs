' FileName:    319_cs.vbs
' Usage:       for login by all 319 CS Grand Forks users to Area52 domain
'edited by SrA Turner, 17 June 2013. Added O drive conditional mapping and supporting function, variables
' edited by SrA Cherry. Adjusted pathnames to represent new SAN Server Shares.
'edited 7/30/2015 by SSgt Stephen Cherry: Changed Admin/CSA paths to 132.10.1.35
'edited 17 Sept 2018 by SSgt Hardy and Mr. Allen Cross, modified share drive path for G drive
'edited by SrA Gates. Changed drives names to reflect bases transition to 319 RW 02Jul2020

' declare variables
dim strLetter, strUNC
dim objWSH, objFSO, objNet
Dim blnIsMember		'Boolean for group membership TRUE/FALSE
Dim objSysInfo		'Returns AD System Information
Dim objUser		'Sets user object variable
Dim objUser2		'Sets user object variable
Dim objShell		'Creates Windows Shell Object
Dim objNetwork
Dim objGroup
Dim strUserDN		'Variable to hold user Distinguished Name
Dim strUserID
Dim strUserCN		'String representing users CN
Dim strDomain
Dim strGroupName

' Initialize system objects
set objWSH = createobject("WScript.shell")
set objFSO = createobject("Scripting.FileSystemObject")
set oShell = Wscript.CreateObject("Wscript.Shell")

' ***Global Printer Drive Mappings***
'MapDrive "P:", "\\52jfsl-ps-101\Printers"
MapDrive "P:", "\\jfsl-qs-001v\printers"

'***Squadron network drives                 

mapdrive "G:","\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS"
mapdrive "S:","\\jfsl-fs-01pv\GrandForks_319_RW_S"


' Creates Tier 0.lnk on current user's desktop on logon
Set SysInfo = CreateObject("WScript.Network" )
Set WScriptShell = WScript.CreateObject("WScript.Shell")
strshortcut = WScriptShell.SpecialFolders("Desktop") & "\Tier 0.lnk"
SET oUrlLink = WScriptShell.CreateShortcut(strshortcut)
oUrlLink.TargetPath = "https://eim.amc.af.mil/org/319arw/Tier0/default.aspx"
oUrlLink.IconLocation = "https://eim.amc.af.mil/org/319arw/Tier0/Picture%20Library/Stock%20Photos/tier0_icon_red.ico"
oUrlLink.Save

x=msgbox("- Never leave Common Access Cards (CACs) or SIPR tokens unattended" &vbnewline& "- Know your Cybersecurity Liason (CSL) & Unit Security Managers" &vbnewline& "- Know your Network Incident Procedures" &vbnewline& "- Report violations/incidents to unit CSLs and/or Security Managers" &vbnewline& "- Never connect unapproved USB devices to government systems" &vbnewline& "- Log out & restart NIPR machines daily" &vbnewline& "- Connect SIPR workstations every Tuesday & Thursday from 0900-1600" &vbnewline& "- Follow weekly Cyber Monday emails" &vbnewline& "- Keep work areas/facilities clean & organized: Clean Desk policy" &vbnewline& "- Digitally sign all e-mails w/attachments or hyperlinks" &vbnewline& "- Encrypt e-mails containing FOUO/PII data" ,64, "CCRI Information")

'Record Management
If IsMemberOfLike ("jfsd-fp-offrec") Then
	MapDrive "O:","\\jfsl-fs-02pv\GrandForks_ACC_OFF_REC\ERM Server"
End IF

'***MCS network drives     
mapMCS

'***GPO-UPDATE***

'Refresh the USER policies and also answer no to logoff if asked.
Result = objWSH.Run("cmd /c echo n | gpupdate /target:user /force",0,true)

'Refresh the Computer policies and answer no to reboot. 
Result = objWSH.Run("cmd /c echo n | gpupdate /target:computer /force",0,true)


' quit script
Cleanup
WScript.quit 0


'--------------------------------------------
' SUBROUTINES & FUNCTIONS
'--------------------------------------------

sub Cleanup()
' release memory
	set objWSH        = Nothing
        set objFSO        = Nothing
        set objNet        = Nothing
end sub


Sub MapDrive(strLetter, strUNC)
  Set objNet = CreateObject("WScript.Network")
  If objFSO.DriveExists(strLetter) Then
    objNet.RemoveNetworkDrive strLetter, True, True
    objNet.MapNetworkDrive strLetter, strUNC
  Else
    objNet.MapNetworkDrive strLetter, strUNC
  End If
End Sub

Sub MapMCS()
'This set of code will check and see if the user is part of MCS if they
  'are then it will map them to the Telecomm folder.

  domainstring = objNet.userdomain
  userstring = objNet.username
  set Userobj = GetObject("WinNT://" & domainstring & "/" & userstring)
 	For each GroupObject in Userobj.Groups

          if groupobject.name = "GLS_319 CS_SCOI-MCS" then 
		mapdrive "G:","\\jfsl-fs-01pv\319-MSG-G\319-CS\SCO\SCOI\Telecomm"
	  end if
	next

End Sub


Function IsMemberOfLike(strGroupName)
	Set objNetwork = CreateObject("WScript.Network")
	strDomain = objNetwork.UserDomain
	strUserID = objNetwork.UserName
	blnIsMember = False
	Set objUser2 = GetObject("WinNT://" & strDomain & "/" & strUserID & ",user")
	For Each objGroup In objUser2.Groups
		If instr(LCase(objGroup.Name),LCase(strGroupName)) then
			blnIsMember = True
			Exit For
		End If
	Next
	IsMemberOfLike = blnIsMember
End Function

Function IsMemberOfLike(strGroupName)
	Set objNetwork = CreateObject("WScript.Network")
	strDomain = objNetwork.UserDomain
	strUserID = objNetwork.UserName
	blnIsMember = False
	Set objUser2 = GetObject("WinNT://" & strDomain & "/" & strUserID & ",user")
	For Each objGroup In objUser2.Groups
		If instr(LCase(objGroup.Name),LCase(strGroupName)) then
			blnIsMember = True
			Exit For
		End If
	Next
	IsMemberOfLike = blnIsMember
End Function