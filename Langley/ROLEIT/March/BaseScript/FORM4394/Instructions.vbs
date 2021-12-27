strComputer="."
strProcess="masqform.exe"
strProcess=UCase(strProcess)
Dim objWMIService, strWMIQuery				
strWMIQuery = "Select * from Win32_Process where name like '" & strProcess & "'"
	
Do while strProcessRunning="No"	

Set objWMIService = GetObject("winmgmts:" _
		& "{impersonationLevel=impersonate}!\\" _ 
		& strComputer & "\root\cimv2") 


		if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
			strProcessRunning="Yes"
		else
			strProcessRunning="No"
		end if

Loop


Const ForReading = 1
strcomputer = "."

Const adOpenStatic = 3
Const adLockOptimistic = 3

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set WshShell = WScript.CreateObject("WScript.Shell")
Set WshNetwork = WScript.CreateObject("WScript.Network")

StrServerPath = "\\area52.afnoapps.usaf.mil\March_AFB\Logon_Scripts\New\BaseScript\FORM4394"
StrInstructionsFile = StrServerPath & "\Instructions.txt"
StrInstructionsHdr = "User Consent Form Instructions:"

Set objTextFile = objFSO.OpenTextFile _
   (StrInstructionsFile, ForReading)

strInstructions = objTextFile.ReadAll
objTextFile.Close


'MSGBOX strInstructions,4096,StrInstructionsHdr

strInstructions = "<font color=red><b>" & strInstructions & "<b></font>"

with HTABox("lightgrey", 600, 400, 400, 500)
  .document.title = StrInstructionsHdr
  .msg.innerHTML = strInstructions
  Timeout = 3000 ' milliseconds
  do until .done.value or (strProcessRunning="No"): 

strWMIQuery = "Select * from Win32_Process where name like '" & strProcess & "'"
	
	Set objWMIService = GetObject("winmgmts:" _
		& "{impersonationLevel=impersonate}!\\" _ 
		& strComputer & "\root\cimv2") 


		if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
			strProcessRunning="Yes"
		else
			strProcessRunning="No"
		end if
MSGBOX strProcessRunning
   
loop
  .done.value = true
  .close
end with

' Author Tom Lavedas, June 2010
Function HTABox(sBgColor, h, w, l, t)
Dim IE, HTA

  randomize : nRnd = Int(1000000 * rnd)
  sCmd = "mshta.exe ""javascript:{new " _
       & "ActiveXObject(""InternetExplorer.Application"")" _
       & ".PutProperty('" & nRnd & "',window);" _
       & "window.resizeTo(" & w & "," & h & ");" _
       & "window.moveTo(" & l & "," & t & ")}"""

  with CreateObject("WScript.Shell")
    .Run sCmd, 1, False
    do until .AppActivate("javascript:{new ") : WSH.sleep 10 : loop
  end with ' WSHShell

  For Each IE In CreateObject("Shell.Application").windows
    If IsObject(IE.GetProperty(nRnd)) Then
      set HTABox = IE.GetProperty(nRnd)
      IE.Quit
      HTABox.document.title = "HTABox"
      HTABox.document.write _
               "<HTA:Application contextMenu=no border=thin " _
             & "minimizebutton=no maximizebutton=no sysmenu=no />" _
             & "<body scroll=no style='background-color:" _
             & sBgColor & ";font:normal 10pt Arial;" _
             & "border-Style:outset;border-Width:3px'" _
             & "onbeforeunload='vbscript:if not done.value then " _
             & "window.event.cancelBubble=true:" _
             & "window.event.returnValue=false:" _
             & "done.value=true:end if'>" _
             & "<input type=hidden id=done value=false>" _
             & "<center><span id=msg>&nbsp;</span><center></body>"
      Exit Function
    End If
  Next

' I can't imagine how this line can be reached, but just in case
  MsgBox "HTA window not found."
  wsh.quit

End Function
