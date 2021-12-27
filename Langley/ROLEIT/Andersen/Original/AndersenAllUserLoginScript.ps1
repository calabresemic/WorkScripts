$ErrorActionPreference = "silentlycontinue"
########################################################################################
#                              PACAF Logon Script
########################################################################################
# Authors: Chase Hayase, SrA John Gill                                                                                   
# Version Date: 7 Oct 2009
########################################################################################
# Change Log:
#	Name			Date		Change Made
#	Dodd, Alexander		10OCT12		Launch IE and navigate to Andersen SharePoint Home Page
#	Torres, Ignacio		10OCT12	    Added code to create desktop icon on users desktop
#	Dodd, Alexander		29NOV12		Modified Andersen Sharepoint URL in both IE Auto-Launch and WaterCooler.LNK creation
#	Dodd, Alexander		22FEB13		Added additional desktop icon creation code for CUI Prep site for IG
#	Dodd, Alexander		28FEB13		Corrected icon for CUI Prep link
#	Dodd, Alexander		29MAY13		Added code to remove CUI Prep link and commented the link creation code
#	Dodd, Alexander		06JUN13		Added a call for PaperBoy.ps1 to change desktop backgrounds on systems deemed out of compliance (see WallpaperList.txt)
#	Dodd, Alexander		28Aug13		Changed URL of Andersen InfoPage and WaterCooler Link
#   Savage, Matthew     08Oct13     Changed URL of Andersen InfoPage and WaterCooler Link  
#	Dodd, Alexander		18Oct13		Commented PaperBoy.ps1 pointer(s)
#	Dodd, Alexander		18Oct13		UN-Commented PaperBoy.ps1 pointer(s)
#	Savage, Matthew		15Nov13		Changed URL of Andersen InfoPage and WaterCooler Link
#	Dodd, Alexander		19NOV13		Commented paperboy.ps1 code and removed all applicable files from folder
#	Nguyen,Julian		10SEP14		Changed URL of Andersen InfoPage and WaterCooler Link
#	Carsner, Alexander	08JAN16		Changed URL of Andersen InfoPage and WaterCooler Link
#	Carsner, Alexander	11JAN16		Added trigger for AAFB_ALL_USER_LOGON.ps1 script
#	Carsner, Alexander	05FEB16		Changed trigger for AAFB_ALL_USER_LOGON.ps1 script.
#	Cruz, Michael		12DEC16		Watercooler desktop shortcut removed per PA, Updated popup to show main page instead
#	Cruz, Michael		19JAN17		Updated 36WG shortcut to point to WG sharepoint
#	Cruz, Michael		19JAN17		Added code to remove old 36WG.lnk
#	Ada, Raymond		02MAR17		Added code to run MDG login script & cleaned up old code.
#   Ada, Raymond        04SEP18     Cleaned up old code; removed logging, AAFB_ALL_USER_LOGON, and old functions.
########################################################################################

########################################################################################
# Creates 36WG.lnk on current users desktop on logon
########################################################################################

$WshShell = New-Object -comObject WScript.Shell
#$Shortcut = $WshShell.CreateShortcut($env:USERPROFILE + "\desktop\36 Wing SharePoint.lnk" )
$Shortcut = $WshShell.CreateShortcut("C:\Users\1258341585A\OneDrive - United States Air Force\Desktop\36 Wing SharePoint.lnk" )
$Shortcut.TargetPath = "https://andersen.eis.pacaf.af.mil/Pages/default.aspx"
$shortcut.IconLocation = "\\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\36WG.ico"
$shortcut.WindowStyle = 1;
$Shortcut.Save()

########################################################################################
#If the user account is not from the same domain as the computer account exit script
#This is for NOSC admins logging into child sites.
########################################################################################


#####################################################################################
#Drive Mappings
#####################################################################################
start-process powershell.exe -argumentlist "-noexit -windowstyle hidden -command ""Unblock-File -Path \\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\Mapper\Drive_Mapper.ps1;robocopy \\52ajjy-hc-001v\Andersen_AFB\Logon_Scripts\Mapper\ C:\Temp\ /XO""" -NoNewWindow | out-null
start-sleep -Seconds 10
start-process powershell.exe -argumentlist "-noexit -windowstyle hidden -command ""C:\temp\Drive_Mapper.ps1"""

#####################################################################################
#Call MDG script prompt for all users in 36MDG.All Users
#####################################################################################

$user = (get-aduser -identity 1258341585a -Properties *).memberof

if($user -match '36MDG.All Users'){

}ELSE{

}


#####################################################################################
# Call Team Andersen Notification Popup
# modify the message.txt file with the message text
# remove the apostrophe from each line below to make the commands run 
#####################################################################################
#dim fso, file, content, checkr
#checkr = "\\52ajjy-hc-001v\LogonScripts\message.txt"
#set fso = CreateObject("Scripting.FileSystemObject")
    #IF fso.fileExists(checkr) THEN
        #IF fso.GetFile(checkr).size <> 0 then
            #set file = fso.OpenTextFile(checkr, 1)
            #content = file.ReadAll
            #file.close
            #MsgBox content, vbInformation or vbOKOnly, "Team Andersen Notification Message" 
        #END IF
    #END IF

#####################################################################################
# Call Team Andersen Notification Popup (Picture Version)
# modify the message.JPG under .\NOTAM\ to the desired slide/picture/etc
# remove the apostrophe from each line below to make the commands run 
#####################################################################################
#dim slide
#slide = "\\52ajjy-hc-001v\LogonScripts\NOTAM\message.hta"
#CreateObject("WScript.Shell").Run slide, 1, True
