$array = @(
@{
Group = "36 ces"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 CES"
},
@{
Group = "36 wg"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 WG"
},
@{
Group = "36 wg"
Drive = "\\ajjy-fs-021v\Andersen\36 WG"
},
@{
Group = "44 aps"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\44 APS"
},
@{
Group = "36MUNS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MXG\36 MUNS (2)"
},
@{
Group = "36 MUNS"
Drive = "\\ajjy-fs-021v\Andersen\36 MXG\36 MUNS"
},
@{
Group = "36cs.scs"
Drive = "\\52ajjy-fs-002.area52.afnoapps.usaf.mil\VI-Media"
},
@{
Group = "36abw.pa"
Drive = "\\52ajjy-fs-002.area52.afnoapps.usaf.mil\VI-Media"
},
@{
Group = "TANKERS-ALL"
Drive = "\\52ajjy-fs-004\Tanker"
},
@{
Group = "734 AMS/ALL USERS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\734 AMS"
},
@{
Group = "734 AMS/ALL USERS"
Drive = "\\ajjy-fs-021v\Andersen\734 AMS"
},
@{
Group = "36mxs"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MXG\36 MXS"
},
@{
Group = "36mxs"
Drive = "\\ajjy-fs-021v\Andersen\36 MXG\36 MXS"
},
@{
Group = "36lrs"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 LRS"
},
@{
Group = "36lrs"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 LRS"
},
@{
Group = "36MXG"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MXG"
},
@{
Group = "36cons"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 CONS"
},
@{
Group = "36cons"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 CONS"
},
@{
Group = "36cons"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 CONS"
},
@{
Group = "36fm"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 WG\CPTS"
},
@{
Group = "36fm"
Drive = "\\ajjy-fs-021v\Andersen\36 WG\CPTS"
},
@{
Group = "36 msg"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 MSG"
},
@{
Group = "36 msg"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 MSG"
},
@{
Group = "36 OSS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 OG\36 OSS"
},
@{
Group = "36 OSS"
Drive = "\\ajjy-fs-021v\Andersen\36 OG\36 OSS"
},
@{
Group = "36mss"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 FSS"
},
@{
Group = "36mss"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 FSS"
},
@{
Group = "36 sfs"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 SFS"
},
@{
Group = "36 SFS"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 SFS"
},
@{
Group = "36 SVS"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 FSS"
},
@{
Group = "644 CBCS"
Drive = "\\ajjy-fs-021v\Andersen\36 CRG\644 CBCS"
},
@{
Group = "644 CBCS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 CRG\644 CBCS"
},
@{
Group = "36 MDG_CD_USERS"
Drive = "\\52ajjy-fs-900v\func_app"
},
@{
Group = "36med"
Drive = "\\52ajjy-fs-900v\medshare"
},
@{
Group = "fedlog"
Drive = "\\52ajjy-fs-001\fedlog"
},
@{
Group = "36 CS"
Drive = "\\ajjy-fs-021v\Andersen\36 MSG\36 CS"
},
@{
Group = "36 CS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MSG\36 CS"
},
@{
Group = "36 MRS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 CRG\36 MRS"
},
@{
Group = "36 MRS"
Drive = "\\ajjy-fs-021v\Andersen\36 CRG\36 MRS"
},
@{
Group = "736 SFS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 CRG\736 SFS"
},
@{
Group = "736 SFS"
Drive = "\\ajjy-fs-021v\Andersen\36 CRG\736 SFS"
},
@{
Group = "36 EAMXS"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\36 MXG\36 EAMXS"
},
@{
Group = "Andersen AFB All Admin"
Drive = "\\52ajjy-fs-001\Admin"
},
@{
Group = "624RSG_OL-A"
Drive = "\\ajjy-fs-022v\PACAF\Andersen\624 RSG OL-A"
}
)
Clear-Content "C:\temp\GroupList.txt"
#$text = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().memberOf | Out-File C:\temp\GroupList.txt -Append
$text = (New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().o | Out-File C:\temp\GroupList.txt -Append
$myshell = New-Object -com "Wscript.Shell"


for($i = 0; $i -lt $array.Count; $i++){
$textreader = Get-Content "C:\temp\GroupList.txt"| Select-String -Pattern $array[$i].Group | Select-Object -Index 0
    foreach($line in $textreader) {
        if($line -match $array[$i].Group){
		$myshell.sendkeys("{ENTER}")
            net use * $array[$i].Drive /p:no -
        }
    }
}
