$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
$folders = (dir -Path C:\Working\PatcherNew\Patches\3rdParty).Name
foreach($computer in $computers)
{
            xcopy /y /e /i C:\Working\PatcherNew\Patches\3rdParty \\$computer\c$\PatcherNew\Patches\3rdParty
                    ForEach($folder in $folders){
                        If((Test-Path C:\Working\PatcherNew\Patches\3rdParty\$folder\runthis.bat) -eq $True){PsExec /s \\$computer C:\PatcherNew\Patches\3rdParty\$folder\runthis.bat}
                        Else {PsExec -accepteula /s \\$computer C:\PatcherNew\Patches\3rdParty\$folder\install.cmd}
                        LOG
                        Remove-Item -Recurse -Force \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
                        Restart
                    }
}
