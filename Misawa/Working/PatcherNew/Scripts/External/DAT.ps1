$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            xcopy /y /e /i "C:\Working\PatcherNew\Patches\DAT" \\$computer\c$\PatcherNew\Patches\DAT
	        PsExec -accepteula \\$computer /s /f /c 'C:\Working\PatcherNew\Scripts\External\DAT.bat'
            LOG
}