$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            xcopy /y /e /i "C:\Working\PatcherNew\Patches\Agent" \\$computer\c$\PatcherNew\Patches\Agent
	        PsExec -accepteula \\$computer /s /f /c 'C:\Working\PatcherNew\Scripts\External\Agent.bat'
            LOG
}
