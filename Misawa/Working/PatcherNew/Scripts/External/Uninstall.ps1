$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            PsExec -accepteula /s \\$computer wmic product where "name like '$program'" call uninstall
            LOG
}
