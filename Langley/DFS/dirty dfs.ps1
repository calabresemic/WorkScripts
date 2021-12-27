Function Get-DFSV2Target ($DFS_Share) {
    $xml = [xml][System.Text.Encoding]::Unicode.GetString($($DFS_Share.'msdfs-targetlistv2')[2..($($DFS_Share.'msdfs-targetlistv2').Length-1)])
    return ($xml.targets.ChildNodes.'#text').foreach{$_.split('\')[2]}
}

function Parse-Pkt {
    [CmdletBinding()]
    Param([Byte[]]$Pkt)

    $bin = $Pkt
    $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
    $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
    $offset = 8
    #https://msdn.microsoft.com/en-us/library/cc227147.aspx
    $object_list = @()
    for($i=1; $i -le $blob_element_count; $i++){
        $blob_name_size_start = $offset
        $blob_name_size_end = $offset + 1
        $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

        $blob_name_start = $blob_name_size_end + 1
        $blob_name_end = $blob_name_start + $blob_name_size - 1
        $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

        $blob_data_size_start = $blob_name_end + 1
        $blob_data_size_end = $blob_data_size_start + 3
        $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

        $blob_data_start = $blob_data_size_end + 1
        $blob_data_end = $blob_data_start + $blob_data_size - 1
        $blob_data = $bin[$blob_data_start..$blob_data_end]
        switch -wildcard ($blob_name) {
            "\siteroot" {  }
            "\domainroot*" {
                # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                # DFSRootOrLinkIDBlob
                $root_or_link_guid_start = 0
                $root_or_link_guid_end = 15
                $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                $guid = New-Object Guid(,$root_or_link_guid) # should match $guid_str
                $prefix_size_start = $root_or_link_guid_end + 1
                $prefix_size_end = $prefix_size_start + 1
                $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                $prefix_start = $prefix_size_end + 1
                $prefix_end = $prefix_start + $prefix_size - 1
                $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])

                $short_prefix_size_start = $prefix_end + 1
                $short_prefix_size_end = $short_prefix_size_start + 1
                $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                $short_prefix_start = $short_prefix_size_end + 1
                $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])

                $type_start = $short_prefix_end + 1
                $type_end = $type_start + 3
                $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)

                $state_start = $type_end + 1
                $state_end = $state_start + 3
                $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)

                $comment_size_start = $state_end + 1
                $comment_size_end = $comment_size_start + 1
                $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                $comment_start = $comment_size_end + 1
                $comment_end = $comment_start + $comment_size - 1
                if ($comment_size -gt 0)  {
                    $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                }
                $prefix_timestamp_start = $comment_end + 1
                $prefix_timestamp_end = $prefix_timestamp_start + 7
                # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                $state_timestamp_start = $prefix_timestamp_end + 1
                $state_timestamp_end = $state_timestamp_start + 7
                $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                $comment_timestamp_start = $state_timestamp_end + 1
                $comment_timestamp_end = $comment_timestamp_start + 7
                $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                $version_start = $comment_timestamp_end  + 1
                $version_end = $version_start + 3
                $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                # Parse rest of DFSNamespaceRootOrLinkBlob here
                $dfs_targetlist_blob_size_start = $version_end + 1
                $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                $reserved_blob_size_end = $reserved_blob_size_start + 3
                $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)

                $reserved_blob_start = $reserved_blob_size_end + 1
                $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                $referral_ttl_start = $reserved_blob_end + 1
                $referral_ttl_end = $referral_ttl_start + 3
                $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                #Parse DFSTargetListBlob
                $target_count_start = 0
                $target_count_end = $target_count_start + 3
                $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                $t_offset = $target_count_end + 1

                for($j=1; $j -le $target_count; $j++){
                    $target_entry_size_start = $t_offset
                    $target_entry_size_end = $target_entry_size_start + 3
                    $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                    $target_time_stamp_start = $target_entry_size_end + 1
                    $target_time_stamp_end = $target_time_stamp_start + 7
                    # FILETIME again or special if priority rank and priority class 0
                    $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                    $target_state_start = $target_time_stamp_end + 1
                    $target_state_end = $target_state_start + 3
                    $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)

                    $target_type_start = $target_state_end + 1
                    $target_type_end = $target_type_start + 3
                    $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)

                    $server_name_size_start = $target_type_end + 1
                    $server_name_size_end = $server_name_size_start + 1
                    $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)

                    $server_name_start = $server_name_size_end + 1
                    $server_name_end = $server_name_start + $server_name_size - 1
                    $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                    $share_name_size_start = $server_name_end + 1
                    $share_name_size_end = $share_name_size_start + 1
                    $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                    $share_name_start = $share_name_size_end + 1
                    $share_name_end = $share_name_start + $share_name_size - 1
                    $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                    $target_list += "\\$server_name\$share_name"
                    $t_offset = $share_name_end + 1
                }
            }
        }
        $offset = $blob_data_end + 1
        $dfs_pkt_properties = @{
            'Name' = $blob_name
            'Prefix' = $prefix
            'TargetList' = $target_list
        }
        $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
        $prefix = $Null
        $blob_name = $Null
        $target_list = $Null
    }
    return $object_list | where {$_.Name -ne "\siteroot"}
}

$results=@()
$namespaces=get-adobject -searchbase "CN=Dfs-Configuration,CN=System,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -filter { (objectclass -eq "msdfs-namespacev2") -or (objectclass -eq "ftdfs") } -Properties remoteServerName,pkt,'msdfs-targetlistv2'
#$namespaces=get-adobject -searchbase "CN=Dfs-Configuration,CN=System,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL" -filter {objectclass -eq "ftdfs"} -Properties remoteServerName,pkt
foreach ($namespace in $namespaces) {
    Remove-Variable childObjects,object,link,rootTargets,startupTargets,logonTargets,dfsv -ErrorAction SilentlyContinue

    if ($namespace.ObjectClass -eq "msdfs-namespacev2") {
        $childObjects= Get-ChildItem "AD:\$($namespace.DistinguishedName)"
        $rootTargets=Get-DFSV2Target $namespace
        $DFSV='DFSv2'

        foreach ($object in $childObjects) {
            $link=Get-ADObject $object -Properties *
            Switch($Link.'msDFS-LinkPathv2') {
                '/Startup_Scripts'    {$startupTargets=Get-DFSV2Target $link}
                '/Logon_Scripts'    {$logonTargets=Get-DFSV2Target $link}
                }
            }
    } else {
        $DFSV='DFSv1'
        $PKT=$namespace.pkt
        $untangledblob=Parse-Pkt $PKT
        $rootTargets=((($untangledblob | where {$_.Name -eq '\domainroot'}).targetlist) -split "\\\\" | where {$_ -ne ''}).foreach{$_.split('\')[0]}
        $startupTargets=((($untangledblob | where {$_.prefix -like '*\Startup_Scripts'}).targetlist) -split "\\\\" | where {$_ -ne ''}).foreach{$_.split('\')[0]}
        $logonTargets=((($untangledblob | where {$_.prefix -like '*\Logon_Scripts'}).targetlist) -split "\\\\" | where {$_ -ne ''}).foreach{$_.split('\')[0]}
    }

    $result=[pscustomobject]@{Namespace=$namespace.Name;Root=$($rootTargets -join "`n");LogonShare=$($logonTargets -join "`n");StartupShare=$($startupTargets -join "`n");DFSVersion=$DFSV}
    $result
    $results+=$result
}
$results | Export-Csv 'C:\Users\1468714589A\OneDrive - United States Air Force\Desktop\Scripts\DFS\results.csv' -NoTypeInformation