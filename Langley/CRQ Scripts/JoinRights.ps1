# Grant-ComputerJoinPermission.ps1
# Written by Bill Stewart (bstewart@iname.com)
#
# Grants an AD identity the ability to join one or more computers to the
# domain.

#requires -version 2

<#
.SYNOPSIS
Grants an AD identity permission to join one or more computers to a domain.

.DESCRIPTION
Grants an AD identity permission to join one or more computers to a domain. The identity is granted the following four permissions over each computer account:
  * Reset password
  * Validated write to DNS host name
  * Validated write to service principal name
  * Write account restrictions

.PARAMETER Identity
Identity of the account (user or group) to be granted join permission, in sAMAccountName format (e.g., 'KenDyer' or 'FABRIKAM\KenDyer'). Wildcards are not permitted.

.PARAMETER Name
Specifies one or more computer names. Wildcards are not permitted.

.PARAMETER Domain
Specifies the domain name where the computer(s) reside (e.g., 'FABRIKAM', 'fabrikam.com', or 'DC=fabrikam,DC=com').

.PARAMETER Server
Specifies a domain server where the AD permissions should be set.

.PARAMETER Credential
Specifies credentials that have permission to update the permissions of the computer account(s).

.INPUTS
Strings or objects with a Name property. AD computer objects can be used as inputs because they have a Name property.

.OUTPUTS
No output.

.EXAMPLE
PS C:\> Grant-ComputerJoinPermission KenDyer COMPUTER1
Grants the KenDyer account permission to join the computer COMPUTER1 to the domain.

.EXAMPLE
PS C:\> Grant-ComputerJoinPermission KenDyer COMPUTER1 -Credential (Get-Credential)
Grants the KenDyer account permission to join the computer COMPUTER1, but prompts for credentials to allow you to specify an account with sufficient authority to make the AD permission changes.

.EXAMPLE
PS C:\> Get-ADComputer -Filter { Name -like "COMPUTER?" } | Grant-ComputerJoinPermission FredDyer
Grants the FredDyer account permission to join the computers matching the wildcard pattern to the domain. This example shows how to use wildcards even though the -Name parameter doesn't support them.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [parameter(Position=0,Mandatory=$true)]
    [Security.Principal.NTAccount] $Identity,
  [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
  [alias("ComputerName")]
    [String[]] $Name,
    [String] $Domain,
    [String] $Server,
    [Management.Automation.PSCredential] $Credential
)

begin {
  # Validate if identity exists
  try {
    [Void] $identity.Translate([Security.Principal.SecurityIdentifier])
  }
  catch [Security.Principal.IdentityNotMappedException] {
    throw "Unable to identify identity - '$identity'"
  }

  # Create DirectorySearcher object
  $Searcher = [ADSISearcher] ""

  # Initializes DirectorySearcher object
  function Initialize-DirectorySearcher {
    [Void] $Searcher.PropertiesToLoad.Add("distinguishedName")
    if ( $Domain ) {
      if ( $Server ) {
        $path = "LDAP://$Server/$Domain"
      }
      else {
        $path = "LDAP://$Domain"
      }
    }
    else {
      if ( $Server ) {
        $path = "LDAP://$Server"
      }
      else {
        $path = ""
      }
    }
    if ( $Credential ) {
      $networkCredential = $Credential.GetNetworkCredential()
      $dirEntry = New-Object DirectoryServices.DirectoryEntry(
        $path,
        $networkCredential.UserName,
        $networkCredential.Password
      )
    }
    else {
      $dirEntry = [ADSI] $path
    }
    $Searcher.SearchRoot = $dirEntry
    $Searcher.Filter = "(objectClass=domain)"
    try {
      [Void] $Searcher.FindOne()
    }
    catch [Management.Automation.MethodInvocationException] {
      throw $_.Exception.InnerException
    }
  }

  Initialize-DirectorySearcher

  # AD rights GUIDs
  $AD_RIGHTS_GUID_RESET_PASSWORD      = "00299570-246D-11D0-A768-00AA006E0529"
  $AD_RIGHTS_GUID_VALIDATED_WRITE_DNS = "72E39547-7B18-11D1-ADEF-00C04FD8D5CD"
  $AD_RIGHTS_GUID_VALIDATED_WRITE_SPN = "F3A64788-5306-11D1-A9C5-0000F80367C1"
  $AD_RIGHTS_GUID_ACCT_RESTRICTIONS   = "4C164200-20C0-11D0-A768-00AA006E0529"

  # Searches for a computer object; if found, returns its DirectoryEntry
  function Get-ComputerDirectoryEntry {
    param(
      [String] $name
    )
    $Searcher.Filter = "(&(objectClass=computer)(name=$name))"
    try {
      $searchResult = $Searcher.FindOne()
      if ( $searchResult ) {
        $searchResult.GetDirectoryEntry()
      }
    }
    catch [Management.Automation.MethodInvocationException] {
      Write-Error -Exception $_.Exception.InnerException
    }
  }

  function Grant-ComputerJoinPermission {
    param(
      [String] $name
    )
    $domainName = $Searcher.SearchRoot.dc
    # Get computer DirectoryEntry
    $dirEntry = Get-ComputerDirectoryEntry $name
    if ( -not $dirEntry ) {
      Write-Error "Unable to find computer '$name' in domain '$domainName'" -Category ObjectNotFound
      return
    }
    if ( -not $PSCmdlet.ShouldProcess($name, "Allow '$identity' to join computer to domain '$domainName'") ) {
      return
    }
    # Build list of access control entries (ACEs)
    $accessControlEntries = New-Object Collections.ArrayList
    #--------------------------------------------------------------------------
    # Reset password
    #--------------------------------------------------------------------------
    [Void] $accessControlEntries.Add((
      New-Object DirectoryServices.ExtendedRightAccessRule(
        $identity,
        [Security.AccessControl.AccessControlType] "Allow",
        [Guid] $AD_RIGHTS_GUID_RESET_PASSWORD
      )
    ))
    #--------------------------------------------------------------------------
    # Validated write to DNS host name
    #--------------------------------------------------------------------------
    [Void] $accessControlEntries.Add((
      New-Object DirectoryServices.ActiveDirectoryAccessRule(
        $identity,
        [DirectoryServices.ActiveDirectoryRights] "Self",
        [Security.AccessControl.AccessControlType] "Allow",
        [Guid] $AD_RIGHTS_GUID_VALIDATED_WRITE_DNS
      )
    ))
    #--------------------------------------------------------------------------
    # Validated write to service principal name
    #--------------------------------------------------------------------------
    [Void] $accessControlEntries.Add((
      New-Object DirectoryServices.ActiveDirectoryAccessRule(
        $identity,
        [DirectoryServices.ActiveDirectoryRights] "Self",
        [Security.AccessControl.AccessControlType] "Allow",
        [Guid] $AD_RIGHTS_GUID_VALIDATED_WRITE_SPN
      )
    ))
    #--------------------------------------------------------------------------
    # Write account restrictions
    #--------------------------------------------------------------------------
    [Void] $accessControlEntries.Add((
      New-Object DirectoryServices.ActiveDirectoryAccessRule(
        $identity,
        [DirectoryServices.ActiveDirectoryRights] "WriteProperty",
        [Security.AccessControl.AccessControlType] "Allow",
        [Guid] $AD_RIGHTS_GUID_ACCT_RESTRICTIONS
      )
    ))
    # Get ActiveDirectorySecurity object
    $adSecurity = $dirEntry.ObjectSecurity
    # Add ACEs to ActiveDirectorySecurity object
    $accessControlEntries | ForEach-Object {
      $adSecurity.AddAccessRule($_)
    }
    # Commit changes
    try {
      $dirEntry.CommitChanges()
    }
    catch [Management.Automation.MethodInvocationException] {
      Write-Error -Exception $_.Exception.InnerException
    }
  }
}

process {
  foreach ( $nameItem in $Name ) {
    Grant-ComputerJoinPermission $nameItem
  }
}