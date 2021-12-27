# Get current directory
$scriptpath = $MyInvocation.MyCommand.Path
$currentdir = Split-Path $scriptpath

# Get list of old and new shares
$Shares = Import-Csv -Path $($currentdir + '\list.csv')

# Get list of all drives
$Drives = Get-PSDrive -PSProvider FileSystem

# Loop through drives list
ForEach ($Drive in $Drives)
{
    # Loop through shares list
    Foreach ($Share in $Shares)
    {
        # Check if drive matches old share
        If ($Drive.DisplayRoot -match $Share.Old)
        {
            # Get drive letter and set new path
            $Name = $Drive.Name
            $Root = (($Drive.DisplayRoot).ToUpper()).Replace($Share.Old,$Share.New)

            # Remove old drive mapping
            net use $($Name + ':') /delete /y

            # Set new drive mapping
            net use $($Name + ':') $Root /Persistent:yes
        }
    }
}