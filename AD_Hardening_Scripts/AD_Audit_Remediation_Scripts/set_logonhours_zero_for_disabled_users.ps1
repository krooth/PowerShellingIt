<#
 Script for setting the logonhours of disabled users to zero.
 This script aims to set the allowed logonhours of disabled users to zero as good security practice.
 Caution: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you, to test out the script for your Environment if you're to use it.
#>


# Import the Active Directory module
Import-Module ActiveDirectory

# Get all disabled users
$disabledUsers = Get-ADUser -Filter {Enabled -eq $false}

# Set the logonhours to zero
[byte[]]$hours = @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

# Iterate through each disabled users
foreach ($user in $disabledUsers) {

    # Assign the logonhours to each disabled users
    Get-ADUser -Identity $user | Set-ADUser -Replace @{logonhours = $hours}
}
