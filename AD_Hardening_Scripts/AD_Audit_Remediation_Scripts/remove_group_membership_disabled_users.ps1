<#
 Script for removing all added groupmembership of disabled users. 
 This script aims to help remove all non-primary groupmembership for disabled users.
 Caution: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you, to test out the script for your Environment if you're to use it.
#>


# Import the Active Directory module
Import-Module ActiveDirectory

# Get all disabled users
$disabledUsers = Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf

# Create an array to store the data
$userData = @()

# Iterate through each disabled user
foreach ($user in $disabledUsers) {
    $userGroups = Get-ADUser $user.SamAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf

    # Remove the user from each group
    foreach ($group in $userGroups) {
        Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
    }

    # Record user data for reporting
    $groupNames = $userGroups | ForEach-Object { (Get-ADGroup $_).Name }
    $userInfo = [PSCustomObject]@{
        UserName = $user.SamAccountName
        Groups   = $groupNames -join ', '
    }

    # Add the user data to the array
    $userData += $userInfo
}

# Output the data in a table
$userData | Format-Table -AutoSize

# Export the data to a CSV file
$userData | Export-Csv -Path "DisabledUsersGroups.csv" -NoTypeInformation
