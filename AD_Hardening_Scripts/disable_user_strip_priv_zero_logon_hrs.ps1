<#
 Script for Exporting groupmembership details for disabled users, in csv format.
 This script aims to help audit role membership security for users already disabled and still having groupmemberships...
 Caution: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you to test the script for your Environment.

#>
# Import the Active Directory module
Import-Module ActiveDirectory

# Input the user to be disabled
$disableUser = Read-Host "What is the username of the user you want to disable?" 
$user = Get-ADUser -Identity $disableUser -Properties MemberOf

# Extract each groups and add them to an array
$userData = @()

$userGroups = Get-ADUser $user.SamAccountName -Properties MemberOf | Select-Object -ExpandProperty MemberOf

# Remove the user from each group
foreach ($group in $userGroups) {
    Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
}

# Record user data for reporting
$groupNames = $userGroups | ForEach-Object { (Get-ADGroup $_).Name}
$userInfo = [PSCustomObject]@{
    UserName = $user.SamAccountName
    Groups   = $groupNames -join ', '
}

# Add the user data to the array
$userData += $userInfo

# Output the data in a table
$userData | Format-Table -AutoSize




