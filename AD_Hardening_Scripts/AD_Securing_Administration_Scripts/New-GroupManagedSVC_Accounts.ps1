<#
 Script for Exporting groupmembership details for disabled users, in csv format.
 This script aims to help audit role membership security for users already disabled and still having groupmemberships...
 Caution: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you to test the script for your Environment.

#>

<#
Step 1: Install RSAT on client (Non-DC) nodes
    `Add-WindowsFeature RSAT-AD-PowerShell`

Step 2: Create a Security groups and add all the computers we'll use the GMSA on to the group we created.
#>

# Import the Active Directory module
Import-Module ActiveDirectory

$gMSA_Name = Read-Host "What is the name of the gmsa you wish to create?"
$gMSA_FQDN = Read-Host "What is the DNS Name (Fully Qualified Domain Name), like (bob.acme.local)?"

# Getting all the hostname from the group
$gMSA_HostName = Get-ADGroup -Identity gMSAs | Select-Object -ExpandProperty Name

# Check if an KDS root keys exist
$rootKeys = Get-KdsRootKey
if ($rootKeys) {
    # if key exists loop through each keys
    foreach (key in $rootKeys) {
        # Get the curent date and time
        $currentTime = Get-Date

        # Check if "EffectiveTime" Property exists
        if ($key.PSPRopertyNames -contains "EffectiveTime") {
            $effectiveTime = $key.EffectiveTime

            if ($effectiveTime )
        }

    }
}

# Add the Rootkey #

<# For Lab Purpose we add 10 hours, for production though we need to wait 10 hours.
 So the key has time to propagate over to all the Domain Contorllers
 #>
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
# For Production, only if it doesn't exist previously #
Add-KdsRootKey -EffectiveImmediately

# Get the pricipal for the computer account(s) in $gMSA_HostNames
$