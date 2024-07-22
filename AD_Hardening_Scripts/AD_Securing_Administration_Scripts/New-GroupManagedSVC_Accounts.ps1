<#
 Script to create group managed service accounts (gMSAs), associated security groups, and KDS root keys.
 This script helps automate the process of setting up gMSAs in an Active Directory environment.
 Full responsibility relies on you to test the script for your Environment.

#>

<#
Step 1: Install RSAT on client (Non-DC) nodes
    `Add-WindowsFeature RSAT-AD-PowerShell`

Step 2: Create a Security group and add all the computers that will use the GMSA to the group created.
#>

# Import the Active Directory module
Import-Module ActiveDirectory

# Functions
# Function for receiving gMSA value inputs
function Get-gMSAProperties {
    param (
        [string]$gMSA_Name,
        [string]$gMSA_FQDN,
        [string]$kerb_encryption_type
    )

    while ([string]::IsNullOrWhiteSpace($gMSA_Name)) {
        $gMSA_Name = Read-Host "Enter the name of the gMSA you wish to create:"
        if ([string]::IsNullOrWhiteSpace($gMSA_Name)) {
            Write-Host "Please provide a valid name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
        }
    }

    while ([string]::IsNullOrWhiteSpace($gMSA_FQDN)) {
        $gMSA_FQDN = Read-Host "Enter the DNS Name (Fully Qualified Domain Name), like (bob.acme.local):"
        if ([string]::IsNullOrWhiteSpace($gMSA_FQDN)) {
            Write-Host "Please provide a valid DNS name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
        }
    }

    while ([string]::IsNullOrWhiteSpace($kerb_encryption_type)) {
        $kerb_encryption_type = Read-Host "Enter the encryption type (None, AES128, AES256, DES, RC4):"
        $kerb_encryption_type = $kerb_encryption_type.ToUpper()
        if ([string]::IsNullOrWhiteSpace($kerb_encryption_type)) {
            Write-Host "Please provide a valid encryption type." -ForegroundColor Red
        }
    }

    return @{
        'gMSA_Name' = $gMSA_Name
        'gMSA_FQDN' = $gMSA_FQDN
        'kerb_encryption_type' = $kerb_encryption_type
    }
}

# Function for creating Security Group
function Create-SecurityGroup {
    param (
        [string]$sec_group_name,
        [string]$path
    )

    while ([string]::IsNullOrWhiteSpace($sec_group_name)) {
        $sec_group_name = Read-Host "Enter the name of the security group for nodes that can retrieve gMSA credentials:"
        if ([string]::IsNullOrWhiteSpace($sec_group_name)) {
            Write-Host "Please provide a valid name for the security group." -ForegroundColor Red
        }
    }

    while ([string]::IsNullOrWhiteSpace($path)) {
        $path = Read-Host "Specify the full path of the security group to be created:"
        if ([string]::IsNullOrWhiteSpace($path)) {
            Write-Host "Please provide a valid path for the security group." -ForegroundColor Red
        }
    }

    try {
        $ad_group = New-ADGroup -Name $sec_group_name -Path $path -GroupCategory Security -GroupScope DomainLocal -PassThru -Verbose 
        return $ad_group.SamAccountName
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to add nodes to the security group that can retrieve the credentials of the gMSA
function Add-NodesToSecurityGroup {
    param (
        [string]$sec_group_name
    )

    $nodes = @()
    while ($true) {
        $node = Read-Host "Enter the name of a node to add to the security group (leave blank to stop adding):"
        if ([string]::IsNullOrWhiteSpace($node)) {
            break
        }

        try {
            $nodeObject = Get-ADComputer -Identity $node -ErrorAction Stop
            $nodes += $nodeObject.SamAccountName
        } catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    foreach ($node in $nodes) {
        try {
            Add-ADGroupMember -Identity $sec_group_name -Members $node -ErrorAction Stop
        } catch {
            Write-Host "Error adding $node to $sec_group_name: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "Nodes added to the security group successfully." -ForegroundColor Green
}

# Function for creating gMSA
function Create-gMSA {
    try {
        $gMSA_Properties = Get-gMSAProperties
        if ($null -eq $gMSA_Properties) {
            Write-Host "Failed to collect gMSA properties. Exiting." -ForegroundColor Red
            return
        }

        $sec_group_name = Create-SecurityGroup
        if ([string]::IsNullOrWhiteSpace($sec_group_name)) {
            Write-Host "Failed to create the security group. Exiting." -ForegroundColor Red
            return
        }

        Add-NodesToSecurityGroup -sec_group_name $sec_group_name

        New-ADServiceAccount -Name $gMSA_Properties['gMSA_Name'] -DNSHostName $gMSA_Properties['gMSA_FQDN'] `
            -PrincipalsAllowedToRetrieveManagedPassword $sec_group_name -KerberosEncryptionType $gMSA_Properties['kerb_encryption_type']
        Write-Host "gMSA created successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to check KDS root key validity
function Check-KDSRootKeyValidity {
    try {
        $thresholdDate = (Get-Date).AddHours(-10)

        $kdsRootKeys = Get-KdsRootKey | Where-Object { $_.EffectiveTime -lt $thresholdDate }

        if ($kdsRootKeys.Count -gt 0) {
            return $true
        } else {
            $purpose = Read-Host "Are you using this in a lab or production? (L) for Lab (P) for Production:"
            if ([string]::IsNullOrWhiteSpace($purpose) -or (($purpose -ne 'L') -and ($purpose -ne 'P'))) {
                Write-Host "Please provide a valid response." -ForegroundColor Red
                return $false
            }

            if ($purpose.ToUpper() -eq 'L') {
                Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
                return $true
            } else {
                return $false
            }
        }
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main
if (Check-KDSRootKeyValidity) {
    Create-gMSA
} else {
    Add-KdsRootKey -EffectiveImmediately
    Write-Host "Waiting for 10 hours for KDS root key to populate throughout the domain..." -ForegroundColor Yellow
    Start-Sleep -Seconds (10 * 3600)
    Create-gMSA
}
