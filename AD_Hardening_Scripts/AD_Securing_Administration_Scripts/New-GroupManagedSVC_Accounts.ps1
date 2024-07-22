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


$gMSA_Name = $null
$gMSA_FQDN = $null
$kerb_encryption_type = $null
$sec_group_name = $null

#Functions
# Function for recieving gmsa value inputs
function gmsa_property_input {
    try {

        $gMSA_Name = Read-Host "What is the name of the gMSA you wish to create?"
        if ([string]::IsNullOrWhiteSpace($gMSA_Name)) {
            Write-Host "Please provide a valid name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
            return $null
        }
        $gMSA_FQDN = Read-Host "What is the DNS Name (Fully Qualified Domain Name), like (bob.acme.local)?"
        if ([string]::IsNullOrWhiteSpace($gMSA_FQDN)) {
            Write-Host "Please provide a valid DNS name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
            return $null
        }
        $kerb_encryption_type = Read-Host "What kind of encryption do you want to use (None, AES128, AES256, DES, RC4)?"
        $kerb_encryption_type = $kerb_encryption_type.ToUpper()  

        return @{
            'gMSA_Name' = $gMSA_Name
            'gMSA_FQDN' = $gMSA_FQDN
            'kerb_encryption_type' = $kerb_encryption_type
        }     
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function for creating Security Group
function create_group {
   try {
    $sec_group_name = Read-Host "What is the name of the security group for nodes that can retrieve gMSA credentials?"
    if ([string]::IsNullOrWhiteSpace($sec_group_name)) {
        Write-Host "Please provide a valid name for the security group." -ForegroundColor Red
        return $null
    }
    $path = Read-Host "Specify the full path of the security group to be created."
    if ([string]::IsNullOrWhiteSpace($path)) {
        Write-Host "Please provide a valid path for the security group." -ForegroundColor Red
        return $null
    }    
    
    $ad_group = New-ADGroup $sec_group_name -Path $path -GroupCategory Security -GroupScope DomainLocal -PassThru -Verbose 
    $sec_group_name = $ad_group | Select-Object -ExpandProperty SamAccountName
    return $sec_group_name
   } catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    return $null
   } 
}
# Function to add nodes to the security group that can retrieve the credentials of the gMSA
function add_nodes_to_sec_group {
    try {
        $nodes = @()
        do {
            $node = Read-Host "Enter the name of a node to add to the security group (leave blank to stop adding):"
            if (![string]::IsNullOrWhiteSpace($node)) {
                $nodeObject = Get-ADComputer -Identity $node -ErrorAction Stop
                $nodeName = $nodeObject.SamAccountName
                $nodes += $nodeName
            }
        } while (![string]::IsNullOrWhiteSpace($node))
        
        # Loop through each node name and add it to the security group
        foreach ($node in $nodes) {
            Add-ADGroupMember -Identity $sec_group_name -Members $node -ErrorAction Stop
        }
        Write-Host "Nodes added to the security group successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function for creating gMSA
function create_gMSA {
    try {
        $gMSA_Properties = gmsa_property_input
        if ($gMSA_Properties -eq $null) {
            Write-Host "Failed to collect gMSA properties. Exiting." -ForegroundColor Red
            return
        }
        $sec_group_name = create_group
        if ([string]::IsNullOrWhiteSpace($sec_group_name)) {
            Write-Host "Failed to create the security group. Exiting." -ForegroundColor Red
            return
        }
        add_nodes_to_sec_group $sec_group_name
        $gMSA_HostName = Get-ADGroup -Identity $sec_group_name | Select-Object -ExpandProperty Name
        New-ADServiceAccount -Name $gMSA_Properties['gMSA_Name'] -DNSHostName $gMSA_Properties['gMSA_FQDN'] `
            -PrincipalsAllowedToRetrieveManagedPassword $sec_group_name -KerberosEncryptionType $gMSA_Properties['kerb_encryption_type']
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function check_kds_rootkey_validity() {
    try {
        $thresholdDate = (Get-Date).AddHours(-10).ToString("yyyy/MM/dd hh:mm:ss tt")

        # Get the KDS root keys created before the threshold date
        $kdsRootKeys = Get-KdsRootKey | Where-Object { $_.EffectiveTime -lt $thresholdDate }
        # Check if there are any KDS root keys created before the threshold date        
        if ($kdsRootKeys.Count -gt 0) {
            return $true            
        } else {
            $purpose = $(Write-Host "Are using this in a lab or production? (L) for Lab (P) for production: " -ForegroundColor red; Read-Host)
            if ([string]::IsNullOrWhiteSpace($purpose) -and (($purpose -ne 'L') -or ($purpose -ne 'P'))) {
                Write-Host "Please provide a valid response." -ForegroundColor Red
            }
            $purpose = $purpose.ToUpper()

            if ($purpose -eq 'L') {
                Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
                return $true
            } else {
                return $false
            }
        }       
    } catch {
        Write-Host $_.Exception.Message
    }
}

# Main 

if (check_kds_rootkey_validity) {
    create_gMSA
} else {
    # For Production, only if it doesn't exist previously #
    Add-KdsRootKey -EffectiveImmediately

    # Wait for 10 hours until it populates throughout the domain
    Write-Host "Waiting for 10 hours...."
    Start-Sleep -Seconds (10 * 3600)

    # Create gMSA after 10 hours
    create_gMSA
}
