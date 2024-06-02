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



# Getting all the hostname from the group
$gMSA_HostName = Get-ADGroup -Identity gMSAs | Select-Object -ExpandProperty Name

#Functions
# Function for recieving gmsa value inputs
function gmsa_property_input {
    try {
        $gmsa_values = @()
        
        $gMSA_Name = Read-Host "What is the name of the gmsa you wish to create?"
        # Check if the gMSA name is provided
        if ([string]::IsNullOrWhiteSpace($gMSA_Name)) {
            Write-Host "Please provide a valid name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
        } else {
            $gMSA_FQDN = Read-Host "What is the DNS Name (Fully Qualified Domain Name), like (bob.acme.local)?"
            if ([string]::IsNullOrWhiteSpace($gMSA_FQDN)) {
                Write-Host "Please provide a valid name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
            } else {
                $kerb_encryption_type = Read-Host "What kind of encyrption do you want to use(None, AES128, AES256, DES, RC4)?"
        }
        $kerb_encryption_type = $kerb_encryption_type.ToUpper()  
        }
    } catch {
        Write-Host $_.Exception.Message
    }
}

# Function for creating Security Group
function create_group {
   try {
    $sec_group_name = Read-Host "What it the name of gMSA password retrieving nodes securty group?"
    $path = Read-Host "Sepcify the full path of the security group to be created."    
    
    # Create security group
    $ad_group = New-ADGroup $sec_group_name -Path $Path -GroupCategory Security -GroupScope DomainLocal -PassThru -Verbose 
    $sec_group_name = $ad_group | Select-Object -ExpandProperty SamAccountName
    return $sec_group_name
   } catch {
    Write-Host $_.Exception.Message
   } 
}
# Function to add nodes to the security group that can retreieve the credentials of the gMSA
function add_nodes_to_sec_group {

    [CmdletBinding()]
    param (
        [string]$sec_group_name
    )

    try {
        $nodes = @()
    do {
        $node = Read-Host "Enter the name of node to add to the security group?"
        if ($node -ne "") {
            $nodes += $node
        }
    } while (node -ne "")
    # Loop through each node name and add it to the security group
    foreach ($node in $nodes) {
        Add-ADGroup -Identity $sec_group_name -Members $node
    }    
    } catch {
        Write-Host $_.Exception.Message
    }
}
# Function for creating gMSA
function create_gMSA() {
    [CmdletBinding()]
    param (
        [string]$gMSA_Name
    )
    try {
        New-ADServiceAccount $gMSA_Name -DNSHostName $gMSA_HostName -PrincipalsAllowedToRetrieveManagedPassword $sec_group_name -KerberosEncryptionType $   
    } catch {
        Write-Host $_.Exception.Message
    }
}


function check_kds_rootkey_validity() {
    try {
        $thresholdDate = (Get-Date).AddDays(-1).ToString("yyyy/MM/dd hh:mm:ss tt")

        # Get the KDS root keys created before the threshold date
        $kdsRootKeys = Get-KdsRootKey | Where-Object { $_.EffectiveTime -lt $thresholdDate }
        # Check if there are any KDS root keys created before the threshold date        
        if ($kdsRootKeys.Count -gt 0) {
            gmsa_property_input
            $sec_group_name = create_group
            create_gMSA($sec_group_name)
        }       
    } catch {
        Write-Host $_.Exception.Message
    }
}
# Check if an KDS root keys exist
$rootKeys = Get-KdsRootKey
if ($rootKeys) {
    # if key exists loop through each keys
    foreach (key in $rootKeys) {
        # Get the curent date and time
        $currentTime = Get-Date -Format "MM/dd/yyy HH:mm:ss tt"
        

        # Check if "EffectiveTime" Property exists
        if ($key.PSPRopertyNames -contains "EffectiveTime") {
            $effectiveTime = $key.EffectiveTime

            if ($effectiveTime) 
        }
        else {
            Add-KdsRootKey -EffectiveImmediately

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