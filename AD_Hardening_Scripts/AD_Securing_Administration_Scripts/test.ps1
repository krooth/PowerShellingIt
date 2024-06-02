# Import the Active Directory module
Import-Module ActiveDirectory

# Functions

# Function for receiving gMSA value inputs
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
        $sec_group_name = $args[0]
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
        $gMSAProperties = gmsa_property_input
        if ($gMSAProperties -eq $null) {
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
        New-ADServiceAccount -Name $gMSAProperties['gMSA_Name'] -DNSHostName $gMSAProperties['gMSA_FQDN'] `
            -PrincipalsAllowedToRetrieveManagedPassword $sec_group_name -KerberosEncryptionType $gMSAProperties['kerb_encryption_type']
        Write-Host "gMSA created successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function check_kds_rootkey_validity {
    try {
        $thresholdDate = (Get-Date).AddHours(-1)

        $kdsRootKeys = Get-KdsRootKey | Where-Object { $_.EffectiveTime -lt $thresholdDate }
        if ($kdsRootKeys.Count -gt 0) {
            return $true            
        } else {
            $purpose = Read-Host "Are you using this in a lab or production environment? (L/P):"
            $purpose = $purpose.ToUpper()
            if ($purpose -eq 'L') {
                Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
                return $true
            } elseif ($purpose -eq 'P') {
                Add-KdsRootKey -EffectiveImmediately
                Write-Host "Waiting for 10
