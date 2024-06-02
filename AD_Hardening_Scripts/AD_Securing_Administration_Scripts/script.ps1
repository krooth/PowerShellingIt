# Get the current date
$currentDate = Get-Date

# Set the time span to check for the KDS root key creation
$timeSpan = New-TimeSpan -Days 30  # Adjust the number of days as needed

# Calculate the date 30 days ago
$thresholdDate = $currentDate.AddDays(-30)

# Get the KDS root keys created before the threshold date
$kdsRootKeys = Get-KdsRootKey | Where-Object { [datetime]::Parse($_.EffectiveTime) -lt $thresholdDate }

# Check if there are any KDS root keys created before the threshold date
if ($kdsRootKeys.Count -gt 0) {
    # Prompt user to enter gMSA name
    $gMSAName = Read-Host -Prompt "Enter the name for the Group Managed Service Account (gMSA)"

    # Check if the gMSA name is provided
    if ([string]::IsNullOrWhiteSpace($gMSAName)) {
        Write-Host "Please provide a valid name for the Group Managed Service Account (gMSA)." -ForegroundColor Red
    }
    else {
        # Create gMSA
        New-ADServiceAccount -Name $gMSAName -DNSHostName $gMSAName -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"
        Write-Host "Group Managed Service Account (gMSA) '$gMSAName' created successfully." -ForegroundColor Green
    }
}
else {
    Write-Host "No KDS root keys created before $thresholdDate found. Cannot create the Group Managed Service Account (gMSA)." -ForegroundColor Yellow
}
