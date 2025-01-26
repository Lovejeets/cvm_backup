[CmdletBinding(DefaultParameterSetName = "Configure")]
param (
    # Login parameters
    [Parameter(Mandatory = $true)]
    [Alias("AppId")]
    [String]
    $ClientId,

    [Parameter(Mandatory = $true)]
    [Alias("SecretKey")]
    [String]
    $ClientSecret,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')] # RegEx to enforce that domain name is passed as a parameter
    [String]
    $TenantId,

    # Azure parameters
    [Parameter(Mandatory = $false)]
    [String]
    $AzureResourceGroup = "AzureStackBackupRG",

    [Parameter(Mandatory = $true)]
    [String]
    $VaultName,

    [Parameter(Mandatory = $false)]
    [String]
    $SubscriptionId,

    [Parameter(Mandatory = $false)]
    [String]
    $AzureLocation = "UAE North",

    [Parameter(Mandatory = $false)]
    [Switch]
    $ExistingRG,

    [Parameter(Mandatory = $false)]
    [Switch]
    $ExistingVault,

    # Server config parameters
    [Parameter(Mandatory = $false)]
    [String]
    $TempFilesPath = "C:\temp",

    [Parameter(Mandatory = $true)]
    [ValidateLength(16, 40)]
    [String]
    $EncryptionKey,

    # Backup schedule config parameters
    [Parameter(Mandatory = $true, ParameterSetName = "Configure")]
    [ValidateCount(1, 7)]
    [String[]]
    $BackupDays,

    [Parameter(Mandatory = $true, ParameterSetName = "Configure")]
    [String[]]
    $BackupTimes,

    [Parameter(Mandatory = $false, ParameterSetName = "Configure")]
    [Int]
    $RetentionLength = 7,

    [Parameter(Mandatory = $false, ParameterSetName = "Configure")]
    [ValidateScript( { $_ -split "," | ForEach-Object { Test-Path -Path $_ } })]
    [String[]]
    $FoldersToBackup,

    [Parameter(Mandatory = $false, ParameterSetName = "Configure")]
    [Switch]
    $BackupNow,

    [Parameter(Mandatory = $true, ParameterSetName = "NoConfigure")]
    [Switch]
    $NoSchedule
)

begin {
    # Change the object type to Array and remove spaces
    $BackupTimes = ($BackupTimes -split ",") -replace " ", ""
    $BackupDays = ($BackupDays -split ",") -replace " ", ""
    $FoldersToBackupArray = ($FoldersToBackup -split ",") -replace " ", ""

    # You can schedule only three daily backups per day so we want to make sure users will NOT run the whole script and then fail, hence we are checking it here
    if ($BackupTimes.Length -gt 3) {
        Write-Error -Message "You can schedule up to three daily backups per day!`nMake sure you only put three objects into the array." -ErrorAction "Stop"
        break
    }
}

process {
    # Initialise TempFilesPath folder
    if (-not (Test-Path -Path $TempFilesPath)) {
        New-Item -ItemType Directory -Path $TempFilesPath -Force | Out-Null
        Write-Output -InputObject "Created directory: $TempFilesPath"
    }

    # Install Modules
    Write-Output -InputObject "Installing Nuget and Az PowerShell modules."
    Install-PackageProvider -Name "NuGet" -Confirm:$false -Force | Out-Null
    Install-Module -Name "Az" -RequiredVersion 2.4.0 -Confirm:$false -AllowClobber
    Install-Module -Name "Az.RecoveryServices" -Confirm:$false -Force

    # Download the MARS agent
    Write-Output -InputObject "Downloading MARS agent."
    $OutPath = Join-Path -Path $TempFilesPath -ChildPath "MARSAgentInstaller.exe"
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("https://aka.ms/azurebackup_agent", $OutPath)

    # Install the MARS agent
    Write-Output -InputObject "Installing MARS agent"
    & $OutPath /q

    if (-not $ExistingVault) {
        # Create and configure a vault, then retrieve settings
        ## Login to public azure
        Write-Output -InputObject "Logging into public Azure with tenant ID: $TenantId"
        $CredPass = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential ($ClientId, $CredPass)
        Connect-AzAccount -Credential $Credentials -ServicePrincipal -Tenant $TenantId

        if (-not $ExistingRG) {
            # Create resource group
            Write-Output -InputObject "Creating resource group: $AzureResourceGroup in public Azure."
            New-AzResourceGroup -Name $AzureResourceGroup -Location $AzureLocation | Out-Null
        }

        # Create the vault
        Write-Output -InputObject "Creating backup vault: $BackupVault in resource group: $AzureResourceGroup in public Azure."
        $BackupVault = New-AzRecoveryServicesVault -Name $VaultName -ResourceGroupName $AzureResourceGroup -Location $AzureLocation
        Set-AzRecoveryServicesBackupProperties -Vault $BackupVault -BackupStorageRedundancy LocallyRedundant
    }

    # Retrieve vault credentials file
    $ScriptPath = Join-Path -Path $TempFilesPath -ChildPath "script.ps1"
    @"
`$CredPass = ConvertTo-SecureString -String `$args[1] -AsPlainText -Force
`$Cred = New-Object System.Management.Automation.PSCredential (`$args[0], `$CredPass)
Connect-AzAccount -Credential `$Cred -ServicePrincipal -Tenant $TenantId -Subscription $SubscriptionId
# Download Vault Settings
Write-Output -InputObject "Downloading vault settings."
`$Retry = 0
while (!`$VaultCredPath -and `$Retry -lt 20) {
    # Get Vault
    `$BackupVaultGet = Get-AzRecoveryServicesVault -Name $VaultName -ResourceGroupName $AzureResourceGroup
    `$VaultCredPath = Get-AzRecoveryServicesVaultSettingsFile -Vault `$BackupVaultGet -Path $TempFilesPath -Backup
    `$VaultCredPath.FilePath | Out-File (Join-Path -Path $TempFilesPath -ChildPath "VaultCredential.txt") -Encoding ascii -Force
    Start-Sleep -Seconds 5
    `$Retry ++
    if (`$Retry -eq 20) {
        Write-Output -InputObject "Unable to retrieve Vault Credentials file"
        break
    }
}
"@ | Out-File $ScriptPath -Force -Encoding ascii

    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $ScriptPath $ClientId $ClientSecret
    $VaultCredPath = Get-Content -Path (Join-Path -Path $TempFilesPath -ChildPath "VaultCredential.txt")

    # Import MS Online Backup module
    Import-Module -Name "C:\Program Files\Microsoft Azure Recovery Services Agent\bin\Modules\MSOnlineBackup"

    # Register MARS agent to Recovery Services vault
    Write-Output -InputObject "Registering MARS agent to Recovery Services vault."
    Start-OBRegistration -VaultCredentials $VaultCredPath -Confirm:$false

    # Set encryption key for MARS agent
    ConvertTo-SecureString -String $EncryptionKey -AsPlainText -Force | Set-OBMachineSetting

    if (-not $NoSchedule) {
        # Configure backup settings
        Write-Output -InputObject "Configuring backup settings"

        ## Create blank backup policy
        $BackupPolicy = New-OBPolicy
        ## Set backup schedule
        $BackupSchedule = New-OBSchedule -DaysOfWeek $BackupDays -TimesOfDay $BackupTimes
        Set-OBSchedule -Policy $BackupPolicy -Schedule $BackupSchedule
        ## Set retention policy
        $RetentionPolicy = New-OBRetentionPolicy -RetentionDays $RetentionLength
        Set-OBRetentionPolicy -Policy $BackupPolicy -RetentionPolicy $RetentionPolicy

        ## Set drives to be backed up, excluding the temporary storage
        if (-not $FoldersToBackupArray) {
            $Drives = Get-PSDrive -PSProvider "Microsoft.PowerShell.Core\FileSystem" | Where-Object -FilterScript { $_.Used -gt 0 -and $_.Description -notlike "Temporary Storage" } | Select-Object -ExpandProperty Root
            $FileInclusions = New-OBFileSpec -FileSpec @($Drives)
        }
        else {
            $FileInclusions = New-OBFileSpec -FileSpec @($FoldersToBackupArray)
        }

        $FileExclusions = New-OBFileSpec -FileSpec @($TempFilesPath) -Exclude
        Add-OBFileSpec -Policy $BackupPolicy -FileSpec $FileInclusions
        Add-OBFileSpec -Policy $BackupPolicy -FileSpec $FileExclusions

        # Remove the (possibly) existing policy
        try {
            Get-OBPolicy | Remove-OBPolicy -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Output -InputObject "No existing policy to remove."
        }

        # Apply the new policy
        Set-OBPolicy -Policy $BackupPolicy -Confirm:$false
    }

    # Start a backup if required
    if ($BackupNow) {
        Get-OBPolicy | Start-OBBackup
    }

    # Clean-up temp resources
    Remove-Item -Path $VaultCredPath -Force -Confirm:$false
    Remove-Item -Path $ScriptPath -Force -Confirm:$false
    Remove-Item -Path $OutPath -Force -Confirm:$false
}
