#powershell.exe


# Written by: Aaron Wurthmann
#
# You the executor, runner, user accept all liability.
# This code comes with ABSOLUTELY NO WARRANTY.
# This is free and unencumbered software released into the public domain.
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# --------------------------------------------------------------------------------------------
# Name: Setup-WindowsEnvironment.ps1
# Version: 2021.10.22.1529
# Description: Setup Windows Environment on my Test System(s)
# 
# Instructions: Run from PowerShell with Administrator permissions and Set-ExecutionPolicy Bypass -Scope Process -Force
#	
# Tested with: Microsoft Windows [Version 10.0.19042.804], PowerShell [Version 5.1.19041.610]
# Arguments: See Params Below
# Output: Standard Out
#
# Notes:  
# --------------------------------------------------------------------------------------------

Param (
	[bool]$myOverrides=$False,
	[string]$NewComputerName,
	
	[bool]$ConfirmWindowsFirewallControl=$True,
	[bool]$ConfirmSetProfile=$True,
	[bool]$ConfirmDisableTelemetry=$True,
	[bool]$ConfirmDisableCortana=$True,
	[bool]$ConfirmDisableOneDrive=$True,
	[bool]$ConfirmDisableUnusedServices=$True,
	[bool]$ConfirmInstallOptionalApps=$True,

	[bool]$ConfirmDisableApplicationSuggestions=$True,
	[bool]$ConfirmDisableActivityHistory=$True,
	[bool]$ConfirmDisableLocationTracking=$True,
	[bool]$ConfirmDisableFeedback=$True,
	[bool]$ConfirmDisableAdTargeting=$True,
	[bool]$ConfirmDisableWindowsP2PUpdates=$True,
	[bool]$ConfirmDisableRemoteAssistance=$True,
	[bool]$ConfirmDisableCapsLock=$True,
	[bool]$ConfirmInstallChoco=$True,
	[bool]$ConfirmInstallBaseApps=$True,
	[bool]$ConfirmInstallSysinternals=$True,

	[bool]$ConfirmRemoveUnwantedApps=$True,
	[bool]$ConfirmDisableEdgeDefaults=$True,
	[bool]$ConfirmSetSecuritySettings=$True,
	[bool]$ConfirmSetWindowsUpdateSettings=$True,
	
	[bool]$ConfirmEnableRDP=$True,

	[bool]$ConfirmSetWindowsExplorerView=$True,
	[bool]$ConfirmRemoveLinks=$True,
	[bool]$ConfirmSetRepositorySettings=$True,
	[bool]$ConfirmGetWindowsUpdates=$True,
	
	[bool]$ConfirmEncryptDesktop=$True,
	
	[bool]$ConfirmRestart=$True,
	
	[bool]$CreateLog=$True,
	[string]$LogFile
)

###My Overrides
If ($myOverrides) {

	#$ConfirmWindowsFirewallControl=$True
	$ConfirmSetProfile=$False
	$ConfirmDisableTelemetry=$False
	$ConfirmDisableCortana=$False
	$ConfirmDisableOneDrive=$False
	$ConfirmDisableUnusedServices=$False
	#$ConfirmInstallOptionalApps=$True

	$ConfirmDisableApplicationSuggestions=$False
	$ConfirmDisableActivityHistory=$False
	$ConfirmDisableLocationTracking=$False
	$ConfirmDisableFeedback=$False
	$ConfirmDisableAdTargeting=$False
	$ConfirmDisableWindowsP2PUpdates=$False
	$ConfirmDisableRemoteAssistance=$False
	$ConfirmDisableCapsLock=$False
	$ConfirmInstallChoco=$False
	$ConfirmInstallBaseApps=$False
	$ConfirmInstallSysinternals=$False

	$ConfirmRemoveUnwantedApps=$False
	$ConfirmDisableEdgeDefaults=$False
	$ConfirmSetSecuritySettings=$False
	$ConfirmSetWindowsUpdateSettings=$False
	
	$ConfirmEnableRDP=$False

	$ConfirmSetWindowsExplorerView=$False
	$ConfirmRemoveLinks=$False
	$ConfirmSetRepositorySettings=$False
	$ConfirmGetWindowsUpdates=$False
	
	#$ConfirmEncryptDesktop=$True
	
	#$ConfirmRestart=$True
	
	#$CreateLog=$True
}
###End My Overrides

function isAdmin {
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function isConnectedToInternet {
	Param ([string]$RemoteHost="www.google.com")
	return (Test-NetConnection -ComputerName $RemoteHost -Port 443).TcpTestSucceeded
}

function isChocoInstalled {
	return (Test-Path -Path "$env:ProgramData\Chocolatey")
}

function isPSGalleryTrusted {
	$PSGallery=Get-PSRepository | Where {($_.Name -eq "PSGallery")}
	return ($PSGallery.InstallationPolicy -eq "Trusted")
}

function isServiceEnabled {
	Param ([string]$ServiceName)
	
	$Service=Get-Service $ServiceName -ErrorAction SilentlyContinue
	If($Service){
		return $($ServiceName | Select -Property StartType -ErrorAction SilentlyContinue).StartType -ne "Disabled"
	}
	Else{
		return $False
	}
	
}

function Write-Log {
	Param ([string]$LogPath,[string]$LogMessage)

	[string]$LineValue = "PS (C) ["+(Get-Date -Format HH:mm:ss:fff)+"]: $LogMessage"
	$LineValue >> $LogPath
}

###Unused Service Related Functions
# function isServiceRunning {
	# Param ([string]$ServiceName)
	# Return $(Get-Service $ServiceName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).Status -eq "Running"
# }
###End Unused Service Related Functions


function Create-RestorePoint {
	
	$MyCommand=$($MyInvocation.MyCommand)
	Write-Log $LogFile "$($MyCommand)"
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$($MyCommand)"
	Write-Host ""
	Write-Host "Creating Restore Point..." -ForegroundColor Green
	Write-Log $LogFile " Enabling Restore Feature for Drive: $($env:SystemDrive)"
	Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
	Write-Log $LogFile " Creating Restore Point Named: 'RP: $(Get-Date -Format yyyyMMdd-HHmmssfff:TK)'"
	Checkpoint-Computer -Description "RP: $(Get-Date -Format yyyyMMdd-HHmmssfff:TK)" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable CapturedWarning
	If ($CapturedWarning){
		Write-Log $LogFile "$CapturedWarning"
		$Result="Warning"
	}
	
	If(!($Result)){$Result="No Errors"}
	Write-Log $LogFile "$($MyCommand) Completed with Result: $Result"
}

function Set-Profile {
	Param ([bool]$Confirm)
	
	$MyCommand=$($MyInvocation.MyCommand)
	Write-Log $LogFile "$($MyCommand)"
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$($MyCommand)"
	Write-Host ""
	Write-Host "Setting Profile..." -ForegroundColor Green

	If ($Confirm) {
		$Proceed=$False
		Write-Host -NoNewLine "I prefer a custom PowerShell profile, a custom prompt and functions.`n As seen here: " -ForegroundColor Yellow
		Write-Host "https://raw.githubusercontent.com/awurthmann/my-powershell-profile/main/Profile.ps1" -ForegroundColor Blue
		Write-Host -NoNewLine " To enable this profile the PowerShell Execution Policy is set to " -ForegroundColor Yellow
		Write-Host "RemoteSigned" -ForegroundColor Red
		
		Write-Host ""
		$msg="Do you want to import this PowerShell profile and set the Execution Policy to RemoteSigned, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyCommand) Skipped"
		return
	}
	
	Write-Host ""
	Write-Host "Import Profile..." -ForegroundColor Green
	Write-Log $LogFile " Importing Profile: 'https://raw.githubusercontent.com/awurthmann/my-powershell-profile/main/Set-Profile.ps1'"
	
	try{
		iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/my-powershell-profile/main/Set-Profile.ps1'))
	}
	catch{
		$Result="Error"
		Write-Log $LogFile $_.Exception.Message
	}
	
	If ($Result -ne "Error"){
		Write-Host ""
		Write-Host "Setting Execution Policy to 'RemoteSigned'" -ForegroundColor Green
		Write-Log $LogFile " Setting Execution Policy to 'RemoteSigned'"
		Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
	}

	If(!($Result)){$Result="No Errors"}
	Write-Log $LogFile "$($MyCommand) Completed with Result: $Result"
	
}

function Disable-Telemetry {
	Param ([bool]$Confirm)
	
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-Telemetry"
	Write-Host ""
	Write-Host "Disable Telemetry..." -ForegroundColor Green

	If ($Confirm) {
		$Proceed=$False
		Write-Host "Windows Telemetry sends diagnostic data to Microsoft. This data includes basic " -ForegroundColor Yellow
		Write-Host "system diagnostics information, logs of how frequently you use features and " -ForegroundColor Yellow
		Write-Host "applications, system files, and more." -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Telemetry, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	$cmds=@(
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0  | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0  | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0  | Out-Null",
		
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' | Out-Null",
		
		"Stop-Service 'DiagTrack' -WarningAction SilentlyContinue",
		"Set-Service 'DiagTrack' -StartupType Disabled -WarningAction SilentlyContinue"
	)
	
	$currErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	ForEach ($cmd in $cmds) {
		If ($cmd -notlike "Write-Host*"){Write-Log $LogFile $cmd}
		try {
			Invoke-Expression $cmd
		}
		catch {
			Write-Log $LogFile " ERROR: $($_.Exception.Message)"
			$cmdError=$True
		}
		If ((!($cmdError)) -and ($cmd -notlike "Write-Host*")) {Write-Log $LogFile " Success"}
	}
	$ErrorActionPreference = $currErrorActionPreference
	
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-ApplicationSuggestions {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-ApplicationSuggestions"
	Write-Host ""
	Write-Host "Disable Application Suggestions..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Windows Application Suggestions makes application and game recommendations based" -ForegroundColor Yellow
		Write-Host "on use. Users will occasionally see app suggestions on Start such as FarmVille" -ForegroundColor Yellow
		Write-Host "Candy Crush, Age of Empires, Netflix, Pandora, Twitter, etc..." -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Application Suggestions, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	# New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force -WarningAction SilentlyContinue| Out-Null
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
	
	$cmds=@(
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'ContentDeliveryAllowed' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'OemPreInstalledAppsEnabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEnabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'PreInstalledAppsEverEnabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SilentInstalledAppsEnabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338388Enabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-353698Enabled' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SystemPaneSuggestionsEnabled' -Type DWord -Value 0 | Out-Null",
		"New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Force -WarningAction SilentlyContinue | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1 | Out-Null"
	)
	
	$currErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	ForEach ($cmd in $cmds) {
		If ($cmd -notlike "Write-Host*"){Write-Log $LogFile $cmd}
		try {
			Invoke-Expression $cmd
		}
		catch {
			Write-Log $LogFile " ERROR: $($_.Exception.Message)"
			$cmdError=$True
		}
		If ((!($cmdError)) -and ($cmd -notlike "Write-Host*")) {Write-Log $LogFile " Success"}
	}
	$ErrorActionPreference = $currErrorActionPreference
	
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-ActivityHistory {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-ActivityHistory"
	Write-Host ""
	Write-Host "Disable Activity History..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Windows collects an Activity History of applications you launch on your PC and " -ForegroundColor Yellow
		Write-Host "sends it to Microsoft. Even if you disable or clear this, Microsoft/'s Privacy " -ForegroundColor Yellow
		Write-Host "Dashboard still shows an Activity History of applications you/’ve launched" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Activity History, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
	
	$cmds=@(
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Type DWord -Value 0 | Out-Null"
	)
	
	$currErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	ForEach ($cmd in $cmds) {
		If ($cmd -notlike "Write-Host*"){Write-Log $LogFile $cmd}
		try {
			Invoke-Expression $cmd
		}
		catch {
			Write-Log $LogFile " ERROR: $($_.Exception.Message)"
			$cmdError=$True
		}
		If ((!($cmdError)) -and ($cmd -notlike "Write-Host*")) {Write-Log $LogFile " Success"}
	}
	$ErrorActionPreference = $currErrorActionPreference
	
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-LocationTracking {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-LocationTracking"
	Write-Host ""
	Write-Host "Disable Location Tracking..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		#Write-Host ""
		Write-Host "When the device location setting is enabled, the Microsoft location service will" -ForegroundColor Yellow
		Write-Host "use a combination of (GPS), nearby wireless access points, cell towers, and" -ForegroundColor Yellow
		Write-Host "your IP address to determine your device’s location." -ForegroundColor Yellow
		Write-Host " Features such as auto-setting the time zone use this functionality." -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Location Tracking, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	# Write-Host "Disabling Location Tracking..." -ForegroundColor Green
	# If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")){
		# New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null}
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

	# Write-Host "Disabling automatic Maps updates..." -ForegroundColor Green
	# Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
	
	# Write-Host "Stopping and disabling Geolocation Service..." -ForegroundColor DarkGreen
	# Stop-Service "lfsvc" -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
	# Set-Service "lfsvc" -StartupType Disabled -WarningAction SilentlyContinue
	
	$cmds=@(
		"Write-Host 'Disabling Location Tracking...' -ForegroundColor Green",
		"New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Force -WarningAction SilentlyContinue | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Type String -Value 'Deny' | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Type DWord -Value 0 | Out-Null",
		"Write-Host 'Disabling automatic Maps updates...' -ForegroundColor Green",
		"Set-ItemProperty -Path 'HKLM:\SYSTEM\Maps' -Name 'AutoUpdateEnabled' -Type DWord -Value 0 | Out-Null",
		"Write-Host 'Stopping and disabling Geolocation Service...' -ForegroundColor DarkGreen",
		"Stop-Service 'lfsvc' -WarningAction SilentlyContinue | Out-Null",
		"Set-Service 'lfsvc' -StartupType Disabled -WarningAction SilentlyContinue | Out-Null"
	)
	
	$currErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	ForEach ($cmd in $cmds) {
		If ($cmd -notlike "Write-Host*"){Write-Log $LogFile $cmd}
		try {
			Invoke-Expression $cmd
		}
		catch {
			Write-Log $LogFile " ERROR: $($_.Exception.Message)"
			$cmdError=$True
		}
		If ((!($cmdError)) -and ($cmd -notlike "Write-Host*")) {Write-Log $LogFile " Success"}
	}
	$ErrorActionPreference = $currErrorActionPreference
	
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-Feedback {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-Feedback"
	Write-Host ""
	Write-Host "Disable Feedback..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "The Windows feedback app in helps Microsoft understand what you think of " -ForegroundColor Yellow
		Write-Host "various features and what you might want to see in the future" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Microsoft Feedback, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	# New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force -WarningAction SilentlyContinue | Out-Null
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 | Out-Null
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 | Out-Null
	# Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	# Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force -WarningAction SilentlyContinue | Out-Null
	
	$cmds=@(
		"Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0 | Out-Null",
		"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1 | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Feedback\Siuf\DmClient' -ErrorAction SilentlyContinue | Out-Null",
		"Disable-ScheduledTask -TaskName 'Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload' -ErrorAction SilentlyContinue | Out-Null"
		
	)
	
	$currErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	ForEach ($cmd in $cmds) {
		If ($cmd -notlike "Write-Host*"){Write-Log $LogFile $cmd}
		try {
			Invoke-Expression $cmd
		}
		catch {
			Write-Log $LogFile " ERROR: $($_.Exception.Message)"
			$cmdError=$True
		}
		If ((!($cmdError)) -and ($cmd -notlike "Write-Host*")) {Write-Log $LogFile " Success"}
	}
	$ErrorActionPreference = $currErrorActionPreference
	
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-AdTargeting {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-AdTargeting"
	Write-Host ""
	Write-Host "Disable Tailored Experiences..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Tailored Experiences allows Microsoft to collect information from " -ForegroundColor Yellow
		Write-Host "you to deliver personalized tips, ads, and recommendations" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Tailored Experiences, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	# New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force -ErrorAction SilentlyContinue | Out-Null
	# Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    
	# Write-Host "Disabling Advertising ID..." -ForegroundColor Green
	# New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction SilentlyContinue | Out-Null
	# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1	
	
	$cmds=@ (
		"Write-Host 'Disabling Tailored Experiences...' -ForegroundColor Green",
		"Write-Host 'Setting DisableTailoredExperiencesWithDiagnosticData...' -ForegroundColor DarkGreen",
		"New-Item -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Force -ErrorAction SilentlyContinue | Out-Null",
		"Set-ItenProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Type DWord -Value 1 | Out-Null",

		"Write-Host 'Disabling AdvertisingInfo via Policy...' -ForegroundColor DarkGreen",
		"New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -ErrorAction SilentlyContinue | Out-Null",
		"Set-ItenProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1 | Out-Null"
	)
	
	$currErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	ForEach ($cmd in $cmds) {
		If ($cmd -notlike "Write-Host*"){Write-Log $LogFile $cmd}
		try {
			Invoke-Expression $cmd
		}
		catch {
			Write-Log $LogFile " ERROR: $($_.Exception.Message)"
			$cmdError=$True
		}
		If ((!($cmdError)) -and ($cmd -notlike "Write-Host*")) {Write-Log $LogFile " Success"}
	}
	$ErrorActionPreference = $currErrorActionPreference
	
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-WindowsP2PUpdates {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-WindowsP2PUpdates"
	Write-Host ""
	Write-Host "Disable Windows Update via P2P..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Windows Peer-to-Peer Updates share Windows updates with other computers on your " -ForegroundColor Yellow
		Write-Host "local network or with other computers over the Internet." -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Windows Peer-to-Peer Updates, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	######Left Off Here
	
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-RemoteAssistance {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-RemoteAssistance"
	Write-Host ""
	Write-Host "Disable Remote Assistance..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Windows Remote Assistance allows others to connect and fix a problem remotely" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Remote Assistance, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-OneDrive {	
	Param ([bool]$Confirm=$True)
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Microsoft OneDrive is a file hosting service and synchronization service" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable OneDrive, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Host "$MyCommand Skipped" 
		Write-Log $LogFile "$MyCommand Skipped"
		return
	}
	
	Write-Host "Disabling OneDrive..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Disabling OneDrive"
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")){
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
	
	Write-Host "Uninstalling OneDrive..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Uninstalling OneDrive"
	
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	
	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}

function Set-WindowsExplorerView {
	Param ([bool]$Confirm)
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "I prefer the following custom Windows Explorer settings:" -ForegroundColor Yellow
		Write-Host " Show Hidden Items and File Extensions, Hide the People Icon" -ForegroundColor Yellow
		Write-Host " Show all tray icons, Show Search icon, Use Dark Gray Desktop" -ForegroundColor Yellow
		Write-Host " Remove Microsoft Store icon, Use Windows Dark Mode Theme" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to set custom Windows Explorer Settings, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	Write-Host "Show Hidden Items and File Extensions" -ForegroundColor DarkGreen
	Write-Log $LogFile "Show Hidden Items and File Extensions"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
	
	Write-Host "Hiding People icon..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Hiding People icon"
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    
	Write-Host "Showing all tray icons..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Showing all tray icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	
	Write-Host "Showing Search icon..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Showing Search icon..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
	
	Write-Host "Setting Desktop to Dark Gray..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Setting Desktop to Dark Gray..."
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value ''
	Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name 'Background' -Value '76 74 72'
	
	Write-Host "Removing Microsoft Store icon..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Removing Microsoft Store icon..."
	$appname = "Microsoft Store"
	((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
	
	Write-Host "Enabling Dark Mode" -ForegroundColor DarkGreen
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
	
	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}

function Disable-CapsLock {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-CapsLock"
	Write-Host ""
	Write-Host "Disabling Caps Lock..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		$msg="Do you want to disable the Caps Lock key, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	$hexified = "00,00,00,00,00,00,00,00,02,00,00,00,2a,00,3a,00,00,00,00,00".Split(',') | % { "0x$_"}
	$kbLayout = 'HKLM:\System\CurrentControlSet\Control\Keyboard Layout'
	$keyName = "Scancode Map"
	if (!(Get-ItemProperty -Path $kbLayout -Name $keyName -ErrorAction SilentlyContinue)){
		New-ItemProperty -Path $kbLayout -Name $keyName -PropertyType Binary -Value ([byte[]]$hexified)
	}
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Enable-RDP {
	Param ([bool]$Confirm)
	
	##Needs to be reworked
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	Write-Host ""
	$msg="Do you want to Enable Remote Desktop, [Y]Yes, [N]No"
	choice /c yn /m $msg
	switch ($LASTEXITCODE){
		1 {$enableRDP=$True}
		2 {$enableRDP=$False}
	}
	
	If($enableRDP){
		Write-Progress -Activity "Setting Up Windows Environment" -Status "Enable-RDP"
		Write-Host "Enabling Remote Desktop Connection..." -ForegroundColor Green
		$installScript=((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/Set-RDP-Connection/main/Set-RDP-Connection.ps1'))
		$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($installScript)
		$ScriptArgs=@($False,$True)
		Invoke-Command $ScriptBlock -ArgumentList $ScriptArgs
	}
	Else {
		Write-Host ""
		$msg="Do you want to Disable RDP, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$disableRDP=$True}
			2 {$disableRDP=$False}
		}
		
		If($disableRDP){
			Write-Progress -Activity "Setting Up Windows Environment" -Status "Enable-RDP"
			Write-Host "Disabling Remote Desktop Connection..." -ForegroundColor Green
			$installScript=((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/Set-RDP-Connection/main/Set-RDP-Connection.ps1'))
			$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($installScript)
			$ScriptArgs=@($False,$False)
			Invoke-Command $ScriptBlock -ArgumentList $ScriptArgs	
		}
	}
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Install-Choco {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-Choco"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		Write-Host "Chocolatey has the largest online registry of Windows packages." -ForegroundColor Yellow
		Write-Host "Packages encapsulate everything required to manage a" -ForegroundColor Yellow
		Write-Host "particular piece of software into one deployment artifact by" -ForegroundColor Yellow
		Write-Host "wrapping installers, executables, zips, and/or scripts into a" -ForegroundColor Yellow
		Write-Host "compiled package file." -ForegroundColor Yellow
		Write-Host "Package submissions go through a rigorous moderation review" -ForegroundColor Yellow
		Write-Host "process, including automatic virus scanning. The community" -ForegroundColor Yellow
		Write-Host "repository has a strict policy on malicious and pirated software." -ForegroundColor Yellow
		Write-Host -NoNewLine "Read More: " -ForegroundColor Yellow
		Write-Host "https://chocolatey.org/" -ForegroundColor Blue
		Write-Host ""
		$msg="Do you want to install and setup the Windows Package Manager, Chocolatey, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped";return}
	
	Set-ExecutionPolicy Bypass -Scope Process -Force
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
	iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Install-BaseApps {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-BaseApps"
	Write-Host ""
	Write-Host "Installing Base Applications..." -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	$baseApps=@{
		#"choco-install-command"="Display Text";
		"7zip.install"="7 Zip";
		"choco-upgrade-all-at-startup"="Automatic Choco Updates at Startup";
		"firefox"="Firefox";
		"googlechrome"="Google Chrome";
		#"microsoft-edge"="Microsoft Edge";
		"microsoft-windows-terminal"="Windows Terminal";
		"notepadplusplus.install"="Notepad++";
		"signal"="Signal";
		"slack"="Slack";
		#"sysinternals"="Sysinternals";
		"vlc"="VLC Media Player";
		"vnc-viewer"="VNC Viewer Desktop Client";
		"zoom"="Zoom Cloud Meetings"
	}
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host -NoNewLine "Applications to install: " -ForegroundColor Yellow
		Write-Host $($baseApps.Values -join ", ") -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to install all of these applications using, Chocolatey, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	Write-Log $LogFile "Attempting to install: $($baseApps.Values -join ", ")"

	choco install $baseApps.keys -y

	Write-Log $LogFile "See $($env:ProgramData)\Chocolatey\logs\chocolatey.log for details"
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Install-Sysinternals {
	Param ([bool]$Confirm)
	
	If (Test-Path "$([Environment]::GetFolderPath('LocalApplicationData'))\Microsoft\WindowsApps\autoruns.exe"){return}
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm){
		Write-Host "Sysinternals Suite is a bundle of the utilities including: Process Explorer," -ForegroundColor Yellow
		Write-Host "Process Monitor, Sysmon, Autoruns, all of the PsTools, and many more" -ForegroundColor Yellow
		Write-Host -NoNewLine "Read More: " -ForegroundColor Yellow
		Write-Host "https://www.sysinternals.com" -ForegroundColor Blue
		Write-Host ""
		$msg="Do you want to install Microsoft's Sysinernals, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Host "$MyCommand Skipped" 
		Write-Log $LogFile "$MyCommand Skipped"
		return
	}

	Write-Host "Attempting to install 'sysinternals' via 'winget'" -ForegroundColor DarkGreen
	Write-Log $LogFile "Attempting to install 'sysinternals' via 'winget'"

	winget install sysinternals

	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}


##Not Added Yet
function Install-PowerToys {
	Param ([bool]$Confirm)
	
	If (Test-Path "$([Environment]::GetFolderPath('LocalApplicationData'))\Microsoft\WindowsApps\autoruns.exe"){return}
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm){
		Write-Host "Microsoft PowerToys is a set of utilities for power users to tune and streamline their Windows experience for greater productivity." -ForegroundColor Yellow
		Write-Host -NoNewLine "Read More: " -ForegroundColor Yellow
		Write-Host "https://docs.microsoft.com/en-us/windows/powertoys/" -ForegroundColor Blue
		Write-Host ""
		$msg="Do you want to install Microsoft's PowerToys, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Host "$MyCommand Skipped" 
		Write-Log $LogFile "$MyCommand Skipped"
		return
	}

	Write-Host "Attempting to install 'powertoys' via 'winget'" -ForegroundColor DarkGreen
	Write-Log $LogFile "Attempting to install 'powertoys' via 'winget'"

	winget install powertoys

	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}
##Not Added Yet

function Install-WindowsFirewallControl {
	Param ([bool]$Confirm=$True)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-WindowsFirewallControl?"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		$msg="Do you want to install Windows Firewall Control, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}

	$autoHotKeyInstalled=((choco list autohotkey.portable --localonly | Select-String "installed.").ToString().Trim()[0])
	if (($autoHotKeyInstalled -eq "0") -or ($autoHotKeyInstalled -eq 0)) {$removeAutoHotKey=$True}
	
	Write-Log $LogFile "Attempting to install Windows Firewall Control"
	choco install windowsfirewallcontrol -y

	If ($removeAutoHotKey){
		
		$autoHotKeyInstalled=((choco list autohotkey.portable --localonly | Select-String "installed.").ToString().Trim()[0])
		if (($autoHotKeyInstalled -ne "0") -and ($autoHotKeyInstalled -ne 0)) {
			Write-Log $LogFile "Attempting to uninstall autohotkey, used temporarily for Windows Firewall Control install"
			choco uninstall autohotkey.portable -force
		}
	}
	
	Write-Log $LogFile "See $($env:ProgramData)\Chocolatey\logs\chocolatey.log for details"
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"

}

function Install-OptionalApps {
	Param ([bool]$Confirm=$True)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-OptionalApps?"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	Write-Host ""	
	If($Confirm){Write-Host "Prompting for Optional Applications..." -ForegroundColor Green}
	
	$optionalApps=@{
		#"choco-install-command"="Display Text";
		"visualstudio2019community"="Visual Studio 2019 Community Edition";
		"github-desktop"="GitHub Desktop";
		"putty"="Putty";
		"winscp"="WinSCP";
		"python"="Python 3";
		"visualstudio2019-workload-python"="Python support in Visual Studio";
		"steam-client"="Steam";
		"goggalaxy"="GOG Galaxy";
		"bitvise-ssh-server"="Bitvise SSH Server";
		"discord"="Discord"
	}
	$installApps=@()
	
	If ($Confirm) {
		Write-Host -NoNewLine "Optional Applications: " -ForegroundColor Yellow
		Write-Host $($optionalApps.Values -join ", ") -ForegroundColor Yellow
		Write-Host ""
	}
	
	:foreach ForEach ($key in $optionalApps.keys) {
		
		If($Confirm){
			
			$msg="Install $($optionalApps[$key]), [Y]Yes, [N]No, [A]All, [Q]Quit/None"
			choice /c ynaq /m $msg
			
			switch($LASTEXITCODE){
				
				1 {$installApps += $key}
				2 {break}
				3 {
					""
					Write-Host "Do you want to install ALL optional applications:" -ForegroundColor Yellow
					Write-Host "    Note: You may have previously indicated No. 'All' overrides previous choices" -ForegroundColor Yellow
					$optionalApps.Values
					$msg="Install all, [Y]Yes, [N]No"
					choice /c yn /m $msg
					switch($LASTEXITCODE){
						1 {$installApps = $optionalApps.keys; break foreach}
						2 {break foreach}
					}
				}
				4 {break foreach}
			}
		}
		
		Else {$installApps = $optionalApps.keys}
	}
	
	If($installApps){
		Write-Log $LogFile "Attempting to install: $($installApps -join ", ")"
		choco install $installApps -y
		Write-Log $LogFile "See $($env:ProgramData)\Chocolatey\logs\chocolatey.log for details"
		Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
	}
	Else {
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Remove-UnwantedApps {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Remove-UnwantedApps"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	$UnwantedApps = @(
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
	    "Microsoft.BingFinance"
	    "Microsoft.BingNews"
	    "Microsoft.BingSports"
	    "Microsoft.BingTranslator"
	    "Microsoft.BingWeather"
        # "Microsoft.GetHelp"
        # "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
		"Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        # "Microsoft.StorePurchaseApp"
		"MicrosoftTeams*"
        "Microsoft.Wallet"
        # "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
		"Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
		"*Spotify*"
        "*Speed Test*"
        # "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
	)
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		Write-Host -NoNewLine "Applications to uninstall (if present): " -ForegroundColor Yellow
		Write-Host $($UnwantedApps -replace "\*","" -join ", ") -ForegroundColor Yellow
		Write-Host ""
		$msg="If present do you want to uninstall all of these applications [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	
    foreach ($App in $UnwantedApps) {
        Get-AppxPackage -Name $App| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
        Write-Host "If present, removing $App." -ForegroundColor DarkGreen
		Write-Log $LogFile "If present, removing $App."
    }
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-EdgeDefaults {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-EdgeDefaults"
	Write-Host ""
    Write-Host "Stopping Edge from taking over as the default application" -ForegroundColor Green
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		$msg="Do you want to disable Edge from being the default application for URLs and HTML files [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	
	$Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
	$edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
		
	$FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
	$URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
		
	$FileTypes = Get-Item $FileAssocKey 
	$URLTypes = Get-Item $URLAssocKey 
		
	$FileAssoc = Get-ItemProperty $FileAssocKey 
	$URLAssoc = Get-ItemProperty $URLAssocKey 
		
	$Associations = @() 
	$Filetypes.Property | foreach {$Associations += $FileAssoc.$_} 
	$URLTypes.Property | foreach {$Associations += $URLAssoc.$_} 
		
	foreach ($Association in $Associations) { 
		$Class = Join-Path HKCU:SOFTWARE\Classes $Association 
		Set-ItemProperty $Class -Name NoOpenWith -Value "" 
		Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
	}
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-Cortana {
	Param ([bool]$Confirm=$True)
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm) {
		Write-Host "Cortana is a virtual assistant developed by Microsoft. Cortana uses the Bing " -ForegroundColor Yellow
		Write-Host " search engine to perform tasks such as setting reminders and answering questions" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to disable Cortana, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Host "$MyCommand Skipped" 
		Write-Log $LogFile "$MyCommand Skipped"
		return
	}
	
	Write-Host "Disabling Cortana..." -ForegroundColor DarkGreen
	Write-Log $LogFile "Disabling Cortana"
	
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	
	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}

function Disable-UnusedServices {
	Param ([bool]$Confirm=$False)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-UnusedServices?"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If($Confirm){Write-Host "Prompting to disable Windows Services..." -ForegroundColor Green}
	
	$targetedSvcs=@{
		"LanmanWorkstation"="Workstation:`n Allows a system to request file and print resources from other systems over the network.";#Default is Auto
		"LanmanServer"="Server:`n Allows a system to share file and print resources with other systems over the network";#Default is Auto
		"Spooler"="Print Spooler:`n Spools print jobs and handles interaction with the printer.`n Note: If you turn off this service, you won't be able to print.";#Default is Auto
		"RemoteRegistry"="Remote Registry:`n Enables remote users to modify registry settings on this computer";#Default is Manual
		"Fax"="Fax:`n Enables you to send and receive faxes.";#Default is Manual
		"MapsBroker"="Downloaded Maps Manager:`n Windows service for application access to downloaded maps.";#Default is Auto
		#"Wcmsvc"="Windows Connection Manager:`n Makes automatic connect/disconnect decisions based on the network connectivity options currently available";#Default is Auto
		"SCardSvr"="Smart Card:`n Manages access to smart cards read by this computer.";#Default is Manual
		"RetailDemo"="Retail Demo Service:`n Service controls device activity while the device is in retail demo mode.";#Default is Manual
		"WMPNetworkSvc"="Windows Media Player Network Sharing Service:`n Shares Windows Media Player libraries to other networked devices.";#Default is Manual
		"AJRouter"="AllJoyn Router Service:`n Routes AllJoyn messages for the local AllJoyn clients.";#Default is Manual
		"lfsvc"="Geolocation Service:`n Monitors the current location of the system.";#Default is Manual <- But starts automatically
		"WbioSrvc"="Windows Biometric Service:`n Allows applications the ability to use biometric data.`n Note: This service is required for Windows Hello.";#Default is Manual <- But starts automatically
		"lmhosts"="TCP/IP NetBIOS Helper:`n Provides support for NetBIOS name resolution, file sharing and printing.`n Note: If this service is stopped, these functions will be unavailable.";#Default is Manual <- But starts automatically
		"EFS"="Encrypting File System:`n Legacy file encryption technology used to store encrypted files on volumes.`n Note: This service is not related to BitLocker";#Default is Manual <- But starts automatically
	}
	$disableSvcs=@()
	
	If($Confirm) {
		:foreach ForEach ($key in $targetedSvcs.keys) {
			If (isServiceEnabled $key){
				Write-Host ""
				$msg="$($targetedSvcs[$key])`nDisable $($targetedSvcs[$key].Split(':')[0]), [Y]Yes, [N]No, [A]All, [Q]Quit/None"
				#$msg="Disable $($targetedSvcs[$key]), [Y]Yes, [N]No, [A]All, [Q]Quit/None"
				choice /c ynaq /m $msg
				
				switch($LASTEXITCODE){
					
					1 {$disableSvcs += $key}
					2 {break}
					3 {
						""
						Write-Host "Do you want to disable ALL targeted Windows Services:" -ForegroundColor Yellow
						Write-Host "    Note: You may have previously indicated No. 'All' overrides previous choices" -ForegroundColor Yellow
						$targetedSvcs.values
						$msg="Disable all, [Y]Yes, [N]No"
						choice /c yn /m $msg
						switch($LASTEXITCODE){
							1 {$disableSvcs = $targetedSvcs.keys; break foreach}
							2 {break foreach}
						}
					}
					4 {break foreach}
				}
			}
		}
	}
	Else {$disableSvcs = $targetedSvcs.keys}
	
	
	If($disableSvcs){
		foreach ($Svc in $disableSvcs) {
			Write-Host "Stopping and disabling $($targetedSvcs[$Svc].Split(':')[0]) service..." -ForegroundColor DarkGreen
			Write-Log $LogFile "Stopping and disabling $($targetedSvcs[$Svc].Split(':')[0]) service"
			Stop-Service $Svc -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
			Set-Service $Svc -StartupType Disabled -WarningAction SilentlyContinue
		}
	}
	Else {
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	if (($disableSvcs -contains "LanmanWorkstation") -and ($disableSvcs -contains "LanmanServer")) {Disable-WindowsFileSharing}
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Disable-WindowsFileSharing {
	#Called from Disable-UnusedServices if "Workstation" and "Server" services are set to disable
	
	Write-Host "Disabling Windows File Sharing..." -ForegroundColor DarkGreen
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	Get-NetAdapterBinding -DisplayName "Client for Microsoft Networks" | % {Disable-NetAdapterBinding -Name $_.Name -ComponentID $_.ComponentID}
	Get-NetAdapterBinding -DisplayName "File and Printer Sharing for Microsoft Networks" | % {Disable-NetAdapterBinding -Name $_.Name -ComponentID $_.ComponentID}
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Remove-Links {
	Param ([bool]$Confirm)
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm) {
		Write-Host "I prefer a clean Windows Desktop" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to remove all shortcuts on Windows Desktop [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped";return}
	
	Write-Host "Removing Links on Desktop..." -ForegroundColor Green
	$userDesktop=[Environment]::GetFolderPath("Desktop")
	Remove-Item "$userDesktop\*.lnk"
	$commonDesktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
	Remove-Item "$commonDesktop\*.lnk"
	
	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}

function Set-SecuritySettings {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Set-SecuritySettings"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		Write-Host "Security Settings:" -ForegroundColor Yellow
		Write-Host "Raise UAC level to highest, Disable SMB 1.0 & 2.0, Enable Windows Defender Cloud" -ForegroundColor Yellow
		Write-Host "Disable Windows Script Host, Enable Meltdown Compatibility Flag" -ForegroundColor Yellow
		Write-Host "Block All Incoming Traffic & Explicitly Block Incoming Traffic for WiFi Adapters" -ForegroundColor Yellow
		Write-Host "Enable Reputation-based Protection, Disable NetBIOS On All Present Adapters" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to apply all of theses security settings [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
	
	Write-Host "Raising UAC level..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
    
	Write-Host "Disabling SMB 1.0 & 2.0 Protocol..." -ForegroundColor Green
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
    
	Write-Host "Enabling Windows Defender Cloud..." -ForegroundColor Green
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
    
	Write-Host "Disabling Windows Script Host..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
	
    Write-Host "Enabling Meltdown (CVE-2017-5754) compatibility flag..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0

	Write-Host "Firewall: Block All Incoming Connections..." -ForegroundColor Green
	Set-NetFirewallProfile -All -Enabled True
	Set-NetFirewallProfile -All -DefaultInboundAction Block
	Set-NetFirewallProfile -All -AllowInboundRules False #May need to be reversed for WSL support via GUI. Settings > Windows Security > Domain/Private/Public > Uncheck Block all incoming connections, including those in the list of allowed apps
	New-NetFirewallRule -DisplayName "Block All Inbound on Wireless Adapters" -Direction Inbound -InterfaceType Wireless -Action Block  | Out-Null #Redundant BUT works with WSL
	
	Write-Log $LogFile " Set-NetFirewallProfile -All -Enabled True"
	Write-Log $LogFile " Set-NetFirewallProfile -All -DefaultInboundAction Block"
	Write-Log $LogFile " Set-NetFirewallProfile -All -AllowInboundRules False"
	Write-Log $LogFile " 	WARNING: Setting may need to be reversed for Windows Subsystem for Linux (WSL) support. Settings > Windows Security > Domain/Private/Public > Uncheck Block all incoming connections, including those in the list of allowed apps"
	Write-Log $LogFile " New-NetFirewallRule -DisplayName "Block All Inbound on Wireless Adapters" -Direction Inbound -InterfaceType Wireless -Action Block "
	Write-Log $LogFile " 	NOTE: This rule is redundant but is compatible with WSL"
	
	Write-Host "Enabling Reputation-based Protection..." -ForegroundColor Green
	Set-MpPreference -PUAProtection Enabled
	
	Write-Host "Disable NetBIOS On All Present Adapters..." -ForegroundColor Green
	$i = 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces'  
	Get-ChildItem $i | ForEach-Object {  
		Set-ItemProperty -Path "$i\$($_.pschildname)" -name NetBiosOptions -value 2}
	(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled="true").SetTcpipNetbios(2) | Out-Null
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Set-WindowsUpdateSettings {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Setting Microsoft Update Settings" -Status "Set-WindowsUpdateSettings"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		$msg="Do you want to enable Microsoft Product Updates, to run every day at 3:00AM [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
		
	Write-Host "Enabling Windows Updates for other Microsoft products..." -ForegroundColor Green
	$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
	$ServiceManager.ClientApplicationID = "My App"
	$NewService = $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
	
	Write-Host "Setting updates to run every day at 3:00 AM..." -ForegroundColor Green
	$AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
	$AUSettings.NotificationLevel=4
	$AUSettings.ScheduledInstallationDay=0
	$AUSettings.ScheduledInstallationTime=3
	$AUSettings.IncludeRecommendedUpdates=$True
	$AUSettings.Save()
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

function Set-RepositorySettings{
	Param ([bool]$Confirm)
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If ($Confirm) {
		Write-Host "The PowerShell Gallery is the central repository for PowerShell content." -ForegroundColor Yellow
		Write-Host "In it, you can find useful PowerShell modules containing PowerShell commands and other resources" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to install the NuGet package provider and trust Microsoft's PSGallery repository [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Host "$MyCommand Skipped" 
		Write-Log $LogFile "$MyCommand Skipped"
		return
	}
	
	Write-Host "Setting PSGallery Repository to Trusted" -ForegroundColor DarkGreen
	Install-PackageProvider -Name NuGet -Force | Out-Null
	Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
	
	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
}

function Get-WindowsUpdates {
	Param ([bool]$Confirm)
	
	Write-Progress -Activity "Get Microsoft Updates" -Status "Get-WindowsUpdates"
	Write-Log $LogFile "$($MyInvocation.MyCommand)"
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host ""
		$msg="Do you want to install the PSWindowsUpdate PowerShell module, and install all Microsoft Updates [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Log $LogFile "$($MyInvocation.MyCommand) Skipped"
		return
	}
		
	Write-Host "Getting Microsoft Updates" -ForegroundColor Green
	Install-Module PSWindowsUpdate -Force
	Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install
	Write-Log $LogFile "$($MyInvocation.MyCommand) Completed"
}

###Unused Functions/Features - may re-add later
# function Encrypt-System {
	# Param([bool]$Confirm=$False)
	
	# Write-Progress -Activity "Setting Up Windows Environment" -Status "Encrypt-System"
	
	# [bool]$Encrypt=$True
	# If($Confirm){
		# If((gwmi win32_computersystem -ea 0).pcsystemtype -ne 2){#If Desktop then prompt
			# Write-Host ""
			# $msg="Do you want to encrypt this desktop system, [Y]Yes, [N]No"
			# choice /c yn /m $msg
			# switch ($LASTEXITCODE){
				# 1 {$Encrypt=$True;break}
				# 2 {$Encrypt=$False;break}
			# }
		# }
	# }
	
	# If ($Encrypt){
		# $SystemDrive=[Environment]::GetEnvironmentVariable("SystemDrive")
		# Enable-BitLocker -MountPoint $SystemDrive -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector
		##Lock-BitLocker -MountPoint $SystemDrive
	# }
# }
###End Unused Functions/Features - may re-add later

function Rename-System {
	Param ([bool]$Confirm=$True, [string]$NewName)
	
	##Needs to be fixed for the event that someone does not want to rename the system
	##Confirm= False, Rename=NULL, Skip
	
	[string]$MyCommand=$($MyInvocation.MyCommand)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
	Write-Host ""
	Write-Host "$MyCommand" -ForegroundColor Green
	Write-Log $LogFile "$MyCommand"
	
	If($NewName){
		$Confirm=$False
	}
	
	If ($Confirm) {
		$Proceed=$False
		Write-Host "Current computer name: $(hostname)" -ForegroundColor Yellow
		Write-Host ""
		$msg="Do you want to rename this computer, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$Proceed=$True}
			2 {$Proceed=$False}
		}
	}
	Else {$Proceed=$True}
	If (!($Proceed)){
		Write-Host "$MyCommand Skipped" 
		Write-Log $LogFile "$MyCommand Skipped"
		return
	}
	
	If(!($NewName)){
		$NewName=Read-Host("Enter New Computer Name")
	}
	

	Write-Progress -Activity "Renaming Computer" -Status "New Name: $NewName"
	Write-Host "Renaming Computer to $NewName..." -ForegroundColor Green
	Write-Log $LogFile "Rename Computer to $NewName..."
	Rename-Computer -NewName $NewName -Restart $False
	Write-Host "$MyCommand Completed" -ForegroundColor DarkGreen
	Write-Log $LogFile "$MyCommand Completed"
	# Write-Host ""
	# $msg="Do you want to rename this computer, [Y]Yes, [N]No"
	# choice /c yn /m $msg
	# switch ($LASTEXITCODE){
		# 1 {$rename=$True}
		# 2 {$rename=$False}
	# }
	
	
	
	# If($rename){
		
		# $NewName=Read-Host("Enter New Computer Name")
		
		# If ($NewName){
			# Rename-Computer -NewName $NewName 
			# Write-Progress -Activity "Renaming Computer" -Status "New Name: $NewName"
			# Write-Host "Renaming Computer to $NewName..." -ForegroundColor Green
		# }
		# Else{
			# $rename=$False
		# }
	# }
	# If (!$rename) {
		# Write-Progress -Activity "Skipping Renaming Computer" -Status "Name: $(hostname)"
	# }
}

##Main##

$localAdmin=isAdmin
$internetAccess=isConnectedToInternet

If($localAdmin -and $internetAccess) {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Starting"
	
	$ScriptName=$MyInvocation.MyCommand.Name
	If (!($ScriptName)){$ScriptName="Setup-WindowsEnvironment.ps1"}
	
	# $ScriptPath=Split-Path $($MyInvocation.MyCommand.Path) -Parent -ErrorAction SilentlyContinue
	# $ScriptName=$MyInvocation.MyCommand.Name
	# If (!($ScriptName)){$ScriptName="Setup-WindowsEnvironment.ps1"}
	
	If (!($LogFile)){
		#If (!($ScriptName)){$ScriptName="Setup-WindowsEnvironment.ps1"}
		#$LogFile="$env:SystemDrive\$($(Get-Date).ToString("yyyyMMddHHmm"))_$($ScriptName)" -replace "ps1","txt"
		$LogFile="$env:SystemDrive\$($ScriptName)" -replace "ps1","txt"
	}
	
	Write-Log $LogFile "Start: $ScriptName"
	
	Create-RestorePoint
	Set-Profile $ConfirmSetProfile
	Disable-Telemetry $ConfirmDisableTelemetry
	Disable-ApplicationSuggestions $ConfirmDisableApplicationSuggestions
	Disable-ActivityHistory $ConfirmDisableActivityHistory
	Disable-LocationTracking $ConfirmDisableLocationTracking
	Disable-Feedback $ConfirmDisableFeedback
	Disable-AdTargeting $ConfirmDisableAdTargeting
	Disable-WindowsP2PUpdates $ConfirmDisableWindowsP2PUpdates
	Disable-RemoteAssistance $ConfirmDisableRemoteAssistance
	Disable-CapsLock $ConfirmDisableCapsLock
	##Chocolatey Installations
	Install-Choco $ConfirmInstallChoco
		If(isChocoInstalled) {
			Install-BaseApps $ConfirmInstallBaseApps
			Install-WindowsFirewallControl $ConfirmWindowsFirewallControl
			Install-OptionalApps $ConfirmInstallOptionalApps
		}
		Else{
			Write-Progress -Activity "Setting Up Windows Environment" -Status "Skipping Chocolatey Installations"
			Write-Host "Chocolatey application installations were skipped, Chocolatey has not been installed" -ForegroundColor Yellow
			#
		}
	##End Chocolatey Installations
	Install-Sysinernals $ConfirmInstallSysinternals
	Remove-UnwantedApps $ConfirmRemoveUnwantedApps
	Disable-EdgeDefaults $ConfirmDisableEdgeDefaults
	Set-SecuritySettings $ConfirmSetSecuritySettings
	Set-WindowsUpdateSettings $ConfirmSetWindowsUpdateSettings
	Enable-RDP $ConfirmEnableRDP
	Disable-UnusedServices $ConfirmDisableUnusedServices
	Disable-OneDrive $ConfirmDisableOneDrive
	Disable-Cortana $ConfirmDisableCortana
	Set-WindowsExplorerView $ConfirmSetWindowsExplorerView
	Remove-Links $ConfirmRemoveLinks
	# Encrypt-System $ConfirmEncryptDesktop #Not fully functional/Up to par
	Set-RepositorySettings $ConfirmSetRepositorySettings
	If (isPSGalleryTrusted){ Get-WindowsUpdates $ConfirmGetWindowsUpdates }
	Rename-System -NewName $NewComputerName
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Complete"
	Write-Host "Complete" -ForegroundColor Cyan
	Write-Log $LogFile "End: $ScriptName"
	
	If ($ConfirmRestart) {
		[string]$MyCommand="ConfirmRestart")
		Write-Progress -Activity "Setting Up Windows Environment" -Status "$MyCommand"
		Write-Host ""
		Write-Host "$MyCommand" -ForegroundColor Green
	
		Write-Host "$ScriptName has completed. Changes may require a restart" -ForegroundColor Yellow
		Write-Host ""
		$msg="Restart computer now, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {Restart-Computer}
			2 {break}
		}
	}
	
}
Else {
	If(!($localAdmin)){
		Write-Host ""
		Write-Error -Message "ERROR: Administrator permissions are required to make requested changes." -Category PermissionDenied
	}
	If(!($internetAccess)){
		Write-Host ""
		Write-Error -Message "ERROR: Unable to determine internet access." -Category ConnectionError
	}
}

##End Main##


