#powershell.exe


# Written by: Aaron Wurthmann
#
# You the executor, runner, user accept all liability.
# This code comes with ABSOLUTELY NO WARRANTY.
# You may redistribute copies of the code under the terms of the GPL v3.
#
# --------------------------------------------------------------------------------------------
# Name: Setup-WindowsEnvironment.ps1
# Version: 2021.03.12.101001
# Description: Setup Windows Enviroment on new System
# 
# Instructions: Run from PowerShell with Administrator permissions and Set-ExecutionPolicy Bypass -Scope Process -Force
#	
# Tested with: Microsoft Windows [Version 10.0.19042.804], PowerShell [Version 5.1.19041.610]
# Arguments: None
# Output: Standard Out
#
# Notes:  
# --------------------------------------------------------------------------------------------

Param (
	[bool]$ConfirmWindowsFirewallControl=$True,
	[bool]$ConfirmDisableCortana=True,
	[bool]$ConfirmDisableOneDrive=True,
	[bool]$ConfirmUnusedServices=$True,
	[bool]$ConfirmOptionalApps=$True,
	[bool]$ConfirmEncryptDesktop=$True
)

function isAdmin {
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Create-RestorePoint {
	Write-Host "Creating Restore Point..." -ForegroundColor Green
    Enable-ComputerRestore -Drive $env:SystemDrive
    Checkpoint-Computer -Description "RP: $(Get-Date -Format yyyyMMdd-HHmmssfff:TK)" -RestorePointType "MODIFY_SETTINGS"
}

function Set-Profile {
	Write-Host "Setting Profile..." -ForegroundColor Green
	iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/my-powershell-profile/main/Set-Profile.ps1'))
}

function Disable-Telemetry {
	Write-Host "Disabling Telemetry..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled -WarningAction SilentlyContinue
}

function Disable-ApplicationSuggestions {
	Write-Host "Disabling Application Suggestions..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

function Disable-ActivityHistory {
	Write-Host "Disabling Activity History..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

function Disable-LocationTracking {
	Write-Host "Disabling Location Tracking..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")){
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

	Write-Host "Disabling automatic Maps updates..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

function Disable-Feedback {
	Write-Host "Disabling Feedback..." -ForegroundColor Green
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

function Disable-AdTargeting {
	Write-Host "Disabling Tailored Experiences..." -ForegroundColor Green
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    
	Write-Host "Disabling Advertising ID..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

function Disable-WindowsP2PUpdates {
	Write-Host "Disable Windows Update via P2P..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
}

function Disable-RemoteAssistance {
	Write-Host "Disabling Remote Assistance..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

function Disable-OneDrive {
	Write-Host "Disabling OneDrive..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")){
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    Write-Host "Uninstalling OneDrive..."
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
	$wshell.Popup("Operation Completed",0,"Done",0x0)
}

function Set-WindowsExplorerView {
	Write-Host "Show Hidden Items and File Extenctions" -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
	
	Write-Host "Hiding People icon..." -ForegroundColor Green
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    
	Write-Host "Showing all tray icons..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	
	Write-Host "Enabling Dark Mode" -ForegroundColor Green
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
}

function Disable-CapsLock {
	Write-Host "Disabling Caps Lock..." -ForegroundColor Green
	$hexified = "00,00,00,00,00,00,00,00,02,00,00,00,2a,00,3a,00,00,00,00,00".Split(',') | % { "0x$_"}
	$kbLayout = 'HKLM:\System\CurrentControlSet\Control\Keyboard Layout'
	$keyName = "Scancode Map"
	if (!(Get-ItemProperty -Path $kbLayout -Name $keyName -ErrorAction SilentlyContinue)){
		New-ItemProperty -Path $kbLayout -Name $keyName -PropertyType Binary -Value ([byte[]]$hexified)}
}

function Enable-RDP {
	Write-Host "Enabling Remote Desktop Connection..." -ForegroundColor Green
	$installScript=((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/Set-RDP-Connection/main/Set-RDP-Connection.ps1'))
	$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($installScript)
	$ScriptArgs=@($False,$True)
	Invoke-Command $ScriptBlock -ArgumentList $ScriptArgs
}

function Install-Choco {
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function Install-BaseApps {
	Write-Host "Installing Base Applications..." -ForegroundColor Green
	$baseApps = @(
		"7zip.install",
		"choco-upgrade-all-at-startup",
		"discord",
		"firefox",
		"googlechrome",
		"microsoft-edge",
		"microsoft-windows-terminal",
		"notepadplusplus.install",
		"signal",
		"slack",
		"sysinternals",
		"vlc",
		"vnc-viewer",
		"zoom"
	)
	
	choco install $baseApps -y
}

function Install-WindowsFirewallControl {
	$autoHotKeyInstalled=((choco list autohotkey.portable --localonly | Select-String "installed.").ToString().Trim()[0])
	if (($autoHotKeyInstalled -eq "0") -or ($autoHotKeyInstalled -eq 0)) {$removeAutoHotKey=$True}
	
	choco install windowsfirewallcontrol -y
	
	If ($removeAutoHotKey){
		$autoHotKeyInstalled=((choco list autohotkey.portable --localonly | Select-String "installed.").ToString().Trim()[0])
		if (($autoHotKeyInstalled -ne "0") -and ($autoHotKeyInstalled -ne 0)) {choco uninstall autohotkey.portable -force}
	}
}

function Install-OptionalApps {
	Param ([bool]$Confirm=$True)
	
	If($Confirm){Write-Host "Prompting for Optional Applications..." -ForegroundColor Green}
	
	$optionalApps=@{
		"visualstudio2019community"="Visual Studio 2019 Community Edition";
		"github-desktop"="GitHub Desktop";
		"putty"="Putty";
		"winscp"="WinSCP";
		"python"="Python 3";
		"visualstudio2019-workload-python"="Python support in Visual Studio";
		"steam-client"="Steam";
		"goggalaxy"="GOG Galaxy"
	}
	$installApps=@()
	
	ForEach ($key in $optionalApps.keys) {
		
		If($Confirm){
			$msg="Install $($optionalApps[$key]), [Y]es, [N]o, [A]ll, [Q]uit/None"
			choice /c ynaq /m $msg
			
			switch($LASTEXITCODE){
				
				1 {$installApps += $key}
				2 {break}
				3 {
					""
					Write-Host "Do you want to install ALL optional applications:" -ForegroundColor Yellow
					Write-Host "    Note: You may have previously indicated No. 'All' overrides previous choices" -ForegroundColor Yellow
					$optionalApps.values
					$msg="Install all, [Y]es, [N]o"
					choice /c yn /m $msg
					switch($LASTEXITCODE){
						1 {$installApps = $optionalApps.keys; break loop}
						2 {break}
					}
				}
				4 {break loop}
			}
		}
		
		Else {$installApps = $optionalApps.keys}
	}
	
	If($installApps){choco instal $installApps -y}
	
}

function Remove-UnwantedApps {
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
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        # "Microsoft.StorePurchaseApp"
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
	
    foreach ($App in $UnwantedApps) {
        Get-AppxPackage -Name $App| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $App."
    }
	
}

function Disable-EdgeDefaults {
    Write-Host "Stopping Edge from taking over as the default application" -ForegroundColor Green
	
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
}

function Disable-Cortana {
	Write-Host "Disabling Cortana..." -ForegroundColor Green
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
}

function Disable-UnusedServices {
	Param ([bool]$Confirm=$False)
	
	If($Confirm){Write-Host "Prompting to disable Windows Services..." -ForegroundColor Green}
	
	$targetedSvcs=@{
		"LanmanWorkstation"="Workstation";#Default is Auto
		"LanmanServer"="Server";#Default is Auto
		"Spooler"="Print Spooler";#Default is Auto
		"RemoteRegistry"="Remote Registry";#Default is Manual
		"Fax"="Fax";#Default is Manual
		"MapsBroker"="Downloaded Maps Manager";#Default is Auto
		#"Wcmsvc"="Windows Connection Manager";#Default is Auto
		"SCardSvr"="Smart Card";#Default is Manual
		"RetailDemo"="Retail Demo Service";#Default is Manual
		"WMPNetworkSvc"="Windows Media Player Network Sharing Service";#Default is Manual
		"AJRouter"="AllJoyn Router Service";#Default is Manual
		"lfsvc"="Geolocation Service";#Default is Manual <- But starts automaticly
		"WbioSrvc"="Windows Biometric Service";#Default is Manual <- But starts automaticly
		"EFS"="Encrypting File System (EFS - Not BitLocker)";#Default is Manual <- But starts automaticly
	}
	$disableSvcs=@()
	
	ForEach ($key in $targetedSvcs.keys) {
		
		If($Confirm){
			$msg="Disable $($targetedSvcs[$key]), [Y]es, [N]o, [A]ll, [Q]uit/None"
			choice /c ynaq /m $msg
			
			switch($LASTEXITCODE){
				
				1 {$disableSvcs += $key}
				2 {break}
				3 {
					""
					Write-Host "Do you want to disable ALL targeted Windows Services:" -ForegroundColor Yellow
					Write-Host "    Note: You may have previously indicated No. 'All' overrides previous choices" -ForegroundColor Yellow
					$targetedSvcs.values
					$msg="Disable all, [Y]es, [N]o"
					choice /c yn /m $msg
					switch($LASTEXITCODE){
						1 {$disableSvcs = $targetedSvcs.keys; break loop}
						2 {break}
					}
				}
				4 {break loop}
			}
		}
		
		Else {$disableSvcs = $targetedSvcs.keys}
	}
	
	If($disableSvcs){
		foreach ($Svc in $disableSvcs) {
			Write-Host "Stopping and disabling $($targetedSvcs[$Svc]) service..."
			Stop-Service $Svc -WarningAction SilentlyContinue
			Set-Service $Svc -StartupType Disabled -WarningAction SilentlyContinue
		}
	}

	
}

function Remove-Links {
	Write-Host "Removing Links on Desktop..." -ForegroundColor Green
	$userDesktop=[Environment]::GetFolderPath("Desktop")
	Remove-Item "$userDesktop\*.lnk"
	$commonDesktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
	Remove-Item "$commonDesktop\*.lnk"
}

function Set-SecuritySettings {
	Write-Host "Raising UAC level..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
    
	Write-Host "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    
	Write-Host "Enabling Windows Defender Cloud..." -ForegroundColor Green
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
    
	Write-Host "Disabling Windows Script Host..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
	
    Write-Host "Enabling Meltdown (CVE-2017-5754) compatibility flag..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

function Encrypt-System {
	Param([bool]$Confirm=$False)
	
	[bool]$Encrypt=$False
	If($Confirm){
		If((gwmi win32_computersystem -ea 0).pcsystemtype -ne 2){#If Desktop then prompt
			Write-Host ""
			$msg="Do you want to encrypt this desktop system, [Y]es, [N]o"
			choice /c yn /m $msg
			switch ($LASTEXITCODE){
				1 {$Encrypt=$True;break}
				2 {$Encrypt=$False;break}
			}
		}
	}
	Else {
		$Encrypt=$True
	}
	
	If ($Encrypt){
		
	}
}

##Main##
If(isAdmin) {
	Create-RestorePoint
	Set-Profile 
	Disable-Telemetry
	Disable-ApplicationSuggestions
	Disable-ActivityHistory
	Disable-LocationTracking
	Disable-Feedback
	Disable-AdTargeting
	Disable-WindowsP2PUpdates
	Disable-RemoteAssistance
	Set-WindowsExplorerView 
	Disable-CapsLock
	Enable-RDP	#TD: Comeback to this one, maybe it should be full script with options
	Install-Choco
	Install-BaseApps
	Install-WindowsFirewallControl#TD: Make Confirmable
	Install-OptionalApps $ConfirmOptionalApps
	Remove-UnwantedApps
	Disable-EdgeDefaults
	Set-SecuritySettings
	Disable-UnusedServices $ConfirmUnusedServices
	Remove-Links
	Encrypt-System $ConfirmEncryptDesktop
	
	#TD: Determine how you want to prompt for confirm
	
	# [bool]$ConfirmWindowsFirewallControl=$True,
	# [bool]$ConfirmDisableCortana=True,
	# [bool]$ConfirmDisableOneDrive=True,
	# [bool]$ConfirmUnusedServices=$True,
	# [bool]$ConfirmOptionalApps=$True
	
	
	
	If ($Silent) {
		If ($DisableCortana) {Disable-Cortana}#Confirmable
		If ($DisableOneDrive) {Disable-OneDrive}#Confirmable
	}
	Else {
		Write-Host ""
		$msg="Do you want to uninstall OneDrive, [Y]es, [N]o"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {Disable-OneDrive}
			2 {break}
		}
		
		Write-Host ""
		$msg="Do you want to remove Cortana, [Y]es, [N]o"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {Disable-Cortana}
			2 {break}
		}
	}
	
	Write-Host "Complete" -ForegroundColor Cyan
}
Else {
	Write-Error -Message "
ERROR: Administrator permissions are required to make requested changes." -Category PermissionDenied
}
##End Main##
