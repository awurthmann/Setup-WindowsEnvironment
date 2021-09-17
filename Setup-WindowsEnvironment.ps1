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
# Version: 2021.08.27.1712
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
	[bool]$ConfirmWindowsFirewallControl=$True,
	[bool]$ConfirmDisableCortana=$True,
	[bool]$ConfirmDisableOneDrive=$True,
	[bool]$ConfirmUnusedServices=$True,
	[bool]$ConfirmOptionalApps=$True,
	[bool]$ConfirmEncryptDesktop=$True,
	[bool]$ConfirmRestart=$True
)

function isAdmin {
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function isConnectedToInternet {
	Param ([string]$RemoteHost="www.google.com")
	return (Test-NetConnection -ComputerName $RemoteHost -Port 443).TcpTestSucceeded
}

###Unused Service Related Functions
# function isServiceRunning {
	# Param ([string]$ServiceName)
	# Return $(Get-Service $ServiceName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).Status -eq "Running"
# }

# function isServiceEnabled {
	# Param ([string]$ServiceName)
	
	# $Service=Get-Service $ServiceName -ErrorAction SilentlyContinue
	# If($Service){
		# return $($ServiceName | Select -Property StartType -ErrorAction SilentlyContinue).StartType -ne "Disabled"
	# }
	# Else{
		# return $False
	# }
	
# }
###End Unused Service Related Functions

function Create-RestorePoint {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Create-RestorePoint"
	Write-Host "Creating Restore Point..." -ForegroundColor Green
    Enable-ComputerRestore -Drive $env:SystemDrive
    Checkpoint-Computer -Description "RP: $(Get-Date -Format yyyyMMdd-HHmmssfff:TK)" -RestorePointType "MODIFY_SETTINGS"
}

function Set-Profile {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Set-Profile"
	Write-Host "Setting Profile..." -ForegroundColor Green
	iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/my-powershell-profile/main/Set-Profile.ps1'))
	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
}

function Disable-Telemetry {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-Telemetry"
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
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-ApplicationSuggestions"
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
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-ActivityHistory"
	Write-Host "Disabling Activity History..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

function Disable-LocationTracking {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-LocationTracking"
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
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-Feedback"
	Write-Host "Disabling Feedback..." -ForegroundColor Green
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

function Disable-AdTargeting {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-AdTargeting"
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
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-WindowsP2PUpdates"
	Write-Host "Disable Windows Update via P2P..." -ForegroundColor Green
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
}

function Disable-RemoteAssistance {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-RemoteAssistance"
	Write-Host "Disabling Remote Assistance..." -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

function Disable-OneDrive {
	Param ([bool]$Confirm=$True)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-OneDrive?"
	
	If ($Confirm) {
		$disableOneDrive=$False
		Write-Host ""
		$msg="Do you want to disable OneDrive, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$disableOneDrive=$True}
			2 {$disableOneDrive=$False}
		}
	}
	Else {$disableOneDrive=$True}
	
	If ($disableOneDrive) {
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
	}
}

function Set-WindowsExplorerView {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Set-WindowsExplorerView"
	Write-Host "Show Hidden Items and File Extensions" -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
	
	Write-Host "Hiding People icon..." -ForegroundColor Green
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    
	Write-Host "Showing all tray icons..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	
	Write-Host "Showing Search icon..." -ForegroundColor Green
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
	
	Write-Host "Setting Desktop to Dark Gray..." -ForegroundColor Green
	Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value ''
	Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name 'Background' -Value '76 74 72'
	
	Write-Host "Removing Microsoft Store icon..." -ForegroundColor Green
	$appname = "Microsoft Store"
	((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}
	
	Write-Host "Enabling Dark Mode" -ForegroundColor Green
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
}

function Disable-CapsLock {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-CapsLock"
	Write-Host "Disabling Caps Lock..." -ForegroundColor Green
	$hexified = "00,00,00,00,00,00,00,00,02,00,00,00,2a,00,3a,00,00,00,00,00".Split(',') | % { "0x$_"}
	$kbLayout = 'HKLM:\System\CurrentControlSet\Control\Keyboard Layout'
	$keyName = "Scancode Map"
	if (!(Get-ItemProperty -Path $kbLayout -Name $keyName -ErrorAction SilentlyContinue)){
		New-ItemProperty -Path $kbLayout -Name $keyName -PropertyType Binary -Value ([byte[]]$hexified)}
}

function Enable-RDP {
	
	Write-Host ""
	$msg="Do you want to Enable RDP, [Y]Yes, [N]No"
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
}

function Install-Choco {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-Choco"
	Set-ExecutionPolicy Bypass -Scope Process -Force
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
	iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function Install-BaseApps {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-BaseApps"
	Write-Host "Installing Base Applications..." -ForegroundColor Green
	$baseApps = @(
		"7zip.install",
		"choco-upgrade-all-at-startup",
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
	
	Param ([bool]$Confirm=$True)
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-WindowsFirewallControl?"
	
	If ($Confirm) {
		$installWFC=$False
		Write-Host ""
		$msg="Do you want to install Windows Firewall Control, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$installWFC=$True}
			2 {$installWFC=$False}
		}
	}
	Else {$installWFC=$True}

	If ($installWFC){
		$autoHotKeyInstalled=((choco list autohotkey.portable --localonly | Select-String "installed.").ToString().Trim()[0])
		if (($autoHotKeyInstalled -eq "0") -or ($autoHotKeyInstalled -eq 0)) {$removeAutoHotKey=$True}
		
		choco install windowsfirewallcontrol -y
		
		If ($removeAutoHotKey){
			$autoHotKeyInstalled=((choco list autohotkey.portable --localonly | Select-String "installed.").ToString().Trim()[0])
			if (($autoHotKeyInstalled -ne "0") -and ($autoHotKeyInstalled -ne 0)) {choco uninstall autohotkey.portable -force}
		}
	}
}

function Install-OptionalApps {
	Param ([bool]$Confirm=$True)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Install-OptionalApps?"
		
	If($Confirm){Write-Host "Prompting for Optional Applications..." -ForegroundColor Green}
	
	$optionalApps=@{
		"visualstudio2019community"="Visual Studio 2019 Community Edition";
		"github-desktop"="GitHub Desktop";
		"putty"="Putty";
		"winscp"="WinSCP";
		"python"="Python 3";
		"visualstudio2019-workload-python"="Python support in Visual Studio";
		"steam-client"="Steam";
		"goggalaxy"="GOG Galaxy";
		"discord"="Discord"
	}
	$installApps=@()
	
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
					$optionalApps.values
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
	
	If($installApps){choco install $installApps -y}
	
}

function Remove-UnwantedApps {
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Remove-UnwantedApps"
	
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
        Write-Host "If present, removing $App." -ForegroundColor DarkGreen
    }
	
}

function Disable-EdgeDefaults {
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-EdgeDefaults"
	
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
	Param ([bool]$Confirm=$True)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-Cortana?"
	
	If ($Confirm) {
		$disableCortana=$False
		Write-Host ""
		$msg="Do you want to disable Cortana, [Y]Yes, [N]No"
		choice /c yn /m $msg
		switch ($LASTEXITCODE){
			1 {$disableCortana=$True}
			2 {$disableCortana=$False}
		}
	}
	Else {$disableCortana=$True}

	If ($disableCortana) {
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
}

function Disable-UnusedServices {
	Param ([bool]$Confirm=$False)
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Disable-UnusedServices?"
	
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
		"lfsvc"="Geolocation Service";#Default is Manual <- But starts automatically
		"WbioSrvc"="Windows Biometric Service";#Default is Manual <- But starts automatically
		"lmhosts"="TCP/IP NetBIOS Helper";#Default is Manual <- But starts automatically
		"EFS"="Encrypting File System (EFS - Not BitLocker)";#Default is Manual <- But starts automatically
	}
	$disableSvcs=@()
	
	:foreach ForEach ($key in $targetedSvcs.keys) {
		
		If($Confirm){
			$msg="Disable $($targetedSvcs[$key]), [Y]Yes, [N]No, [A]All, [Q]Quit/None"
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
		
		Else {$disableSvcs = $targetedSvcs.keys}
	}
	
	If($disableSvcs){
		foreach ($Svc in $disableSvcs) {
			Write-Host "Stopping and disabling $($targetedSvcs[$Svc]) service..." -ForegroundColor DarkGreen
			Stop-Service $Svc -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
			Set-Service $Svc -StartupType Disabled -WarningAction SilentlyContinue
		}
	}
	
	if (($disableSvcs -contains "LanmanWorkstation") -and ($disableSvcs -contains "LanmanServer")) {Disable-WindowsFileSharing}
	
}

function Disable-WindowsFileSharing {
	Write-Host "Disabling Windows File Sharing..." -ForegroundColor DarkGreen
	Get-NetAdapterBinding -DisplayName "Client for Microsoft Networks" | % {Disable-NetAdapterBinding -Name $_.Name -ComponentID $_.ComponentID}
	Get-NetAdapterBinding -DisplayName "File and Printer Sharing for Microsoft Networks" | % {Disable-NetAdapterBinding -Name $_.Name -ComponentID $_.ComponentID}
}

function Remove-Links {
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Remove-Links"
	
	Write-Host "Removing Links on Desktop..." -ForegroundColor Green
	$userDesktop=[Environment]::GetFolderPath("Desktop")
	Remove-Item "$userDesktop\*.lnk"
	$commonDesktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
	Remove-Item "$commonDesktop\*.lnk"
}

function Set-SecuritySettings {
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Set-SecuritySettings"
	
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
	Set-NetFirewallProfile -All -Enabled True #May need to be reversed for WSL support via GUI 
	Set-NetFirewallProfile -All -DefaultInboundAction Block #May need to be reversed for WSL support via GUI 
	Set-NetFirewallProfile -All -AllowInboundRules False #May need to be reversed for WSL support via GUI 
	New-NetFirewallRule -DisplayName "Block All Inbound on Wireless Adapters" -Direction Inbound -InterfaceType Wireless -Action Block #Redundant BUT works with WSL
	
	Write-Host "Enabling Reputation-based Protection..." -ForegroundColor Green
	Set-MpPreference -PUAProtection Enabled
	
	Write-Host "Disable NetBIOS On All Present Adapters..." -ForegroundColor Green
	$i = 'HKLM:\SYSTEM\CurrentControlSet\Services\netbt\Parameters\interfaces'  
	Get-ChildItem $i | ForEach-Object {  
		Set-ItemProperty -Path "$i\$($_.pschildname)" -name NetBiosOptions -value 2}
	(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IpEnabled="true").SetTcpipNetbios(2) | Out-Null
	
}

function Set-WindowsUpdateSettings {
	Write-Progress -Activity "Setting Microsoft Update Settings" -Status "Set-WindowsUpdateSettings"
	
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
}

function Set-RepositorySettings{
	Write-Progress -Activity "Setting PSGallery Repository to Trusted" -Status "Set-RepositorySettings"
	
	Write-Host "Setting PSGallery Repository to Trusted" -ForegroundColor Green
	Install-PackageProvider -Name NuGet -Force
	Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

function Get-WindowsUpdates {
	Write-Progress -Activity "Get Microsoft Updates" -Status "Get-WindowsUpdates"
	
	Write-Host "Getting Microsoft Updates" -ForegroundColor Green
	Install-Module PSWindowsUpdate -Force
	Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install
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
	Write-Host ""
	$msg="Do you want to rename this computer, [Y]Yes, [N]No"
	choice /c yn /m $msg
	switch ($LASTEXITCODE){
		1 {$rename=$True}
		2 {$rename=$False}
	}
	
	If($rename){
		
		$NewName=Read-Host("Enter New Computer Name")
		
		If ($NewName){
			Rename-Computer -NewName $NewName 
			Write-Progress -Activity "Renaming Computer" -Status "New Name: $NewName"
			Write-Host "Renaming Computer to $NewName..." -ForegroundColor Green
		}
		Else{
			$rename=$False
		}
	}
	If (!$rename) {
		Write-Progress -Activity "Skipping Renaming Computer" -Status "Name: $(hostname)"
	}
}

##Main##

$localAdmin=isAdmin
$internetAccess=isConnectedToInternet

If($localAdmin -and $internetAccess) {
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Starting"
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
	Disable-CapsLock
	Install-Choco
	Install-BaseApps
	Install-WindowsFirewallControl $ConfirmWindowsFirewallControl
	Install-OptionalApps $ConfirmOptionalApps
	Remove-UnwantedApps
	Disable-EdgeDefaults
	Set-SecuritySettings
	Set-WindowsUpdateSettings
	Enable-RDP
	Disable-UnusedServices $ConfirmUnusedServices
	Disable-OneDrive $ConfirmDisableOneDrive
	Disable-Cortana $ConfirmDisableCortana
	Set-WindowsExplorerView 
	Remove-Links
	#Encrypt-System $ConfirmEncryptDesktop #Not fully functional/Up to par
	Set-RepositorySettings
	Get-WindowsUpdates
	Rename-System
	
	Write-Progress -Activity "Setting Up Windows Environment" -Status "Complete"
	Write-Host "Complete" -ForegroundColor Cyan
	
	If ($ConfirmRestart) {
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


