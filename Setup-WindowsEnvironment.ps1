#Setup-WindowsEnvironment.ps1

function isAdmin {
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-Profile {
	iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/my-powershell-profile/main/Set-Profile.ps1'))
}

function Enable-RDP {
	$installScript=((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/Set-RDP-Connection/main/Set-RDP-Connection.ps1'))
	$ScriptBlock = [System.Management.Automation.ScriptBlock]::Create($installScript)
	$ScriptArgs=@($False,$True)
	Invoke-Command $ScriptBlock -ArgumentList $ScriptArgs
}

function Install-Choco {
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function Install-BaseApps {
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

function Install-OptionalApps {

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
		
		
		$msg="Install $($optionalApps[$key]), [Y]es, [N]o, [A]ll"
		choice /c yna /m $msg
		
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
		}
	}
	
	choco instal $installApps -y
}

function Remove-Links {
	$userDesktop=[Environment]::GetFolderPath("Desktop")
	Remove-Item "$userDesktop\*.lnk"
	$commonDesktop=[Environment]::GetFolderPath("CommonDesktopDirectory")
	Remove-Item "$commonDesktop\*.lnk"
}

##Main##
If(isAdmin) {

	Set-Profile 
	Enable-RDP
	Install-Choco
	Install-BaseApps
	Install-OptionalApps
	Remove-Links

}
Else {
	Write-Error -Message "
ERROR: Administrator permissions are required to make requested changes." -Category PermissionDenied
}
##End Main##
