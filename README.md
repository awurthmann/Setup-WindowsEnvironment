# Setup-WindowsEnvironment

Script used to re-setup my test system(s) after being reset to "Factory Defaults". 
This script and its default options are specific to my needs. You may need to edit this script yourself for your own.

## Legal
You the executor, runner, user accept all liability.
This code comes with ABSOLUTELY NO WARRANTY.
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

## Instructions:
	Copy/Paste the line below into PowerShell for default settings
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/awurthmann/Setup-WindowsEnvironment/main/Setup-WindowsEnvironment.ps1'))
```
## Alternative Instructions:
	  - Download Setup-WindowsEnvironment.ps1
	  - Open PowerShell
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```
	  - Execute Setup-WindowsEnvironment.ps1 with desired paramaters or none and be prompted.
 
 ## Notes:
 Not every intended feature of this script is fully functional, this is being uploaded and made public per request.
 
 ## What is not working:
 1) Bitlocker isn't as fully automated as I would like, I may revisit this. Current thinking is to use a password protected PasteBin.
 2) Start Menu customization isn't as functional as I would like. May not finish this one with Windows 11 coming out. 
 3) "Block Downloads" under "Reputation-based protection" isn't checked and there doesn't seem to be a registry setting that controls this setting.
	To enable manually: To turn on potentially unwanted app blocking go to Start  > Settings  > Update & Security > Windows Security > App & browser control > Reputation-based protection settings. Check Block Apps, Check Block downloads
 
