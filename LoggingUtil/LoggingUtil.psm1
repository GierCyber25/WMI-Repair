# Author: Carter Gierhart
# Last Updated: Wednesday, September 30th, 2026 8:15 PM
# Copyright (c) 2025 Carter Gierhart // Licensed under the MIT License. See LICENSE file for details.

# Logging Utility Module
##################### Initial detection and setup for logging.
Import-Module "$PSScriptRoot\RebootRequest.psm1"

Function Get-DateStamp {
    Get-Date -Format "MM/dd/yyyy"
}

Function Get-TimeStamp {
    Get-Date -Format "HH:mm:ss"
}

$script:LogPath = $null

Function Initialize-LogFile {

        #################### Variable initialization
        $GetUser = (Get-ChildItem env:\userprofile).Value
        $UserPath_OneDrive = Join-Path $GetUser "OneDrive\Desktop"
        $UserPath = Join-path $GetUser "Desktop"
        $FallBack = "C:\WMI Repair Logs"
        $LogFile = "WMI_Repair_Log[$(Get-DateStamp)].txt"
        $Header = "----------------------------WMI Repair Script Log: [$(Get-DateStamp)]----------------------------"

        # Determine logging directory
        If (Test-Path -Path $UserPath_OneDrive)
            {
                Write-Host "OneDrive detected`nSetting up logfile accordingly.."
                $LogDir = Join-Path $UserPath_OneDrive "WMI Repair Logs"
            }
                
        ElseIf (Test-Path -Path $UserPath)
            {
                Write-Host "Normal user path detected!`nSetting up logfile accordingly.."
                $LogDir = Join-Path $UserPath "WMI Repair Logs"
            }
                
        Else
            {
                $LogDir = $FallBack
                If (-not (Test-Path $LogDir))
                    {
                        New-Item -Path $LogDir -ItemType Directory | Out-Null
                    }
                Write-Host "Using fallback path: $LogDir"
            }

        $LogPath = Join-Path $LogDir $LogFile

        # Create or Update log file
        If (-not (Test-Path $LogPath))
            {
                New-Item -Path $LogPath -ItemType File -Value "$Header`n" | Out-Null
            } 
        Else
            {
                Add-Content -Path $LogPath -Value "`n$Header"
            }
        
        Return $LogPath
}

function Get-LogFile {
    if (-not $script:LogPath) {
        $script:LogPath = Initialize-LogFile
    }
    return $script:LogPath
}

Function Write-Failure {
    #################### Function for unrecoverable failures requiring a reboot.
        param 
            ( 
                [Parameter(ValueFromPipeline = $True)]
                $ErrorMessage = "An unrecoverable unknown or undefined error has been detected requiring a reboot", 
                
                [string]$LogPath = (Get-LogFile)
            )
        
        Write-Host "Unrecoverable Script Failure Detected! Reboot required... `nsending request now..." 
        Add-Content -Path $LogPath -Value "`n[$(Get-TimeStamp)] Critical: Unrecoverable script failure detected!`n`tWarning: $ErrorMessage" 

        #################### send windows notification sound to computer speakers before reboot
        for ($i = 0; $i -lt 1; $i++){[System.Media.SystemSounds]::Exclamation.Play()}
        Request-Reboot
        exit 1
}


Function Write-Log {
    
    #################### General Failures and General Logs: debug, information, and warning.
    #################### usually no reboot required. (Error handling should already be in place.)
        [CmdletBinding()]
        param 
            (
                [Parameter(ValueFromPipeline = $True)]$Message = "Unknown or Undefined error detected!",

                [ValidateSet("Info", "Debug", "Warning")]
                [string]$Type = "Info", #################### Debug, Info (default), Warning 
                [string]$LogPath = (Get-LogFile)
            )
        
        process 
            {
                $LogMessage = If ($Message -is [string]) { $Message } Else { $Message | Out-String }

                If ($Type -eq "Debug") 
                    {
                        Write-Host "General Script Error Detected: $LogMessage"
                        Add-Content -Path $LogPath -Value "`n[$(Get-TimeStamp)] $Type : General script error detected!`n`tError info: $LogMessage"
                    }
                Else 
                    {
                        Add-Content -Path $LogPath -Value "`n[$(Get-TimeStamp)] $Type : $LogMessage"
                    }
            }
}
