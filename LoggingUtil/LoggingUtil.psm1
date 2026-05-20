##################### Initial detection and setup for logging.
Function Date-Stamp {
    Get-Date -Format "MM/dd/yyyy"
}

Function Get-Time {
    Get-Date -Format "HH:mm:ss"
}

Function Log-File
    {
        #################### Variable initialization
        $GetUser = (Get-ChildItem env:\userprofile).Value
        $UserPath_OneDrive = Join-Path $GetUser "OneDrive\Desktop"
        $UserPath = Join-path $GetUser "Desktop"
        $FallBack = "C:\WMI Repair Logs"
        $LogFile = "WMI_Repair_Log[$(Date-Stamp)].txt"
        $Header = "----------------------------WMI Repair Script Log: [$(Date-Stamp)]----------------------------"

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


Function Write-Failure
    {
    #################### Function for unrecoverable failures requiring a reboot.
        param 
            ( 
                [Parameter(ValueFromPipeline = $True)]
                $ErrorMessage = "An unrecoverable unknown or undefined error has been detected requiring a reboot", 
                
                [string]$LogPath = (Log-File)
            )
        
        Write-Host "Unrecoverable Script Failure Detected! Restarting computer in 30 seconds" 
        Add-Content -Path $LogPath -Value "`n[$(Get-Time)] Critical: Unrecoverable script failure detected!`n`tWarning: $ErrorMessage" 

        #################### send windows notif sound to computer speakers before reboot
        for ($i = 0; $i -le 1; $i++){"`a"}
        Request-Reboot
        exit 1
    }


Function Write-Log
    {
    
    #################### General Failures and General Logs: debug, information, and warning.
    #################### usually no reboot required. (Error handling should already be in place.)
        [CmdletBinding()]
        param 
            (
                [Parameter(ValueFromPipeline = $True)]$Message = "Unknown or Undefined error detected!",

                [ValidateSet("Info", "Debug", "Warning")]
                [string]$Type = "Info", #################### Debug, Info (default), Warning 
                [string]$LogPath = (Log-File)
            )
        
        process 
            {
                $LogMessage = If ($Message -is [string]) { $Message } Else { $Message | Out-String }

                If ($Type -eq "Debug") 
                    {
                        Write-Host "General Script Error Detected: $LogMessage"
                        Add-Content -Path $LogPath -Value "`n[$(Get-Time)] $Type : General script error detected!`n`tError info: $LogMessage"
                    }
                Else 
                    {
                        Add-Content -Path $LogPath -Value "`n[$(Get-Time)] $Type : $LogMessage"
                    }
            }
    }