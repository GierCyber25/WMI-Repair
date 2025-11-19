# Author: Carter Gierhart
# Last Updated: 11/18/2025 9:42 PM
# Copyright (c) 2025 Carter Gierhart // Licensed under the MIT License. See LICENSE file for details.



# --------------------------------------------------------Logging Section--------------------------------------------------------
##################### logging is still a work in progress

function Date-Stamp {
    Get-Date -Format "MM/DD/YYYY"
}

function Get-Time {
    Get-Date -Format "HH:mm:ss"
}

##################### Initial detection and setup for logging.

function Log-File
    {
        #################### Note: when using this function for logpath you must write it as (Log-File) i.e. <command> | Write-Log -LogPath (Log-File)
        #################### Variable initialization
        $GetUser = Get-ChildItem env:\userprofile | Select-Object -ExpandProperty Value
        $UsrPath_OneDrive = $GetUser + "\OneDrive\Desktop\"
        $UsrPath = $GetUser + "\Desktop\"

        $PathError = "Error: User path could not be found!"
        $LogFile = "WMI_Repair_Log.txt"
        
        #################### Test user desktop path with error handling

        Try
            {
                If (Test-Path -Path $UsrPath_OneDrive)
                    {
                        Write-Host "OneDrive detected`nSetting up logfile accordingly.."
                        $UsrPth = $UsrPath_OneDrive                    
                    }
                
                ElseIf (Test-Path -Path $UsrPath)
                    {
                        Write-Host "Normal user path detected!`nSetting up logfile.."
                        $UsrPth = $UsrPath
                    }
                
                Else
                    {
                        Throw $PathError
                    }
            }
        Catch
            {
                If ($_ -match $PathError)
                    {
                        $UsrPth = $False
                    }
            }
        
        #################### Testing for log existence under user desktop

        If ($UsrPth -ne $False)
            {
                $UsrLogPath = $UsrPth+$LogFile
                $TestUserPath = Test-Path -Path $UsrLogPath

                If ($TestUserPath -eq $True)
                    {
                        Write-Host "Log file detected"
                        Write-Log -LogPath $UsrLogPath -Value "--------------WMI Repair Script Log: [$(Date-Stamp)]--------------"
                        Return $UsrLogPath
                    }

                If ($TestUserPath -eq $False)
                    {
                        #################### Create log file If it does not exist
                        New-Item -Path $UsrPth -Name $LogFile -ItemType "File" -Value "--------------WMI Repair Script Log: [$(Date-Stamp)]--------------" 
                        Return $UsrLogPath
                    }
            }

        #################### Test for log existence If user path not findable

        If ($UsrPth -eq $False)
            {
                $LogFolder = "C:\WMI Repair Logs"
                $LogFilePath = $LogFolder + $LogFile
                $TestFolderPath = Test-Path -Path $LogFolder
                $TestFilePath = Test-Path -Path $LogFilePath

                If ($TestFolderPath -eq $True)
                    {
                        If ($TestFilePath -eq $True)
                            {
                                Write-Host "Pre-existing log found in alternative location!"
                                Write-Log -LogPath $LogFilePath -Value "--------------WMI Repair Script Log: [$(Date-Stamp)]--------------"
                                Return $LogFilePath

                            }
                    }
                
                ElseIf ($TestFolderPath -eq $False)
                    {
                        Write-Host "Pre-existing log file not found"
                        New-Item -Path $LogFolder -ItemType "Directory"
                        New-Item -path $LogFolder -Name $LogFile -ItemType "File" -Value "--------------WMI Repair Script Log: [$(Date-Stamp)]--------------"

                        Return $LogFilePath
                    }
            }
         
        
    }


Function Write-HardFailure
    {
    #################### Function for unrecoverable failures requiring a reboot.
        param 
            ( 
                [string]$ErrorMessage = "An unrecoverable unknown or undefined error has been detected requiring a reboot", 
                [string]$LogPath
            )
        
        Write-Host "Unrecoverable Script Failure Detected! Restarting computer in 30 seconds" 
        Add-Content -Path $LogPath -Value "[$(Get-Time)]: Unrecoverable script failure detected!`n`tWarning: $ErrorMessage" 
        Start-Sleep -Seconds 30

        #################### send windows notif sound to computer speakers before reboot
        for ($i = 0; $i -le 1; $i++){"`a"}
        Restart-Computer -Force
        exit 1
    }


Function Write-GeneralFailure
    {
    #################### general failures, usually no reboot required. (Error handling should already be in place.)
        param 
            (
                [Parameter(ValueFromPipeline = $True)]$ErrorMessage = "Unknown or Undefined error detected!",
                [string]$LogPath 
            )
        Write-Host "General Script Failure Detected"
        Add-Content -Path $LogPath -Value "[$(Get-Time)]: General script failure detected!`n`tError: $ErrorMessage"
    }

function Write-Log
    {
    #################### General Logging function: debug or information
        [CmdletBinding()]
        param 
            (
                [Parameter(ValueFromPipeline = $True)]$Message,
                [string]$Type = "Info", #################### Debug, Info, Warning (default)
                [string]$LogPath
            )

        process{
            $LogMessage = if ($Message -is [string]) { $Message } else { $Message | Out-String }
            Add-Content -Path $LogPath -Value "[$(Get-Time)] $Type : $LogMessage"
        }
    }



# --------------------------------------------------------Main script functions--------------------------------------------------------



function Test-WMIRepo {
		Return (cmd /c "winmgmt /verifyrepository") -notmatch "consistent"
	}


Function Get-BitLocker {
		Return (Manage-Bde -Status c:) -match "invalid namespace"
	}


Function Verify-WMIEvents 
	{
		[CmdletBinding()]
		param (
			[int]$DaysBack = 3
		)
		$Since = (Get-Date).AddDays(-$DaysBack)
		$Found = Get-WinEvent -FilterHashtable @{
			LogName   = 'Application';
			Id        = '2003','5612','2002','1025';
			StartTime = $Since
		} -MaxEvents 1 -ErrorAction SilentlyContinue
		Return [bool]$Found
	}


Function Verify-PerfLib 
	{
		[CmdletBinding()]
		param (
			[int]$DaysBack = 3
		)
		$Since = (Get-Date).AddDays(-$DaysBack)
		$Found = Get-WinEvent -FilterHashtable @{
			LogName   = 'Application';
			Id        = '1000','1008','1023','2003','1022','1017';
			StartTime = $Since
		} -MaxEvents 1 -ErrorAction SilentlyContinue
		Return [bool]$Found
	}


Function Get-WmiApSrv 
	{
    #################### service checks | for some reason this service can get deleted sometimes
		$ServiceName = 'wmiapsrv'
		$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

		# 1. Check If DeleteFlag exists and is set status: 1
		Try 
			{
				$Flag = Get-ItemProperty -Path $RegPath -Name DeleteFlag -ErrorAction Stop
				If ($Flag.DeleteFlag -eq 1) { Return 1 }
			}
		Catch 
			{
				# Continue If DeleteFlag not found
			}

		# 2. If DeleteFlag missing → check service existence
		$Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
		If ($null -eq $Svc) 
			{
				# Service does not exist: status 2
				Return 2
			} 
		Else 
			{
				# Service exists and isn't marked: status 3
				Return 3
			}
	}


function Resolve-WmiApSrv
	{
    #################### parse output of Get-WmiApSrv to determine next steps
		switch (Get-WmiApSrv) 
			{
				1 {Recreate-WmiApSrv}
				2 {Recreate-WmiApSrv}
				3 {Write-Output "WmiApSrv service exists!`nMoving On!"}
			}
	}


Function Rebuild-WMIRepo
	{
        param
            (
                [ValidateSet("Standard", "Complete")]
                [string]$RepairType
            )


        If ($RepairType -eq "Standard")
            {
                $SvcError = "WMI Service could not be forcefully stopped.`nA reboot is required to continue!"
		
                Resolve-WmiApSrv
		        cd C:\Windows\System32\wbem; cmd /c "regsvr32 wmiutils.dll /s"
		
                # Attempt to stop the WMI service
		        $CheckSvc = cmd /c "net stop winmgmt /y"
		        If ($CheckSvc -match "could not be stopped.") 
			        {
				        Write-Host "Windows Management Instrumentation Services could not be stopped.`nAttempting to forcefully restart the service."
                        Write-Output "Windows Management Instrumentation Services could not be stopped normally.`n`tAttempting forceful service restart" | Write-GeneralFailure -LogPath (Log-File)
                
				        # Attempt to forcefully restart the service
				        Try 
					        {
						        Restart-Service -Name "winmgmt" -Force -ErrorAction Stop
						        Write-Host "WMI Service forcefully Stopped."
					        } 
				        Catch 
					        {
						        Write-Host "WMI Service stop could not be forcefully stopped.."
                                Write-HardFailure -ErrorMessage $SvcError -LogPath (Log-File)
					        }
			        } 
		        ElseIf ($CheckSvc -match "service was stopped successfully") 
			        {
				        Write-Host "Windows Management Instrumentation stopped successfully.`nRestarting service.."
				        cmd /c "net start winmgmt"
			        } 
		        Else 
			        {
				        Write-Host "Unexpected result while stopping the service. Manual intervention may be required."
			        }
			
		        Resolve-WmiApSrv
		        cmd /c "for /f %s in ('dir /s /b *.mof *.mfl') do mofcomp %s"
		        cmd /c "for /f %s in ('dir /b /s *.dll') do regsvr32 /s %s"
		        cmd /c "for %i in (*.exe) do %i /regserver"
		        cmd /c "regsvr32 C:\Windows\System32\wbem\wmisvc.dll /s"
		        cmd /c "wmiprvse /regserver"
            }

        If ($RepairType -eq "Complete")
            {
		        Resolve-WmiApSrv
		        cd C:\Windows\System32\wbem;cmd /c "regsvr32 wmiutils.dll /s"
		        sc.exe config "winmgmt" start= "disabled"
		        # Attempt to stop the WMI service
		        $CheckSvc = cmd /c "net stop winmgmt /y"
		        If ($CheckSvc -match "could not be stopped.") 
			        {
				        Write-Host "Windows Management Instrumentation couldn't stop.`nAttempting to forcefully stop the service."
                        Start-Sleep -Seconds 2
				        # Attempt to forcefully stop the service
				        Try 
					        {
						        Stop-Service -Name "winmgmt" -Force -ErrorAction Stop
						        Write-Host "Service forcefully restarted." | Write-Log -LogPath (Log-File)
                                Start-Sleep -Seconds 2
					        } 
				        Catch 
					        {
						        Write-Host "Service stop could not be forced. Restarting Device in 30 seconds.."
                                Write-HardFailure -ErrorMessage "Windows Management Instrumentation services couldn't be stopped." -LogPath (Log-File)
						        exit 1
					        }
			        } 
		        ElseIf ($CheckSvc -match "service was stopped successfully") 
			        {
				        Write-Host "Windows Management Instrumentation stopped successfully.`Restarting Service."
			        } 
		        Else 
			        {
				        Write-Host "Unexpected result while stopping the service. Manual intervention may be required."
			        }
		        Rename-Item -Path "C:\Windows\System32\Wbem\Repository" -NewName "Repository.old" -Force
		        Resolve-WmiApSrv
		        cmd /c "for /f %s in ('dir /s /b *.mof *.mfl') do mofcomp %s"
		        cmd /c "for /f %s in ('dir /b /s *.dll') do regsvr32 /s %s"
		        cmd /c "for %i in (*.exe) do %i /regserver"
		        cmd /c "regsvr32 wmisvc.dll /s"
		        cmd /c "wmiprvse /regserver"
            }
	}


Function Recreate-WmiApSrv 
	{
		taskkill /im wmi* /f /t; taskkill /im mmc* /f /t
		Copy-Item -Path "C:\Windows\WinSxS\**\wmiapsrv.exe" -Destination "C:\Windows\System32\wbem\wmiapsrv.exe"
		sc.exe create WmiApSrv binPath= "C:\Windows\System32\wbem\wmiapsrv.exe" DisplayName= "WMI Performance Adapter" type= "own" start= "demand" error= "normal" obj= "LocalSystem"
		sc.exe start WmiApSrv
	}


Function Resync-Counters 
	{
        param
            (
                [ValidateSet("Standard", "Complete")]
                [string]$SyncType
            )
		Write-Host "`nAttempting to rebuild performance counters"
		
		#Initializing error handling
		$Attempt = 0
		$MaxAttempts = 3
		$ErrorPattern = "Error: Unable to rebuild performance counter setting"
		$SuccessPattern = "Info: Successfully rebuilt performance counter setting"
		
        if ($SyncType -eq "Standard")
            {
		        do {
			        $Attempt++
			        Try {
					        "C:\Windows\system32", "C:\Windows\SysWOW64" |
					        ForEach-Object 
						        {
							        & cmd /c "cd $_ && lodctr /R" 2>&1 |
							        ForEach-Object 
								        { 
									        If ($_ -match $ErrorPattern)
										        { 
											        Throw $_ 
										        } 
									        ElseIf ($_ -match $SuccessPattern)
										        {
											        Write-Output "Rebuild Successful"
										        } 
								        } 
						        }
					        #sync counters If lodctr succeed
					        & cmd /c "cd C:\Windows\System32 && winmgmt /resyncperf"
					        Write-Host "Resync Successful!"
					        Return $True
				        }
			        Catch 
				        {
					        If ($_.Exception.Message -match $ErrorPattern) 
						        {
							        Write-Host "Rebuild Error Detected, retrying (Attempt $Attempt)" 
                                    Write-Output "Maximum Retries Reached! Could not rebuild counters after $Attempt attempts..." | Write-Log -Type Debug -LogPath (Log-File)
							        If ($Attempt -lt $MaxAttempts)
								        {
									        Start-Sleep -Seconds 2
								        }
							        Else
								        {
									        Write-Host "Failed to rebuild performance counters after $MaxAttempts attempts. Rebooting computer!"
									        Write-Error $_.Exception.Message
									        Return $False
								        }
						        }
					        Else 
						        {
							        Write-Error $_.Exception.Message
							        Restart-Computer
							        Return $False
						        }
				        }
			        } while ($Attempt -lt $MaxAttempts)

		        # Set WMI Services back to normal and start them
		        sc.exe config "winmgmt" start= "auto"
		        sc.exe config "wmiApSrv" start= "auto"
		        cmd /c "net start winmgmt"
		        cmd /c "net start wmiApSrv"
            }
############################################################
		if ($SyncType -eq "Complete")
            {
                Write-Host "`nAttempting to rebuild performance counters"
		
		        #Initializing error handling
		
		        do {
			        $Attempt++
			        Try {
					        "C:\Windows\system32", "C:\Windows\SysWOW64" |
					        ForEach-Object 
						        {
							        & cmd /c "cd $_ && lodctr /R" 2>&1 |
							        ForEach-Object 
								        { 
									        If ($_ -match $ErrorPattern)
										        { 
											        Throw $_ 
										        } 
									        ElseIf ($_ -match $SuccessPattern)
										        {
											        Write-Output "Rebuild Successful"

										        } 
								        }
						        }
					        #sync counters If lodctr succeed
					        & cmd /c "cd C:\Windows\System32 && winmgmt /resyncperf"
					        Write-Host "Resync Successful!"
                            Write-Log 
				        }
			        Catch 
				        {
					        If ($_.Exception.Message -match $ErrorPattern)
						        {
							        Write-Host "Rebuild Error Detected, retrying (Attempt $Attempt)"
							        If ($Attempt -lt $MaxAttempts)
								        {
									        Start-Sleep -Seconds 2
								        }
							        Else
								        {
									        Write-Host "Failed to rebuild performance counters after $MaxAttempts attempts."
                                            Write-Output "Error detected while re-syncing performance counters!`n`tRetrying (Attempt $Attempt)..." | Write-Log -Type Debug -LogPath (Log-File)
									        Write-HardFailure $_.Exception.Message
								        }
							
						        }
					        Else 
						        {
							        Write-Host "Unexpected error has occurred."
                                    Write-HardFailure $_.Exception.Message
						        }
				        }
			        } while ($Attempt -lt $MaxAttempts)
		
		        # Set WMI Services back to normal and start them
		        sc.exe config "winmgmt" start= "auto"
		        sc.exe config "wmiApSrv" start= "auto"
		        cmd /c "net start winmgmt"
		        cmd /c "net start wmiApSrv"
            }
	}
	

Function Main
    {
        Write-Host "Beginning Initial Verification of WMI"
        If (Test-WMIRepo) 
	        {
		        Write-Host "Repository inconsistent – attempting salvage..."
		        Rebuild-WMIRepo -RepairType Standard
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters -SyncType Standard
		
		        If (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed – performing full reset"
				        Rebuild-WMIRepo -RepairType Complete
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters -SyncType Complete
			        } 
		        Else 
			        {
				        Write-Output "Repository passed initial verification.`nReviewing machine logs for relevant Events."
			        }
			
	        }

        ElseIf (Get-BitLocker) 
	        {
		        Write-OutPut "Bitlocker namespace invalid.`nRebuilding Repository!"
		        Rebuild-WMIRepo -RepairType Standard
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters -SyncType Standard
		
		        If (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed!`nResetting Repository."
				        Rebuild-WMIRepo -RepairType Complete
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters -SyncType Complete
			        } 
		        Else 
			        {
				        Write-Output "Bitlocker namespace verified successfully!"
			        }
			
	        } 

        If (Verify-WMIEvents) 
	        {
		        Write-Output "WMI Error/Warning events have been detected in the last 30 days.`nRebuilding WMI repository.."
		        Rebuild-WMIRepo -RepairType Standard
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters -SyncType Standard
		
		        If (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed - performing reset"
				        Rebuild-WMIRepo -RepairType Complete
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters -SyncType Complete
			        } 
		        Else 
			        {
				        Write-Output "`nNo relevant WMI events found in the last 30 days."
			        }
				
	        }

        If (Verify-PerfLib) 
	        {
		        Write-Output "PerfLib errors found.`nRe-Registering Associated dll's."
		        cd C:\Windows\System32
		        cmd /c "regsvr32 C:\Windows\System32\bitsperf.dll /s"
		        cmd /c "regsvr32 C:\Windows\System32\sysmain.dll /s"
                cmd /c "regsvr32 C:\Windows\System32\wbem\WmiApRpl.dll /s"
            } 
        Else 
	        { 
                Write-OutPut "Verification Completed.`nNo Errors Found"
	        }
    }
