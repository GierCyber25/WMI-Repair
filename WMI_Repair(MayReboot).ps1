# Author: Carter Gierhart
# Last Updated: 11/18/2025 9:42 PM
# Copyright (c) 2025 Carter Gierhart // Licensed under the MIT License. See LICENSE file for details.



# --------------------------------------------------------Logging Section--------------------------------------------------------
##################### logging is still a work in progress

$date = Get-Date

function Get-Time {
    Get-Date -Format "HH:mm:ss"
}

##################### Initial detection and setup for logging.

function LogFile
    {
        #################### variables
        $getUser = get-childitem env:\userprofile | select-object -expandproperty value
        $usrPath_OneDrive = $getUser + "\OneDrive\Desktop\"
        $usrPath = $getUser + "\Desktop\"

        $pathError = "Error: User path could not be found!"
        $logFile = "WMI_Repair_Log.txt"
        
        #################### Test user desktop path with error handling

        try
            {
                if (Test-Path -Path $usrPath_OneDrive)
                    {
                        Write-Host "OneDrive detected`nSetting up logfile accordingly.."
                        $usrPth = $usrPath_OneDrive                    
                    }
                
                elseif (Test-Path -Path $usrPath)
                    {
                        Write-Host "Normal user path detected!`nSetting up logfile.."
                        $usrPth = $usrPath
                    }
                
                else
                    {
                        throw $pathError
                    }
            }
        catch
            {
                if ($_ -match $pathError)
                    {
                        $usrPth = $False
                    }
            }
        
        #################### Testing for log existence under user desktop

        if ($usrPth -ne $false)
            {
                $usrLogPath = $usrPth+$logFile
                $test = Test-Path -Path $usrLogPath

                if ($test -eq $true)
                    {
                        Write-Host "Log file detected"
                        Add-Content -Path $usrLogPath -Value "-------WMI Repair Script Log-------`n($date)"
                        return $usrLogPath
                    }

                if ($test -eq $false)
                    {
                        #################### Create log file if it does not exist
                        New-Item -Path $usrPth -Name $logFile -ItemType "File" -Value "-------WMI Repair Script Log-------`n($date)" 
                        return $usrLogPath
                    }
            }

        #################### Test for log existence if user path not findable

        if ($usrPth -eq $false)
            {
                $logFolder = "C:\WMI Repair Logs"
                $logFilePath = $logFolder + $logFile
                $test1 = Test-Path -Path $logFolder
                $test2 = Test-Path -Path $logFilePath

                if ($test1 -eq $true)
                    {
                        if ($test2 -eq $true)
                            {
                                Write-Host "Pre-existing log found in alternative location!"
                                Add-Content -Path $logFilePath -Value "-------WMI Repair Script Log-------`n($date)"
                                return $logFilePath

                            }
                    }
                
                elseif ($test1 -eq $false)
                    {
                        Write-Host "Pre-existing log file not found"
                        New-Item -Path $logFolder -ItemType "Directory"
                        New-Item -path $logFolder -Name $logFile -ItemType "File" -Value "-------WMI Repair Script Log-------`n($date)"

                        return $logFilePath
                    }
            }
         
        
    }


Function UnrecoverableScriptFailure
    {
        param 
            ( 
                [string]$ErrorMessage = "An unrecoverable unknown or undefined error has been detected requiring a reboot", 
                [string]$logPath
            )
        
        Write-Host "Unrecoverable Script Failure Detected! Restarting computer in 30 seconds" 
        Add-Content -Path $logPath -Value "[$(Get-Time)]: Unrecoverable script failure detected!`nError: ($ErrorMessage)" 
        Start-Sleep -Seconds 30
        Restart-Computer -Force
        exit 1
    }


Function ScriptFailure_General
    {
        param 
            ( 
                [string]$ErrorMessage = "Unknown or Undefined error detected!",
                [string]$logPath 
            )
        Write-Host "General Script Failure Detected"
        Add-Content -Path $logPath -Value "[$(Get-Time)]: General script failure detected!`nError: ($ErrorMessage)"
    }

function debugLog
    {
        # To Do: add logic
    }

# --------------------------------------------------------Main script functions--------------------------------------------------------



function Test-WMIRepo 
	{
		return (cmd /c "winmgmt /verifyrepository") -notmatch "consistent"
	}

Function Check-Bitlocker 
	{
		return (manage-bde -status c:) -match "invalid namespace"
	}

Function Verify-WMIEvents 
	{
		[CmdletBinding()]
		param (
			[int]$DaysBack = 2
		)
		$since = (Get-Date).AddDays(-$DaysBack)
		$found = Get-WinEvent -FilterHashtable @{
			LogName   = 'Application'
			Id        = 2003,5612,2002,1025
			StartTime = $since
		} -MaxEvents 1 -ErrorAction SilentlyContinue
		return [bool]$found
	}

Function Verify-PerfLib 
	{
		[CmdletBinding()]
		param (
			[int]$DaysBack = 2
		)
		$since = (Get-Date).AddDays(-$DaysBack)
		$found = Get-WinEvent -FilterHashtable @{
			LogName   = 'Application';
			Id        = '1008','1023';
			StartTime = $since
		} -MaxEvents 1 -ErrorAction SilentlyContinue
		return [bool]$found
	}

Function Get-WmiApSrv 
	{
		$serviceName = 'wmiapsrv'
		$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"

		# 1. Check if DeleteFlag exists and is set status: 1
		try 
			{
				$flag = Get-ItemProperty -Path $regPath -Name DeleteFlag -ErrorAction Stop
				if ($flag.DeleteFlag -eq 1) { return 1 }
			}
		catch 
			{
				# Continue if DeleteFlag not found
			}

		# 2. If DeleteFlag missing → check service existence
		$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
		if ($null -eq $svc) 
			{
				# Service does not exist: status 2
				return 2
			} 
		else 
			{
				# Service exists and isn't marked: status 3
				return 3
			}
	}

function WmiApSrvChk
	{
		switch (Get-WmiApSrv) 
			{
				1 {Recreate-WmiApSrv}
				2 {Recreate-WmiApSrv}
				3 {Write-Output "WmiApSrv service exists!`nMoving On!"}
			}
	}

Function Rebuild-WMIRepo
	{
        $svcError = "WMI Service could not be forcefully stopped.`nA reboot is required to continue!"
		
        WmiApSrvChk
		cd C:\Windows\System32\wbem; cmd /c "regsvr32 wmiutils.dll /s"
		
        # Attempt to stop the WMI service
		$CheckSvc = cmd /c "net stop winmgmt /y"
		if ($CheckSvc -match "could not be stopped.") 
			{
				Write-Host "Windows Management Instrumentation couldn't be stopped.`nAttempting to forcefully restart the service."
                
				# Attempt to forcefully restart the service
				try 
					{
						Restart-Service -Name "winmgmt" -Force -ErrorAction Stop
						Write-Host "WMI Service forcefully Stopped."
					} 
				catch 
					{
						Write-Host "WMI Service stop could not be forced."
                        UnrecoverableScriptFailure -ErrorMessage $svcError -logPath LogFile
						
					}
			} 
		elseif ($CheckSvc -match "service was stopped successfully") 
			{
				Write-Host "Windows Management Instrumentation stopped successfully.`nRestarting service.."
				cmd /c "net start winmgmt"
			} 
		else 
			{
				Write-Host "Unexpected result while stopping the service. Manual intervention may be required."
			}
			
		WmiApSrvChk
		cmd /c "for /f %s in ('dir /s /b *.mof *.mfl') do mofcomp %s"
		cmd /c "for /f %s in ('dir /b /s *.dll') do regsvr32 /s %s"
		cmd /c "for %i in (*.exe) do %i /regserver"
		cmd /c "regsvr32 C:\Windows\System32\wbem\wmisvc.dll /s"
		cmd /c "wmiprvse /regserver"
	}

Function Rebuild-WMIRepo_FullReset 
	{
		WmiApSrvChk
		cd C:\Windows\System32\wbem;cmd /c "regsvr32 wmiutils.dll /s"
		sc.exe config "winmgmt" start= "disabled"
		# Attempt to stop the WMI service
		$CheckSvc = cmd /c "net stop winmgmt /y"
		if ($CheckSvc -match "could not be stopped.") 
			{
				Write-Host "Windows Management Instrumentation couldn't stop.`nAttempting to forcefully stop the service."
                Start-Sleep -Seconds 2
				# Attempt to forcefully stop the service
				try 
					{
						Stop-Service -Name "winmgmt" -Force -ErrorAction Stop
						Write-Host "Service forcefully restarted."
                        Start-Sleep -Seconds 2
					} 
				catch 
					{
						Write-Host "Service stop could not be forced. Restarting Device in 30 seconds.."
                        Start-Sleep -Seconds 30
						Restart-Computer -Force
						exit 1
					}
			} 
		elseif ($CheckSvc -match "service was stopped successfully") 
			{
				Write-Host "Windows Management Instrumentation stopped successfully.`Restarting Service."
			} 
		else 
			{
				Write-Host "Unexpected result while stopping the service. Manual intervention may be required."
			}
		Rename-Item -Path "C:\Windows\System32\Wbem\Repository" -NewName "Repository.old" -Force
		WmiApSrvChk
		cmd /c "for /f %s in ('dir /s /b *.mof *.mfl') do mofcomp %s"
		cmd /c "for /f %s in ('dir /b /s *.dll') do regsvr32 /s %s"
		cmd /c "for %i in (*.exe) do %i /regserver"
		cmd /c "regsvr32 wmisvc.dll /s"
		cmd /c "wmiprvse /regserver"
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
		Write-Host "`nAttempting to rebuild performance counters"
		
		#Initializing error handling
		$attempt = 0
		$maxAttempts = 3
		$errorPattern = "Error: Unable to rebuild performance counter setting"
		$successPattern = "Info: Successfully rebuilt performance counter setting"
		
		do {
			$attempt++
			try {
					"C:\Windows\system32", "C:\Windows\SysWOW64" |
					ForEach-Object 
						{
							& cmd /c "cd $_ && lodctr /R" 2>&1 |
							ForEach-Object 
								{ 
									if ($_ -match $errorPattern)
										{ 
											throw $_ 
										} 
									elseif ($_ -match $successPattern)
										{
											Write-Output "Rebuild Successful"
										} 
								} 
						}
					#sync counters if lodctr succeed
					& cmd /c "cd C:\Windows\System32 && winmgmt /resyncperf"
					Write-Host "Resync Successful!"
					return $True
				}
			catch 
				{
					if ($_.Exception.Message -match $errorPattern) 
						{
							Write-Host "Rebuild Error Detected, retrying (Attempt $attempt)"
							if ($attempt -lt $maxAttempts)
								{
									Start-Sleep -Seconds 2
								}
							else
								{
									Write-Host "Failed to rebuild performance counters after $maxAttempts attempts. Rebooting computer!"
									Write-Error $_.Exception.Message
									Return $false
								}
						}
					else 
						{
							Write-Error $_.Exception.Message
							Restart-Computer
							return $false
						}
				}
			} while ($attempt -lt $maxAttempts)

		# Set WMI Services back to normal and start them
		sc.exe config "winmgmt" start= "auto"
		sc.exe config "wmiApSrv" start= "auto"
		cmd /c "net start winmgmt"
		cmd /c "net start wmiApSrv"
	}

Function Resync-Counters_Full 
	{
		Write-Host "`nAttempting to rebuild performance counters"
		
		#Initializing error handling
		$attempt = 0
		$maxAttempts = 3
		$errorPattern = "Error: Unable to rebuild performance counter setting"
		$successPattern = "Info: Successfully rebuilt performance counter setting"
		
		do {
			$attempt++
			try {
					"C:\Windows\system32", "C:\Windows\SysWOW64" |
					ForEach-Object 
						{
							& cmd /c "cd $_ && lodctr /R" 2>&1 |
							ForEach-Object 
								{ 
									if ($_ -match $errorPattern)
										{ 
											throw $_ 
										} 
									elseif ($_ -match $successPattern)
										{
											Write-Output "Rebuild Successful"

										} 
								}
						}
					#sync counters if lodctr succeed
					& cmd /c "cd C:\Windows\System32 && winmgmt /resyncperf"
            
					Write-Host "Resync Successful!"
				}
			catch 
				{
					if ($_.Exception.Message -match $errorPattern)
						{
							Write-Host "Rebuild Error Detected, retrying (Attempt $attempt)"
							if ($attempt -lt $maxAttempts)
								{
									Start-Sleep -Seconds 2
								}
							else
								{
									Write-Host "Failed to rebuild performance counters after $maxAttempts attempts."
									Write-Error $_.Exception.Message
								}
							
						}
					else 
						{
							Write-Error -Message "Unexpected error has occurred ($_.Exception.Message)"
						}
				}
			} while ($attempt -lt $maxAttempts)
		
		# Set WMI Services back to normal and start them
		sc.exe config "winmgmt" start= "auto"
		sc.exe config "wmiApSrv" start= "auto"
		cmd /c "net start winmgmt"
		cmd /c "net start wmiApSrv"
	}
	

Function Main
    {
        Write-Host "Beginning Initial Verification of WMI"
        if (Test-WMIRepo) 
	        {
		        Write-Host "Repository inconsistent – attempting salvage..."
		        Rebuild-WMIRepo
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters
		
		        if (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed – performing full reset"
				        Rebuild-WMIRepo_FullReset
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters_Full
			        } 
		        else 
			        {
				        Write-Output "Repository passed initial verification.`nReviewing machine logs for relevant Events."
			        }
			
	        }

        if (Check-Bitlocker) 
	        {
		        Write-OutPut "Bitlocker namespace invalid.`nRebuilding Repository!"
		        Rebuild-WMIRepo
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters
		
		        if (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed!`nResetting Repository."
				        Rebuild-WMIRepo_FullReset
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters_Full
			        } 
		        else 
			        {
				        Write-Output "Bitlocker namespace verified successfully!"
			        }
			
	        } 

        if (Verify-WMIEvents) 
	        {
		        Write-Output "WMI events (2003 or 5612) detected in the last 30 days.`nRebuilding WMI repository.."
		        Rebuild-WMIRepo
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters
		
		        if (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed - performing reset"
				        Rebuild-WMIRepo_FullReset
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters_Full
			        } 
		        else 
			        {
				        Write-Output "`nNo relevant WMI events found in the last 30 days."
			        }
				
	        }

        if (Verify-PerfLib) 
	        {
		        Write-Output "PerfLib errors found.`nRe-Registering Associated dll's."
		        cd C:\Windows\System32
		        cmd /c "regsvr32 C:\Windows\System32\bitsperf.dll /s"
		        cmd /c "regsvr32 C:\Windows\System32\sysmain.dll /s"
                cmd /c "regsvr32 C:\Windows\System32\wbem\WmiApRpl.dll /s"
            } 
        else 
	        { 
                Write-OutPut "Verification Completed.`nNo Errors Found"
	        }
    }
