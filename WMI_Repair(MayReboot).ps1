# Author: Carter Gierhart
# Last Updated: Wednesday, May 20th, 2026 6:45 PM
# Copyright (c) 2025 Carter Gierhart // Licensed under the MIT License. See LICENSE file for details.

Import-Module "$PSScriptRoot\RebootRequest"
Import-Module "$PSScriptRoot\LoggingUtil"

# -------------------------------------------------------- Diagnostic Functions --------------------------------------------------------

Function Test-WMIRepo {
		Return (cmd /c "winmgmt /verifyrepository") -notmatch "consistent"
	}


Function Get-BitLocker {
		Return (Manage-Bde -Status C:) -match "invalid namespace"
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
		} -MaxEvents 10 -ErrorAction SilentlyContinue
		Return [bool]$Found
	}


Function Get-WmiApSrv 
	{
    #################### service checks | for some reason this service can get deleted sometimes
		$ServiceName = 'wmiapsrv'
		$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

		# 1. Check If DeleteFlag exists and is set. function status set to 1
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
				# Service does not exist: function status set to 2
				Return 2
			} 
		Else 
			{
				# Service exists and isn't marked: function status set to 3
				Return 3
			}
	}


Function Resolve-WmiApSrv
	{
    #################### parse output of Get-WmiApSrv to determine next steps
		switch (Get-WmiApSrv) 
			{
				1 {Recreate-WmiApSrv}
				2 {Recreate-WmiApSrv}
				3 {Write-Output "WmiApSrv service exists!`nMoving On!"}
                default {Write-Log -Type Debug}
			}
	}

# Testing for each perfcounter 
Function Test-PerfCounters
    {
        param
            (
                [string]$DLL_Name,
                
                [ValidateSet(0,1)]
                [int]$TestPath = 0,

                [ValidateSet(0,1)]
                [int]$GetService = 0,

                [ValidateSet(0,1)]
                [int]$VerifyDLL = 0,

                [ValidateSet(0,1)]
                [int]$RegTest = 0,

                [ValidateSet(0,1)]
                [int]$EnablePerf = 0,

                [ValidateSet(0,1)]
                [int]$ParseEvents = 0
            )
        
        $DLL_Path = "C:\Windows\System32\$DLL_Name.dll"
        $DLL_RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$DLL_Name\Performance"
        
        # HKLM:\SYSTEM\CurrentControlSet\Services\$DLL\Performance
        If ($PSBoundParameters.ContainsKey('TestPath'))
            {
                $DLLres = Test-Path $DLL_Path
                If ($DLLres)
                    {
                        Return [PSCustomObject]@{Status = "Present"; Message = "DLL found"}
                    }
                Else 
                    {
                        Return [PSCustomObject]@{Status = "Missing"; Message = "DLL not found"}
                    }
            }
        
        If ($PSBoundParameters.ContainsKey('GetService'))
            {
            }
        
        If ($PSBoundParameters.ContainsKey('VerifyDLL'))
            {
                #insert logic
                #sfc /verifyfile="$DllPath" /OFFLOGFILE=(Log-File)
            }
        
        If ($PSBoundParameters.ContainsKey('RegTest'))
            {
                $RegResult = Test-Path $DLL_RegistryPath
                If ($RegResult)
                    {
                        Return [PSCustomObject]@{Status = "Present"; Message = "Performance counter registry key is present."}
                    }
                Else
                    {
                        Return [PSCustomObject]@{Status = "Missing"; Message = "Performance counter registry key could not be found!"}
                    }
            }
        
        If ($PSBoundParameters.ContainsKey('EnablePerf'))
            {
                # testing to see if perf counter can be enabled.
                $EnTest = lodctr /e:$DLL_Name
            }

        If ($PSBoundParameters.ContainsKey())
            {
            }

        <#
        
        Test existence:

        If path returns true:
        
        try lodctr /e:%dllname%
        match (Error: unable to enable service "%dllname%"; error code is 2.)
        
        Get-Service "%PerfSvc%"
        If disabled:
        Set-Service -Name "%PerfSvc%" -StartupType Automatic
        Start-Service -Name "%dllname%"

        Verify Registry Entry:
        Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\%dllname%\Performance"

        If entry is not found pass false out of function so that the corrections can be performed.
        #>
    }

Function Repair-PerfCounters
 {
    param
        (
            [string]$PerfLib
        )
    
    $keepProps = @("Library", "Open", "Collect", "Close", "First Counter", "First Help", "Last Counter", "Last Help", "Library Validation Code", "PerfIniFile", "PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")
    
    # Need to simplify testing by moving some functions into Test-PerfCounters

    # Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\%dllname%\Performance"


    If ($PSBoundParameters.ContainsKey('Perflib'))
    {

        If ($PerfLib -eq "LSM")
            {
                # Reset LSM Performance registry values
                $LSM_PerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LSM\Performance"

                # Ensure key exists
                If (-not (Test-Path $LSM_PerfKey)) {
                    New-Item -Path $LSM_PerfKey -Force
                }

                # Remove invalid entries
                (Get-ItemProperty -Path $LSM_PerfKey).PSObject.Properties |
                    Where-Object { $_.Name -notin $keepProps } |
                    ForEach-Object { Remove-ItemProperty -Path $LSM_PerfKey -Name $_.Name -ErrorAction SilentlyContinue }

                # Set correct values
                Set-ItemProperty -Path $LSM_PerfKey -Name "Library" -Value "C:\Windows\System32\lsmperf.dll"
                Set-ItemProperty -Path $LSM_PerfKey -Name "Open" -Value "OpenTSPerformanceData"
                Set-ItemProperty -Path $LSM_PerfKey -Name "Collect" -Value "CollectTSPerformanceData"
                Set-ItemProperty -Path $LSM_PerfKey -Name "Close" -Value "CloseTSPerformanceData"


                Write-Host "Registry values for LSM Performance key have been reset."

                # Rebuild counters
                Write-Host "Rebuilding performance counters..."
                lodctr /T:LSM
                lodctr /e:LSM

                Write-Host "Done. Please run 'sfc /scannow' to verify DLL integrity."
            }

        If ($PerfLib -eq "BITS")
            {
                # -------------------------------------------------------- BITS perf counters/registration 
                $BITS_PerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\BITS\Performance"
				
                
                If (-not (Test-Path $BITS_PerfKey)) { 
                        New-Item -Path $BITS_PerfKey -Force 
                    }
                # Remove invalid entries
                (Get-ItemProperty -Path $BITS_PerfKey).PSObject.Properties |
                    Where-Object { $_.Name -notin $keepProps } |
                    ForEach-Object { Remove-ItemProperty -Path $BITS_PerfKey -Name $_.Name -ErrorAction SilentlyContinue }
                

                # Set correct values
                Set-ItemProperty -Path $BITS_PerfKey -Name "Library" -Value "C:\Windows\System32\bitsperf.dll"
                Set-ItemProperty -Path $BITS_PerfKey -Name "Open" -Value "PerfMon_Open"
                Set-ItemProperty -Path $BITS_PerfKey -Name "Collect" -Value "PerfMon_Collect"
                Set-ItemProperty -Path $BITS_PerfKey -Name "Close" -Value "PerfMon_Close"
				Set-ItemProperty -Path $BITS_PerfKey -Name "PerfIniFile" -Value "bitsctrs.ini"

                lodctr /T:BITS
                lodctr /e:BITS
            }

        If ($PerfLib -eq "TermService")
            {
                # -------------------------------------------------------- TermService perf counters and registration

                # dll = "C:\Windows\System32\perfts.dll"
                $TermPerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Performance"
                If (-not (Test-Path $TermPerfKey)) { 
                        New-Item -Path $TermPerfKey -Force 
                    }

                # Remove invalid entries
                (Get-ItemProperty -Path $TermPerfKey).PSObject.Properties |
                    Where-Object { $_.Name -notin $keepProps } |
                    ForEach-Object { Remove-ItemProperty -Path $TermPerfKey -Name $_.Name -ErrorAction SilentlyContinue }

                # Set correct values
                Set-ItemProperty -Path $TermPerfKey -Name "Library" -Value "C:\Windows\System32\perfts.dll"
                Set-ItemProperty -Path $TermPerfKey -Name "Open" -Value "OpenTSObject"
                Set-ItemProperty -Path $TermPerfKey -Name "Collect" -Value "CollectTSObjectData"
                Set-ItemProperty -Path $TermPerfKey -Name "Close" -Value "CloseTSObject"
				Set-ItemProperty -Path $TermPerfKey -Name "PerfIniFile" -Value "tslabels.ini"

                lodctr /T:TermService
                lodctr /e:TermService
            }
        
        If ($Perflib -eq "WMISvc")
            {
                # -------------------------------------------------------- WMI perf counters and registration 

                $WMI_PerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WmiApRpl\Performance"
                # Ensure key exists
                If (-not (Test-Path $WMI_PerfKey)) {
                        New-Item -Path $WMI_PerfKey -Force
                    }

                # Remove invalid entries
                (Get-ItemProperty -Path $WMI_PerfKey).PSObject.Properties |
                    Where-Object { $_.Name -notin $keepProps } |
                    ForEach-Object { Remove-ItemProperty -Path $WMI_PerfKey -Name $_.Name -ErrorAction SilentlyContinue }

                # Set correct values
                Set-ItemProperty -Path $WMI_PerfKey -Name "Library" -Value "C:\Windows\System32\wbem\WmiApRpl.dll"
                Set-ItemProperty -Path $WMI_PerfKey -Name "Open" -Value "WmiOpenPerfData"
                Set-ItemProperty -Path $WMI_PerfKey -Name "Collect" -Value "WmiCollectPerfData"
                Set-ItemProperty -Path $WMI_PerfKey -Name "Close" -Value "WmiClosePerfData"
				Set-ItemProperty -Path $TermPerfKey -Name "PerfIniFile" -Value "WmiApRpl.ini"

                Write-Host "WmiApRpl Performance key has been reset."
                lodctr /T:WmiApRpl
                lodctr /e:WmiApRpl
            }
        <#
        # ------------------------------------------------------------------------

        finally do this:
        lodctr /R 
        sfc /scannow 
        #>
    }
 }



# -------------------------------------------------------- Main Functions --------------------------------------------------------

Function Recreate-WmiApSrv 
	{
		taskkill /im wmi* /f /t; taskkill /im mmc* /f /t
		Copy-Item -Path "C:\Windows\WinSxS\**\wmiapsrv.exe" -Destination "C:\Windows\System32\wbem\wmiapsrv.exe"
		sc.exe create WmiApSrv binPath= "C:\Windows\System32\wbem\wmiapsrv.exe" DisplayName= "WMI Performance Adapter" type= "own" start= "demand" error= "normal" obj= "LocalSystem"
		sc.exe start WmiApSrv
	}


Function Update-Winmgmt
    {
        
        [CmdletBinding()]

        param
            (
                [ValidateSet(0,1)]
                [int]$Enabled, # 0 or 1
                
                [ValidateSet(0,1)]
                [int]$Stop = 0,
                
                [ValidateSet(0,1)]
                [int]$Start = 0,

                [ValidateSet(0,1)]
                [int]$Force = 0
            )
        
        #################### Parameter handling
        If ($PSBoundParameters.ContainsKey('Enabled')) 
            {
                If ($Enabled -eq 1) 
                    {
                        Write-Host "Enabling and starting Winmgmt service..."
                        sc.exe config "winmgmt" start= "auto"
                        sc.exe config "wmiapsrv" start= "auto"
                        cmd /c "net start winmgmt"
                        cmd /c "net start wmiapsrv"
                    }
                ElseIf ($Enabled -eq 0) 
                    {
                        Write-Host "Disabling and stopping Winmgmt service..."
                        sc.exe config "winmgmt" start= disabled
                        cmd /c "net stop winmgmt /y"
                    }
            }
        
        If ($PSBoundParameters.ContainsKey('Start'))
            {
                $output = cmd /c "net start winmgmt /y"
                If ($output -match "services was started successfully")
                    {
                        Return [PSCustomObject]@{Status = 'Success'; Message = 'Winmgmt service started successfully'}
                    }
                Else
                    {
                        Return [PSCustomObject]@{Status = 'Failed'; Message = 'Could not start winmgmt service'}
                    }
            }

        If ($PSBoundParameters.ContainsKey('Stop'))
            {
                $output = cmd /c "net stop winmgmt /y"
                If ($output -match "service was stopped successfully")
                    {
                        Return [PSCustomObject]@{Status = 'Success'; Message = 'Winmgmt service stopped successfully'}
                    }
                Else
                    {
                        Return [PSCustomObject]@{Status = 'Failed'; Message = 'Winmgmt service could not be stopped'}
                    }
            }


        If ($PSBoundParameters.ContainsKey('Force')) 
            {
                Write-Host "Attempting forceful restart of Winmgmt service..."
                $stopStatus = 'Failed'
                $startStatus = 'Failed'
                $fallbackUsed = $false

                Try 
                    {
                        Stop-Service -Name "winmgmt" -Force -ErrorAction Stop
                        $stopStatus = 'Success'
                        #add output to log
                    } 
            
                Catch 
                    {
                        Write-Host "Stop-Service failed. Falling back to Restart-Service..."
                        #add output to log
                        $fallbackUsed = $true
                        Try 
                            {
                                Restart-Service -Name "winmgmt" -Force -ErrorAction Stop
                                $stopStatus = 'Success'   # Treat fallback as success
                                $startStatus = 'Success'
                                #add output to log
                            } 
                
                        Catch 
                            {
                                Write-Host "Restart-Service also failed."
                                #add output to log
                            }
                    }

                # If Stop succeeded, try Start
                If ($stopStatus -eq 'Success' -and -not $fallbackUsed) 
                    {
                        Try 
                            {
                                Start-Service -Name "winmgmt" -ErrorAction Stop
                                $startStatus = 'Success'
                                #add output to log
                            } 
                    
                        Catch 
                            {
                                Write-Host "Failed to start Winmgmt after stop."
                                #add output to log
                            }
                    }

                Return [PSCustomObject]@{
                    Status       = If ($stopStatus -eq 'Success' -and $startStatus -eq 'Success') { 'Success' } Else { 'Failed' }
                    Stop         = $stopStatus
                    Start        = $startStatus
                    FallbackUsed = $fallbackUsed
                    Message      = If ($fallbackUsed) { "Stop failed; Restart-Service used as fallback and succeeded." } Else { "Force restart completed successfully." }
                }
            }
    }


Function Rebuild-WMIRepo
	{
        param
            (
                [ValidateSet("Standard", "Complete")]
                [string]$RepairType
            )

        If ($PSBoundParameters.ContainsKey('RepairType'))
            {
                If ($RepairType -eq "Standard")
                    {
                        $SvcError = "WMI Service could not be forcefully stopped.`nA reboot is required to continue!"
		
                        Resolve-WmiApSrv
		                cd C:\Windows\System32\wbem; cmd /c "regsvr32 wmiutils.dll /s"
		
                        # Attempt to stop the WMI service
                        $result = Update-Winmgmt -Stop
		        
                        If ($result.Status -eq 'Failed') 
			                {
				                Write-Host "Windows Management Instrumentation Services could not be stopped."
                                Write-Output "Windows Management Instrumentation Services could not be stopped normally.`n`tAttempting forceful service restart" | Write-Log -Type Debug
                
				                # Attempt to forcefully restart the service
				                Try 
					                {
						                Update-Winmgmt -Force
						                Write-Host "WMI Service forcefully Stopped."
                                        Write-Log -Message "WMI Services forcefully restarted" -Type Info
					                } 
				                Catch 
					                {
						                Write-Host "Windows Management Instrumentation Service (winmgmt) could not be forcefully stopped.."
                                        Write-Failure -ErrorMessage $SvcError
					                }
			                } 
		                ElseIf ($result.Status -eq 'Success') 
			                {
				                Write-Host "Windows Management Instrumentation stopped successfully.`nRestarting service.."
				                Update-Winmgmt -Start
			                } 
		                Else 
			                {
				                Write-Host "Unexpected result while stopping the service. Manual intervention may be required."
                                Write-Log -Type Debug
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
		                Update-Winmgmt -Enabled 0 # -> Update-Winmgmt -Enabled 0
		                # Attempt to stop the WMI service
		                $SvcChk = Update-Winmgmt -Stop
		                If ($SvcChk.Status -eq "Failed") 
			                {
				                Write-Host "Windows Management Instrumentation couldn't stop.`nAttempting to forcefully stop the service."
                                Start-Sleep -Seconds 2
				                # Attempt to forcefully stop the service
				                Try 
					                {
						                Update-Winmgmt -Force
						                Write-Host "Service forcefully restarted."
                                        # Write-Log -Message "WMI Services forcefully restarted" | probably going to handle this in the origin module itself
                                        Start-Sleep -Seconds 2
					                } 
				        
                                Catch 
					                {
						                Write-Host "Service stop could not be forced. Restarting Device in 30 seconds.."
                                        Write-Failure -ErrorMessage "Windows Management Instrumentation services couldn't be stopped."
						                exit 1
					                }
			                } 
		                ElseIf ($SvcChk.Status -eq "Success") 
			                {
				                Write-Host "Windows Management Instrumentation stopped successfully."
			                } 
		                Else 
			                {
				                Write-Output "Unexpected result while stopping the service. Manual intervention may be required." | Write-Log -Type Debug
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
        Else
            {
                Return [PSCustomObject]@{
                    Status      = 'Failed'
                    Message     = 'Invalid function use!'
                }
            }
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
		If ($PSBoundParameters.ContainsKey('SyncType'))
            {
                If ($SyncType -eq "Standard")
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
							                Write-Output "Error detected while re-syncing performance counters!`n`tRetrying (Attempt $Attempt)..." | Write-Log -Type Warning
							                If ($Attempt -lt $MaxAttempts)
								                {
									                Start-Sleep -Seconds 2
								                }
							                Else
								                {
									                Write-Output "Failed to rebuild performance counters after $MaxAttempts attempts!" | Write-Log -Type Warning
									                Write-Failure -ErrorMessage $_.Exception.Message
									                Return $False
								                }
						                }
					                Else 
						                {
							                Write-Log $_.Exception.Message -Type Debug
							                Return $False
						                }
				                }
			                } while ($Attempt -lt $MaxAttempts)

		                # Set WMI Services back to normal and start them
                        Update-Winmgmt -Enabled 1
                    }

		        If ($SyncType -eq "Complete")
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
											                Write-Output "Rebuild Successful" | Write-Log 

										                } 
								                }
						                }
					                #sync counters If lodctr succeed
					                & cmd /c "cd C:\Windows\System32 && winmgmt /resyncperf"
					                Write-Host "Resync Successful!"
                                    Write-Log -Message "Successfully re-synced performance counters" -Type Info
                                    Return $True
				                }
			                Catch 
				                {
					                If ($_.Exception.Message -match $ErrorPattern)
						                {
							                Write-Output "Error detected while re-syncing performance counters!`n`tRetrying (Attempt $Attempt)..." | Write-Log -Type Warning
							                If ($Attempt -lt $MaxAttempts)
								                {
									                Start-Sleep -Seconds 2
								                }
							                Else
								                {
									                Write-Host "Failed to rebuild performance counters after $MaxAttempts attempts."
									                Write-Failure $_.Exception.Message
                                                    Return $False
								                }
							
						                }
					                Else 
						                {
							                Write-Host "Unexpected error has occurred."
                                            Write-Failure $_.Exception.Message -Type Debug
                                            Return $False
						                }
				                }
			                } while ($Attempt -lt $MaxAttempt)
		
		                # Set WMI Services back to normal and start them
                        Update-Winmgmt -Enabled 1
                    }
                }
        Else
            {
                Return [PSCustomObject]@{
                    Status     = 'Failed'
                    Message    = 'Invalid function input'    
                }
            }
	}
	
# -------------------------------------------------------- Main --------------------------------------------------------

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
				        Write-Output "Repository passed initial verification.`nReviewing machine logs for relevant Events." | Write-Log
			        }
			
	        }

        ElseIf (Get-BitLocker) 
	        {
		        Write-OutPut "Bitlocker namespace invalid.`nRebuilding Repository!" | Write-Log -Type Warning
		        Rebuild-WMIRepo -RepairType Standard
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters -SyncType Standard
		
		        If (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed!`nResetting Repository." | Write-Log -Type Warning
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
		        Write-Output "WMI Error/Warning events have been detected in the last 30 days.`nRebuilding WMI repository.." | Write-Log -Debug
		        Rebuild-WMIRepo -RepairType Standard
		        cmd /c "winmgmt /salvagerepository"
		        Resync-Counters -SyncType Standard
		
		        If (Test-WMIRepo) 
			        {
				        Write-Output "Salvage failed - performing reset" | Write-Log -Type Warning
				        Rebuild-WMIRepo -RepairType Complete
				        cmd /c "winmgmt /resetrepository"
				        Resync-Counters -SyncType Complete
			        } 
		        Else 
			        {
				        Write-Output "`nNo relevant WMI events found in the last 30 days." | Write-Log
			        }
				
	        }
        ######## Refactor to new function that reads event content. Keep Verify-Perflib for boolean evaluation and use new for in-depth diagnostic
        If (Verify-PerfLib) #basically a true or false check
	        {
                # new function being written: 
		        Write-Output "PerfLib errors found.`nRepairing Associated dll's." | Write-Log -Type Warning
		        cd C:\Windows\System32

                # These aren't com dll's so this straight up just doesn't work
                # I've been known to be something of a dumbass on occasion 
		        <# Adding repairs and checks for these:
                C:\Windows\System32\bitsperf.dll
		        C:\Windows\System32\sysmain.dll
                C:\Windows\System32\wbem\WmiApRpl.dll#>
            } 
        Else 
	        { 
                Write-OutPut "Verification Completed.`nNo Errors Found"
	        }
    }
