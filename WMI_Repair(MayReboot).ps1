# Author: Carter Gierhart
# Last Updated: Friday, November 21, 2025 3:04:20 PM
# Copyright (c) 2025 Carter Gierhart // Licensed under the MIT License. See LICENSE file for details.

# -------------------------------------------------------- To Do/Implement --------------------------------------------------------

# -------------------------------------------------------- Logging Functions --------------------------------------------------------



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
        
        If ($Type -eq "Debug")
            {
                Write-Host "General Script Error Detected"
                process
                    {
                        $LogMessage = if ($Message -is [string]) { $Message } else { $Message | Out-String }
                        Add-Content -Path $LogPath -Value "`n[$(Get-Time)] $Type : General script error detected!`n`tError info: $LogMessage"
                    }
            }
        Else
            {
                process
                    {
                        $LogMessage = if ($Message -is [string]) { $Message } else { $Message | Out-String }
                        Add-Content -Path $LogPath -Value "`n[$(Get-Time)] $Type : $LogMessage"
                    }
            }
    }

# -------------------------------------------------------- Supporting Functions --------------------------------------------------------

Function Request-Reboot 
    {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Add-Type -AssemblyName Microsoft.VisualBasic

        # Create the form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Unrecoverable Script Failure"
        $form.Size = New-Object System.Drawing.Size(400,200)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = 'FixedDialog'
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false

        # Label
        $label = New-Object System.Windows.Forms.Label
        $label.Text = "Critical Error! A reboot is required."
        $label.AutoSize = $true
        $label.Location = New-Object System.Drawing.Point(30,20)
        $form.Controls.Add($label)

        # Restart Immediately button
        $btnRestartNow = New-Object System.Windows.Forms.Button
        $btnRestartNow.Text = "Restart Immediately"
        $btnRestartNow.Size = New-Object System.Drawing.Size(150,30)
        $btnRestartNow.Location = New-Object System.Drawing.Point(30,80)
        $btnRestartNow.Add_Click({
            [System.Windows.Forms.MessageBox]::Show("Restarting now...","Restart","OK","Information")
            Restart-Computer -Force
        })
        $form.Controls.Add($btnRestartNow)

        # Restart Later button
        $btnRestartLater = New-Object System.Windows.Forms.Button
        $btnRestartLater.Text = "Restart Later"
        $btnRestartLater.Size = New-Object System.Drawing.Size(150,30)
        $btnRestartLater.Location = New-Object System.Drawing.Point(200,80)
        $btnRestartLater.Add_Click({
            $form.Close()
            While ($true) 
                {
                    Write-Host "You have 30 seconds to enter delay in minutes (default = 5)..."
                    $job = Start-Job { Read-Host "Enter delay in minutes" }
                    Wait-Job $job -Timeout 30 | Out-Null
                    $delay = Receive-Job $job
                    Remove-Job $job

                    if (-not $delay) 
                        {
                            $delay = 5
                            Write-Host "No input detected. Defaulting to 5 minutes."
                        }

                    if ($delay -match '^\d+$') 
                        {
                            $seconds = [int]$delay * 60
                            [System.Windows.Forms.MessageBox]::Show("Reboot scheduled in $delay minute(s).","Confirmation","OK","Information")
                            Write-Host "System will restart in $delay minute(s)..."
                            Start-Sleep -Seconds $seconds
                            Restart-Computer -Force
                            break
                        } 
                    else 
                        {
                            Write-Host "Invalid input. Please enter a numeric value."
                        }
                }
        })
        $form.Controls.Add($btnRestartLater)

        # Show the form
        $form.Topmost = $true
        $form.ShowDialog()
    }


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
                [string]$DllPath,
                [string]$TestPath,
                [string]$GetService,
                [string]$VerifyDll,
                [string]$EnablePerf,
                [string]$RegTest,
                [string]$ParseEvents
            )

        If ($PSBoundParameters.ContainsKey('TestDll'))
            {
                # Insert Logic
                # can PSCustom object not need.

            }

        If ($
        <#sfc /verifyfile="$DllPath" /OFFLOGFILE=(Log-File)
        
        Test existence:
        Test-Path $DllPath


        if path returns true:
        
        try lodctr /e:%dllname%
        match (Error: unable to enable service "%dllname%"; error code is 2.)
        
        Get-Service "%PerfSvc%"
        if disabled:
        Set-Service -Name "%PerfSvc%" -StartupType Automatic
        Start-Service -Name "%dllname%"

        Verify Registry Entry:
        Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\%dllname%\Performance"

        if entry is not found pass false out of function so that the corrections can be performed.#>
    }

Function Repair-PerfCounters
 {
    param
        (
            [string]$Perflib
        )
    
    $keepProps = @("Library","Open","Collect","Close")
    
    Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\%dllname%\Performance"


    If ($PSBoundParameters.ContainsKey('Perflib'))
    {
        <# Sysmain dll perfcounters/registration

        $sysmainPerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain\Performance"

        # Create key if missing
        If (-not (Test-Path $sysmainPerfKey)) {
            New-Item -Path $sysmainPerfKey -Force
        }

        # Set correct values
        Set-ItemProperty -Path $sysmainPerfKey -Name "Library" -Value "C:\Windows\System32\sysmain.dll"
        Set-ItemProperty -Path $sysmainPerfKey -Name "Open" -Value "OpenSysMainPerformanceData"
        Set-ItemProperty -Path $sysmainPerfKey -Name "Collect" -Value "CollectSysMainPerformanceData"
        Set-ItemProperty -Path $sysmainPerfKey -Name "Close" -Value "CloseSysMainPerformanceData"

        Write-Host "SysMain Performance key has been created/reset."
    
    
        # -------------------------------------------------------- LSM perf counters/registration 

        #dll "C:\Windows\System32\perfts.dll"
        # Reset LSM Performance registry values
        $lsmPerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LSM\Performance"

        # Ensure key exists
        if (-not (Test-Path $lsmPerfKey)) {
            New-Item -Path $lsmPerfKey -Force
        }

        # Set correct values
        Set-ItemProperty -Path $lsmPerfKey -Name "Library" -Value "C:\Windows\System32\perfts.dll"
        Set-ItemProperty -Path $lsmPerfKey -Name "Open" -Value "OpenTSPerformanceData"
        Set-ItemProperty -Path $lsmPerfKey -Name "Collect" -Value "CollectTSPerformanceData"
        Set-ItemProperty -Path $lsmPerfKey -Name "Close" -Value "CloseTSPerformanceData"

        # Remove invalid entries


        Write-Host "Registry values for LSM Performance key have been reset."

        # Rebuild counters
        Write-Host "Rebuilding performance counters..."
        lodctr /T:LSM
        lodctr /e:LSM

        Write-Host "Done. Please run 'sfc /scannow' to verify DLL integrity."

        # -------------------------------------------------------- BITS perf counters/registration 

        $bitsPerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\BITS\Performance"
        if (-not (Test-Path $bitsPerfKey)) { New-Item -Path $bitsPerfKey -Force }
        Set-ItemProperty -Path $bitsPerfKey -Name "Library" -Value "C:\Windows\System32\bitsperf.dll"
        Set-ItemProperty -Path $bitsPerfKey -Name "Open" -Value "OpenBitsPerformanceData"
        Set-ItemProperty -Path $bitsPerfKey -Name "Collect" -Value "CollectBitsPerformanceData"
        Set-ItemProperty -Path $bitsPerfKey -Name "Close" -Value "CloseBitsPerformanceData"
        Remove-ItemProperty -Path $bitsPerfKey -Name "PerfIniFile" -ErrorAction SilentlyContinue

        # -------------------------------------------------------- WMI perf counters and registration 

        $wmiPerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WmiApRpl\Performance"

        # Ensure key exists
        if (-not (Test-Path $wmiPerfKey)) {
            New-Item -Path $wmiPerfKey -Force
        }

        # Remove invalid entries
        (Get-ItemProperty -Path $wmiPerfKey).PSObject.Properties |
            Where-Object { $_.Name -notin $keepProps } |
            ForEach-Object { Remove-ItemProperty -Path $wmiPerfKey -Name $_.Name -ErrorAction SilentlyContinue }

        # Set correct values
        Set-ItemProperty -Path $wmiPerfKey -Name "Library" -Value "C:\Windows\System32\wbem\WmiApRpl.dll"
        Set-ItemProperty -Path $wmiPerfKey -Name "Open" -Value "OpenWmiApRplPerformanceData"
        Set-ItemProperty -Path $wmiPerfKey -Name "Collect" -Value "CollectWmiApRplPerformanceData"
        Set-ItemProperty -Path $wmiPerfKey -Name "Close" -Value "CloseWmiApRplPerformanceData"

        Write-Host "WmiApRpl Performance key has been reset."
        lodctr /T:WmiApRpl
        lodctr /e:WmiApRpl
        # -------------------------------------------------------- TermService perf counters and registration

        # dll = "C:\Windows\System32\perfts.dll"
        $termPerfKey = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Performance"
        if (-not (Test-Path $termPerfKey)) { New-Item -Path $termPerfKey -Force }
        Set-ItemProperty -Path $termPerfKey -Name "Library" -Value "C:\Windows\System32\perfts.dll"
        Set-ItemProperty -Path $termPerfKey -Name "Open" -Value "OpenTSPerformanceData"
        Set-ItemProperty -Path $termPerfKey -Name "Collect" -Value "CollectTSPerformanceData"
        Set-ItemProperty -Path $termPerfKey -Name "Close" -Value "CloseTSPerformanceData"
        Remove-ItemProperty -Path $termPerfKey -Name "PerfIniFile" -ErrorAction SilentlyContinue

        lodctr /T:TermService
        lodctr /e:TermService
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
                [int]$Stop = 0,
                [int]$Start = 0,
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
                    Status       = if ($stopStatus -eq 'Success' -and $startStatus -eq 'Success') { 'Success' } else { 'Failed' }
                    Stop         = $stopStatus
                    Start        = $startStatus
                    FallbackUsed = $fallbackUsed
                    Message      = if ($fallbackUsed) { "Stop failed; Restart-Service used as fallback and succeeded." } else { "Force restart completed successfully." }
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
                                            #Write-Log $_.Exception.Message + attempt number
                                    
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
							                Write-Log $_.Exception.Message
							                Return $False
						                }
				                }
			                } while ($Attempt -lt $MaxAttempts)

		                # Set WMI Services back to normal and start them
                        Update-Winmgmt -Enabled 1
                    }

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
											                Write-Output "Rebuild Successful" | Write-Log 

										                } 
								                }
						                }
					                #sync counters If lodctr succeed
					                & cmd /c "cd C:\Windows\System32 && winmgmt /resyncperf"
					                Write-Host "Resync Successful!"
                                    Write-Log -Message "Successfully re-synced performance counters" -Type Info
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
                                                    Write-Output "Error detected while re-syncing performance counters!`n`tRetrying (Attempt $Attempt)..." | Write-Log -Type Warning
									                Write-Failure $_.Exception.Message
								                }
							
						                }
					                Else 
						                {
							                Write-Host "Unexpected error has occurred."
                                            Write-Failure $_.Exception.Message
						                }
				                }
			                } while ($Attempt -lt $MaxAttempts)
		
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
