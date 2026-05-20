# Reboot Request Module
Function Request-Reboot {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Unrecoverable Script Failure"
    $form.Size = New-Object System.Drawing.Size(400, 200)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Topmost = $true

    # Label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Critical Error! A reboot is required."
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(30, 20)
    $form.Controls.Add($label)

    # Shared result variable
    $script:rebootChoice = $null

    # Restart Immediately button
    $btnRestartNow = New-Object System.Windows.Forms.Button
    $btnRestartNow.Text = "Restart Immediately"
    $btnRestartNow.Size = New-Object System.Drawing.Size(150, 30)
    $btnRestartNow.Location = New-Object System.Drawing.Point(30, 80)
    $btnRestartNow.Add_Click({
        $script:rebootChoice = 'Now'
        $form.Close()
    })
    $form.Controls.Add($btnRestartNow)

    # Restart Later button
    $btnRestartLater = New-Object System.Windows.Forms.Button
    $btnRestartLater.Text = "Restart Later"
    $btnRestartLater.Size = New-Object System.Drawing.Size(150, 30)
    $btnRestartLater.Location = New-Object System.Drawing.Point(200, 80)
    $btnRestartLater.Add_Click({
        $script:rebootChoice = 'Later'
        $form.Close()
    })
    $form.Controls.Add($btnRestartLater)

    # Show the form (blocks until closed)
    $form.ShowDialog() | Out-Null
    $form.Dispose()

    # Handle choice after form is gone
    if ($script:rebootChoice -eq 'Now') {
        [System.Windows.Forms.MessageBox]::Show("Restarting now...", "Restart", "OK", "Information")
        Restart-Computer -Force
    }
    elseif ($script:rebootChoice -eq 'Later') {
        $delay = $null
        while ($true) {
            Write-Host "Enter delay in minutes, or press Enter for default (5 minutes):"
            $input = Read-Host "Delay (minutes)"

            if ([string]::IsNullOrWhiteSpace($input)) {
                $delay = 5
                Write-Host "Defaulting to 5 minutes."
                break
            }
            elseif ($input -match '^\d+$' -and [int]$input -gt 0) {
                $delay = [int]$input
                break
            }
            else {
                Write-Host "Invalid input. Please enter a positive whole number."
            }
        }

        [System.Windows.Forms.MessageBox]::Show(
            "Reboot scheduled in $delay minute(s).",
            "Confirmation", "OK", "Information"
        )
        Write-Host "System will restart in $delay minute(s)..."
        Start-Sleep -Seconds ($delay * 60)
        Restart-Computer -Force
    }
}