# Author: Carter Gierhart
# Last Updated: Wednesday, September 30th, 2026 8:15 PM
# Copyright (c) 2025 Carter Gierhart // Licensed under the MIT License. See LICENSE file for details.

# Reboot Request Module
Function Request-Reboot {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Unrecoverable Script Failure"
    $form.Size = New-Object System.Drawing.Size(400, 230)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Topmost = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Critical Error! A reboot is required."
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(30, 20)
    $form.Controls.Add($label)

    # Delay selector replaces Read-Host
    $lblDelay = New-Object System.Windows.Forms.Label
    $lblDelay.Text = "Delay if restarting later (minutes):"
    $lblDelay.AutoSize = $true
    $lblDelay.Location = New-Object System.Drawing.Point(30, 60)
    $form.Controls.Add($lblDelay)

    $numDelay = New-Object System.Windows.Forms.NumericUpDown
    $numDelay.Minimum = 1
    $numDelay.Maximum = 1440
    $numDelay.Value = 5
    $numDelay.Location = New-Object System.Drawing.Point(250, 57)
    $numDelay.Size = New-Object System.Drawing.Size(80, 25)
    $form.Controls.Add($numDelay)

    # DialogResult closes the form and returns the choice, so no handlers or $script: vars
    $btnNow = New-Object System.Windows.Forms.Button
    $btnNow.Text = "Restart Immediately"
    $btnNow.Size = New-Object System.Drawing.Size(150, 30)
    $btnNow.Location = New-Object System.Drawing.Point(30, 110)
    $btnNow.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $form.Controls.Add($btnNow)

    $btnLater = New-Object System.Windows.Forms.Button
    $btnLater.Text = "Restart Later"
    $btnLater.Size = New-Object System.Drawing.Size(150, 30)
    $btnLater.Location = New-Object System.Drawing.Point(200, 110)
    $btnLater.DialogResult = [System.Windows.Forms.DialogResult]::No
    $form.Controls.Add($btnLater)

    $result  = $form.ShowDialog()
    $minutes = [int]$numDelay.Value   # read before Dispose
    $form.Dispose()

    switch ($result) {
        'Yes' { Restart-Computer -Force }
        'No'  {
            shutdown.exe /r /t ($minutes * 60) /c "WMI repair script: reboot scheduled in $minutes minute(s). Run 'shutdown /a' to cancel."
            Write-Host "Reboot scheduled in $minutes minute(s)."
        }
        default { Write-Host "Reboot prompt dismissed. Please restart the computer manually." }
    }
}
