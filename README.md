# Windows Management Instrumentation Repair 
// Copyright (c) 2025 Carter Gierhart
// Licensed under the MIT License. See LICENSE file for details.
# script currently broken, do not use.

This PowerShell script is designed for manual execution or integration into automation workflows to verify and repair components associated with Windows Management Instrumentation (WMI).


### Manual Use Case
Since powershell scripts are disabled by default, scripts must be run with a temporary change to execution policy.
In this instance if the script were placed at the root of your C drive the command would be run like so:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; C:\WMI_Repair(MayReboot).ps1

### Automation
for automation setup this is completely dependant upon what you're using to setup scheduling of the script.
Since this script can be used both commerically and privately you could be using task scheduler or you might be using an endpoint management system built in-house or by a third party.
In either case you should follow available documentation from the respective software developers on how to setup the script within automation.
