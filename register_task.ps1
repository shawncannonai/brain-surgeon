# Register a task that runs brain_surgeon.py --apply every N minutes, no console window, hard 3-minute limit.
#
#     powershell -NoProfile -ExecutionPolicy Bypass -File register_task.ps1 [-Minutes 5]
#
# Runs pythonw.exe DIRECTLY (not through a detached launcher) so Task Scheduler sees the instance and
# MultipleInstances IgnoreNew really prevents a pile-up. Limited run level: it can remove the current user's
# processes, not elevated ones. Idempotent.
param([int]$Minutes = 5, [string]$TaskName = "BrainSurgeon")
$pyw = (Get-Command pythonw.exe -ErrorAction Stop).Source
$dir = $PSScriptRoot
$action   = New-ScheduledTaskAction -Execute $pyw -Argument "`"$dir\brain_surgeon.py`" --apply" -WorkingDirectory $dir
$trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes $Minutes) -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) `
              -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
$t = Get-ScheduledTask -TaskName $TaskName
Write-Output ("{0}: {1}; next {2}" -f $t.TaskName, $t.State, ($t | Get-ScheduledTaskInfo).NextRunTime)
