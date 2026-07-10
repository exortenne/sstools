# ============================================================
#   Нюдсы 11 классниц бесплатно
#   1. System Checker
#   2. Void Mod Analyzer
#   3. Command History Analyzer
# ============================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# -------------------------------------------------------------
#  ADMIN CHECK  (shared - only need it once)
# -------------------------------------------------------------
$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n" -ForegroundColor Red
    Write-Host "=================================================" -ForegroundColor Red
    Write-Host "        ADMINISTRATOR PRIVILEGES REQUIRED       " -ForegroundColor Red
    Write-Host "      Please run this script as Administrator!    " -ForegroundColor Red
    Write-Host "=================================================" -ForegroundColor Red
    Write-Host "`n" -ForegroundColor Red
    exit
}


# ============================================================
#  PART 1 - SYSTEM CHECKER
# ============================================================
# verdict tracking - collected across both parts, evaluated at the very end
$verdictFlags    = [System.Collections.Generic.List[string]]::new()
$verdictWarnings = [System.Collections.Generic.List[string]]::new()

Clear-Host
Write-Host "сосать байпасеры by exortenne" -ForegroundColor Cyan
Write-Host ""

# -- Boot time ------------------------------------------------
try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime   = (Get-Date) - $bootTime
    Write-Host "SYSTEM BOOT TIME" -ForegroundColor Cyan
    Write-Host ("  Last Boot: {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
    Write-Host ("  Uptime: {0} days, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor White
} catch {
    Write-Host "Unable to retrieve boot time information" -ForegroundColor Red
}

try {
    $mcProc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProc) { $mcProc = Get-Process java -ErrorAction SilentlyContinue }
    if ($mcProc) {
        $mcUptime = (Get-Date) - $mcProc.StartTime
        Write-Host ("  Minecraft Start: {0}" -f $mcProc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
        Write-Host ("  MC Uptime: {0} days, {1:D2}:{2:D2}:{3:D2}" -f $mcUptime.Days, $mcUptime.Hours, $mcUptime.Minutes, $mcUptime.Seconds) -ForegroundColor White
    } else {
        Write-Host "  Minecraft: Not running" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Unable to retrieve Minecraft process info" -ForegroundColor Red
}

# -- Connected drives -------------------------------------------
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host "`nCONNECTED DRIVES" -ForegroundColor Cyan
    foreach ($drive in $drives) {
        Write-Host ("  {0}: {1}" -f $drive.DeviceID, $drive.FileSystem) -ForegroundColor White
    }
}

# -- Services --------------------------------------------------
Write-Host "`nSERVICE STATUS" -ForegroundColor Cyan

$services = @(
    @{Name = "SysMain"; DisplayName = "SysMain"},
    @{Name = "PcaSvc"; DisplayName = "Program Compatibility Assistant Service"},
    @{Name = "DPS"; DisplayName = "Diagnostic Policy Service"},
    @{Name = "EventLog"; DisplayName = "Windows Event Log"},
    @{Name = "Schedule"; DisplayName = "Task Scheduler"},
    @{Name = "Bam"; DisplayName = "Background Activity Moderator"},
    @{Name = "Dusmsvc"; DisplayName = "Data Usage"},
    @{Name = "Appinfo"; DisplayName = "Application Information"},
    @{Name = "CDPSvc"; DisplayName = "Connected Devices Platform Service"},
    @{Name = "DcomLaunch"; DisplayName = "DCOM Server Process Launcher"},
    @{Name = "PlugPlay"; DisplayName = "Plug and Play"},
    @{Name = "wsearch"; DisplayName = "Windows Search"},
    @{Name = "DiagTrack"; DisplayName = "Connected User Experiences and Telemetry"},
    @{Name = "Power"; DisplayName = "Power"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            $displayName = $service.DisplayName
            if ($displayName.Length -gt 40) {
                $displayName = $displayName.Substring(0, 37) + "..."
            }
            Write-Host ("  {0,-12} {1,-40}" -f $svc.Name, $displayName) -ForegroundColor Magenta -NoNewline
            
            if ($svc.Name -eq "Bam") {
                Write-Host " | Enabled" -ForegroundColor Yellow
            } else {
                try {
                    $process = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" | Select-Object ProcessId
                    if ($process.ProcessId -gt 0) {
                        $proc = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue
                        if ($proc) {
                            Write-Host (" | {0}" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor Yellow
                        } else {
                            Write-Host " | N/A" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host " | N/A" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host " | N/A" -ForegroundColor Yellow
                }
            }
        } else {
            $displayName = $service.DisplayName
            if ($displayName.Length -gt 40) {
                $displayName = $displayName.Substring(0, 37) + "..."
            }
            Write-Host ("  {0,-12} {1,-40} {2}" -f $svc.Name, $displayName, $service.Status) -ForegroundColor Red
        }
    } else {
        Write-Host ("  {0,-12} {1,-40} {2}" -f $svc.Name, "Not Found", "Stopped") -ForegroundColor Yellow
    }
}

# -- Registry --------------------------------------------------
Write-Host "`nREGISTRY" -ForegroundColor Cyan

$regSettings = @(
    @{ Name = "CMD";               Path = "HKCU:\Software\Policies\Microsoft\Windows\System";                               Key = "DisableCMD";                Warning = "Disabled"; Safe = "Available" },
    @{ Name = "PowerShell Logging";Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";        Key = "EnableScriptBlockLogging";  Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Activities Cache";  Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";                               Key = "EnableActivityFeed";        Warning = "Disabled"; Safe = "Enabled" },
    @{ Name = "Prefetch Enabled";  Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; Warning = "Disabled"; Safe = "Enabled" }
)

foreach ($s in $regSettings) {
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    Write-Host "  " -NoNewline
    if ($status -and $status.$($s.Key) -eq 0) {
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Warning)" -ForegroundColor Red
    } else {
        Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
        Write-Host "$($s.Safe)" -ForegroundColor Magenta
    }
}

# -- Event log helpers -----------------------------------------
function Check-EventLog {
    param ($logName, $eventID, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "  $message at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Magenta
    }
}

function Check-RecentEventLog {
    param ($logName, $eventIDs, $message)
    $event = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$($eventIDs -join ' or EventID=')]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($event) {
        Write-Host "  $message (ID: $($event.Id)) at: " -NoNewline -ForegroundColor White
        Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "  $message - No records found" -ForegroundColor Magenta
    }
}

function Check-DeviceDeleted {
    try {
        $event = Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" -FilterXPath "*[System[EventID=400]]" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) { Write-Host "  Device configuration changed at: " -NoNewline -ForegroundColor White; Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow; return }
    } catch {}
    try {
        $event = Get-WinEvent -FilterHashtable @{LogName="System"; ID=225} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($event) { Write-Host "  Device removed at: " -NoNewline -ForegroundColor White; Write-Host $event.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow; return }
    } catch {}
    try {
        $events = Get-WinEvent -LogName "System" | Where-Object {$_.Id -eq 225 -or $_.Id -eq 400} | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($events) { Write-Host "  Last device change at: " -NoNewline -ForegroundColor White; Write-Host $events.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow; return }
    } catch {}
    Write-Host "  Device changes - No records found" -ForegroundColor Magenta
}

# -- Event logs ------------------------------------------------
Write-Host "`nEVENT LOGS" -ForegroundColor Cyan
Check-EventLog      "Application" 3079          "USN Journal cleared"
Check-RecentEventLog "System"     @(104, 1102)  "Event Logs cleared"
Check-EventLog      "System"      1074           "Last PC Shutdown"
Check-EventLog      "Security"    4616           "System time changed"
Check-EventLog      "System"      6005           "Event Log Service started"
Check-DeviceDeleted

# -- Prefetch integrity ----------------------------------------
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "`nPREFETCH INTEGRITY" -ForegroundColor Cyan

    $files = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "  No prefetch found?? Check the folder please" -ForegroundColor Yellow
    } else {
        $hashTable              = @{}
        $suspiciousFiles        = @{}
        $totalFiles             = $files.Count
        $hiddenFiles            = @()
        $readOnlyFiles          = @()
        $hiddenAndReadOnlyFiles = @()

        foreach ($file in $files) {
            try {
                $isHidden   = $file.Attributes -band [System.IO.FileAttributes]::Hidden
                $isReadOnly = $file.Attributes -band [System.IO.FileAttributes]::ReadOnly

                if ($isHidden -and $isReadOnly) {
                    $hiddenAndReadOnlyFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) { $suspiciousFiles[$file.Name] = "Hidden and Read-only" }
                } elseif ($isHidden) {
                    $hiddenFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) { $suspiciousFiles[$file.Name] = "Hidden file" }
                } elseif ($isReadOnly) {
                    $readOnlyFiles += $file
                    if (-not $suspiciousFiles.ContainsKey($file.Name)) { $suspiciousFiles[$file.Name] = "Read-only file" }
                }

                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($hash) {
                    if ($hashTable.ContainsKey($hash.Hash)) { $hashTable[$hash.Hash].Add($file.Name) }
                    else { $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new(); $hashTable[$hash.Hash].Add($file.Name) }
                }
            } catch {
                if (-not $suspiciousFiles.ContainsKey($file.Name)) { $suspiciousFiles[$file.Name] = "Error analyzing file: $($_.Exception.Message)" }
            }
        }

        if ($hiddenAndReadOnlyFiles.Count -gt 0) {
            Write-Host "  Hidden & Read-only Files: $($hiddenAndReadOnlyFiles.Count) found" -ForegroundColor Yellow
            foreach ($file in $hiddenAndReadOnlyFiles) { Write-Host ("    {0}" -f $file.Name) -ForegroundColor White }
        }

        if ($hiddenFiles.Count -gt 0) {
            Write-Host "  Hidden Files: $($hiddenFiles.Count) found" -ForegroundColor Yellow
            foreach ($file in $hiddenFiles) { Write-Host ("    {0}" -f $file.Name) -ForegroundColor White }
        } else { Write-Host "  Hidden Files: None" -ForegroundColor Magenta }

        if ($readOnlyFiles.Count -gt 0) {
            Write-Host "  Read-Only Files: $($readOnlyFiles.Count)" -ForegroundColor Yellow
            foreach ($file in $readOnlyFiles) { Write-Host ("    {0}" -f $file.Name) -ForegroundColor White }
        } else { Write-Host "  Read-Only Files: None" -ForegroundColor Magenta }

        $repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        if ($repeatedHashes) {
            Write-Host "  Duplicate Files: $($repeatedHashes.Count) sets found" -ForegroundColor Yellow
            foreach ($entry in $repeatedHashes) {
                foreach ($f in $entry.Value) { if (-not $suspiciousFiles.ContainsKey($f)) { $suspiciousFiles[$f] = "Duplicate file" } }
                Write-Host ("    Duplicate set: {0}" -f ($entry.Value -join ", ")) -ForegroundColor White
            }
        } else { Write-Host "  Duplicates: None" -ForegroundColor Magenta }

        if ($suspiciousFiles.Count -gt 0) {
            Write-Host "`n  SUSPICIOUS FILES FOUND: $($suspiciousFiles.Count)/$totalFiles" -ForegroundColor Yellow
            foreach ($entry in $suspiciousFiles.GetEnumerator() | Sort-Object Key) {
                Write-Host ("    {0} : {1}" -f $entry.Key, $entry.Value) -ForegroundColor White
            }
        } else {
            Write-Host "`n  Prefetch integrity: Clean ($totalFiles files checked)" -ForegroundColor Magenta
        }
    }
} else {
    Write-Host "`nCouldnt find prefetch folder?? (check yo paths hoe)" -ForegroundColor Red
}

# -- Recycle Bin + Console History -------------------------------
try {
    $recycleBinPath = "$env:SystemDrive" + '\$Recycle.Bin'
    Write-Host "`nRECYCLE BIN" -ForegroundColor Cyan

    if (Test-Path $recycleBinPath) {
        $recycleBinFolder = Get-Item -LiteralPath $recycleBinPath -Force
        $userFolders      = Get-ChildItem -LiteralPath $recycleBinPath -Directory -Force -ErrorAction SilentlyContinue

        if ($userFolders) {
            $allDeletedItems = @()
            $latestModTime   = $recycleBinFolder.LastWriteTime

            foreach ($userFolder in $userFolders) {
                if ($userFolder.LastWriteTime -gt $latestModTime) { $latestModTime = $userFolder.LastWriteTime }
                $userItems = Get-ChildItem -LiteralPath $userFolder.FullName -File -Force -ErrorAction SilentlyContinue
                if ($userItems) {
                    $allDeletedItems += $userItems
                    $latestFile = $userItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestFile -and $latestFile.LastWriteTime -gt $latestModTime) { $latestModTime = $latestFile.LastWriteTime }
                }
            }

            Write-Host "  Last Modified: " -NoNewline -ForegroundColor White
            Write-Host $latestModTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow

            if ($allDeletedItems.Count -gt 0) {
                Write-Host "  Total Items: "  -NoNewline -ForegroundColor White; Write-Host $allDeletedItems.Count -ForegroundColor Yellow
                $latestItem = $allDeletedItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-Host "  Latest Item: "  -NoNewline -ForegroundColor White; Write-Host $latestItem.Name -ForegroundColor Gray
            } else {
                Write-Host "  Status: " -NoNewline -ForegroundColor White; Write-Host "Folders present but empty" -ForegroundColor Magenta
            }
        } else {
            Write-Host "  Status: "       -NoNewline -ForegroundColor White; Write-Host "Emptyy"                                                        -ForegroundColor Magenta
            Write-Host "  Last Modified: " -NoNewline -ForegroundColor White; Write-Host $recycleBinFolder.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Magenta
        }

        $clearEvent = Get-WinEvent -FilterHashtable @{LogName="System"; Id=10006} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($clearEvent) {
            Write-Host "  Last Cleared (Event): " -NoNewline -ForegroundColor White
            Write-Host $clearEvent.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Red
        }
    } else {
        Write-Host "  Recycle Bin not found at: $recycleBinPath" -ForegroundColor Yellow
        Write-Host "  Note: Recycle Bin may be empty or on different drive" -ForegroundColor Gray
    }

    $consoleHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    Write-Host "`n  CONSOLE HOST HISTORY" -ForegroundColor Magenta

    if (Test-Path $consoleHistoryPath) {
        $historyFile = Get-Item -Path $consoleHistoryPath -Force
        Write-Host "    Last Modified: " -NoNewline -ForegroundColor White
        Write-Host $historyFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -ForegroundColor Yellow
        $attributes = $historyFile.Attributes
        if ($attributes -ne "Archive") {
            Write-Host "    Attributes: " -NoNewline -ForegroundColor White; Write-Host $attributes -ForegroundColor Yellow
        } else {
            Write-Host "    Attributes: Normal" -ForegroundColor Magenta
        }
        $fileSize = $historyFile.Length
        Write-Host "    File Size: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($fileSize/1024, 2)) KB" -ForegroundColor Yellow
    } else {
        Write-Host "    File not found: $consoleHistoryPath"                           -ForegroundColor Yellow
        Write-Host "    Note: PowerShell history may be disabled or never used"        -ForegroundColor Gray
    }
} catch {
    Write-Host "  Error accessing system information: $($_.Exception.Message)" -ForegroundColor Red
}

# -- USB history -----------------------------------------------
Write-Host "`nUSB HISTORY" -ForegroundColor Cyan
try {
    $usbRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if (Test-Path $usbRegPath) {
        $usbDevices = Get-ChildItem -Path $usbRegPath -ErrorAction SilentlyContinue
        if ($usbDevices) {
            foreach ($device in $usbDevices) {
                $instances = Get-ChildItem -Path $device.PSPath -ErrorAction SilentlyContinue
                foreach ($instance in $instances) {
                    $props        = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                    $friendlyName = $props.FriendlyName
                    if (-not $friendlyName) { $friendlyName = $device.PSChildName -replace "_", " " }

                    # last plug-in time from the Properties subkey
                    $lastArrival = $null
                    $propKey = Join-Path $instance.PSPath "Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0065"
                    if (Test-Path $propKey) {
                        $raw = Get-ItemProperty -Path $propKey -ErrorAction SilentlyContinue
                        if ($raw.'(default)') {
                            try { $lastArrival = [datetime]::FromFileTime([BitConverter]::ToInt64($raw.'(default)', 0)) } catch {}
                        }
                    }

                    Write-Host "  * " -NoNewline -ForegroundColor Magenta
                    Write-Host $friendlyName -ForegroundColor White -NoNewline
                    if ($lastArrival) {
                        Write-Host (" | Last seen: {0}" -f $lastArrival.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Yellow
                    } else {
                        Write-Host ""
                    }
                }
            }
        } else {
            Write-Host "  No USB storage devices found in registry" -ForegroundColor Magenta
        }
    } else {
        Write-Host "  USBSTOR registry key not accessible" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Error reading USB history: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Logged-on users --------------------------------------------
Write-Host "`nLOGGED-ON USERS" -ForegroundColor Cyan
try {
    $sessions = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue |
                Where-Object { $_.LogonType -in @(2, 10, 11) }  # Interactive, RemoteInteractive, CachedInteractive

    if ($sessions) {
        foreach ($session in $sessions) {
            $assoc = Get-CimAssociatedInstance -InputObject $session -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue
            if (-not $assoc) { $assoc = Get-CimAssociatedInstance -InputObject $session -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue }

            $username = if ($assoc) { "$($assoc.Domain)\$($assoc.Name)" } else {
                # fallback - grab from Win32_ComputerSystem
                (Get-CimInstance Win32_ComputerSystem).UserName
            }

            $logonTypeMap = @{ 2="Interactive"; 10="RemoteInteractive"; 11="CachedInteractive" }
            $logonType    = $logonTypeMap[[int]$session.LogonType]
            $startTime    = if ($session.StartTime) { $session.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }

            Write-Host "  * " -NoNewline -ForegroundColor Magenta
            Write-Host ("{0,-30}" -f $username) -NoNewline -ForegroundColor White
            Write-Host (" Type: {0,-22} Since: {1}" -f $logonType, $startTime) -ForegroundColor Yellow
        }
    } else {
        # simple fallback
        $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
        if ($currentUser) {
            Write-Host "  * $currentUser" -ForegroundColor Magenta
        } else {
            Write-Host "  No active interactive sessions found" -ForegroundColor Magenta
        }
    }
} catch {
    Write-Host "  Error retrieving logged-on users: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Late JAR injection into javaw.exe -------------------------
Write-Host "`nLATE JAR INJECTION CHECK" -ForegroundColor Cyan
try {
    $mcProc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProc) { $mcProc = Get-Process java -ErrorAction SilentlyContinue }

    if (-not $mcProc) {
        Write-Host "  Minecraft (javaw/java) is not running" -ForegroundColor Gray
    } else {
        $procStartTime   = $mcProc.StartTime
        $injectionWindow = $procStartTime.AddMinutes(2)
        $suspiciousJars  = [System.Collections.Generic.List[object]]::new()
        $allJars2        = [System.Collections.Generic.List[object]]::new()

        $modsRoot = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
        if (Test-Path $modsRoot) {
            $jarFiles2 = Get-ChildItem -Path $modsRoot -Filter *.jar -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($jar in $jarFiles2) {
                $allJars2.Add($jar)
                # LastAccessTime updates when the JVM reads the file into its classloader
                if ($jar.LastAccessTime -gt $injectionWindow) {
                    $suspiciousJars.Add($jar)
                }
            }
        }

        Write-Host ("  Minecraft started:  {0}" -f $procStartTime.ToString("HH:mm:ss"))                         -ForegroundColor White
        Write-Host ("  Suspicious after:   {0}  (+2 min grace period)" -f $injectionWindow.ToString("HH:mm:ss")) -ForegroundColor Gray
        Write-Host ("  JARs in mods folder: {0}" -f $allJars2.Count)                                            -ForegroundColor White

        if ($suspiciousJars.Count -eq 0) {
            Write-Host "  No late-loaded JARs detected" -ForegroundColor Magenta
        } else {
            Write-Host ("  LATE-LOADED JARs DETECTED: {0}" -f $suspiciousJars.Count) -ForegroundColor Red
            Write-Host "  Used to check for stuff like replaces (check timestamps)" -ForegroundColor Gray
            foreach ($jar in ($suspiciousJars | Sort-Object LastAccessTime -Descending)) {
                Write-Host "    ! " -NoNewline -ForegroundColor Red
                Write-Host $jar.Name -NoNewline -ForegroundColor Yellow
                Write-Host (" | Accessed: {0}" -f $jar.LastAccessTime.ToString("HH:mm:ss")) -ForegroundColor White
            }
        }
    }
} catch {
    Write-Host "  Error during injection check: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Windows Defender real-time protection --------------------
Write-Host "`nWINDOWS DEFENDER" -ForegroundColor Cyan
try {
    $defenderKey  = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
    $defenderPol  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

    $rtpValue     = (Get-ItemProperty -Path $defenderKey  -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
    $polValue     = (Get-ItemProperty -Path $defenderPol  -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
    $tamperValue  = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue).TamperProtection

    $rtpDisabled  = ($rtpValue -eq 1) -or ($polValue -eq 1)

    Write-Host "  Real-Time Protection: " -NoNewline -ForegroundColor White
    if ($rtpDisabled) {
        Write-Host "DISABLED" -ForegroundColor Red
    } else {
        Write-Host "Enabled" -ForegroundColor Magenta
    }

    Write-Host "  Tamper Protection:    " -NoNewline -ForegroundColor White
    if ($tamperValue -eq 5) {
        Write-Host "Enabled" -ForegroundColor Magenta
    } elseif ($null -eq $tamperValue) {
        Write-Host "Unknown" -ForegroundColor Gray
    } else {
        Write-Host "DISABLED" -ForegroundColor Red
    }

    if ($polValue -eq 1) {
        Write-Host "  Note: Disabled via Group Policy" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error reading Defender status: $($_.Exception.Message)" -ForegroundColor Red
}

# -- BAM entries linked to javaw.exe ---------------------------
Write-Host "`nBAM - EXECUTABLES LINKED TO MINECRAFT SESSION" -ForegroundColor Cyan
try {
    $mcProc2 = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProc2) { $mcProc2 = Get-Process java -ErrorAction SilentlyContinue }

    if (-not $mcProc2) {
        Write-Host "  Minecraft is not running - cannot correlate BAM entries" -ForegroundColor Gray
    } else {
        $mcStart = $mcProc2.StartTime

        # BAM stores last run time per user SID under each entry's SequenceNumber subkey
        $bamRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        if (-not (Test-Path $bamRoot)) {
            $bamRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings"
        }

        if (-not (Test-Path $bamRoot)) {
            Write-Host "  BAM registry key not found - service may be disabled" -ForegroundColor Gray
        } else {
            $sidKeys   = Get-ChildItem -Path $bamRoot -ErrorAction SilentlyContinue
            $bamHits   = [System.Collections.Generic.List[object]]::new()

            foreach ($sidKey in $sidKeys) {
                $entries = Get-ItemProperty -Path $sidKey.PSPath -ErrorAction SilentlyContinue
                if (-not $entries) { continue }

                foreach ($prop in $entries.PSObject.Properties) {
                    # BAM values are binary (FILETIME); skip non-binary/meta props
                    if ($prop.Name -match '^PS|SequenceNumber|Version') { continue }
                    if ($prop.Value -isnot [byte[]]) { continue }
                    if ($prop.Value.Length -lt 8) { continue }

                    try {
                        $ft        = [BitConverter]::ToInt64($prop.Value, 0)
                        if ($ft -le 0) { continue }
                        $lastRun   = [datetime]::FromFileTime($ft)

                        # only include entries that ran within the current Minecraft session
                        if ($lastRun -lt $mcStart) { continue }

                        $exePath   = $prop.Name -replace '\\Device\\HarddiskVolume\d+', '' -replace '\\', '\'
                        $exeName   = Split-Path $exePath -Leaf

                        $bamHits.Add([PSCustomObject]@{
                            Name     = $exeName
                            FullPath = $exePath
                            LastRun  = $lastRun
                        })
                    } catch { continue }
                }
            }

            if ($bamHits.Count -eq 0) {
                Write-Host "  No BAM entries found during current Minecraft session" -ForegroundColor Magenta
            } else {
                # sort newest first, skip javaw itself
                $filtered = $bamHits | Where-Object { $_.Name -notmatch '^javaw?\.exe$' } | Sort-Object LastRun -Descending
                if ($filtered.Count -eq 0) {
                    Write-Host "  No other executables ran during current Minecraft session" -ForegroundColor Magenta
                } else {
                    Write-Host "  Executables run since Minecraft launched ($($filtered.Count) found):" -ForegroundColor Yellow
                    foreach ($entry in $filtered) {
                        $timeDiff = ($entry.LastRun - $mcStart).TotalSeconds
                        $tag      = if ($timeDiff -le 120) { " [within 2min of launch]" } else { "" }
                        $color    = if ($tag) { "Red" } else { "White" }
                        Write-Host "    * " -NoNewline -ForegroundColor Magenta
                        Write-Host ("{0,-35}" -f $entry.Name) -NoNewline -ForegroundColor $color
                        Write-Host (" {0}{1}" -f $entry.LastRun.ToString("HH:mm:ss"), $tag) -ForegroundColor $color
                    }
                }
            }
        }
    }
} catch {
    Write-Host "  Error reading BAM entries: $($_.Exception.Message)" -ForegroundColor Red
}

# -- DLLs injected into javaw.exe ------------------------------
Write-Host "`nJAVAW.EXE LOADED DLLs" -ForegroundColor Cyan
try {
    $mcProcDll = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProcDll) { $mcProcDll = Get-Process java -ErrorAction SilentlyContinue }

    if (-not $mcProcDll) {
        Write-Host "  Minecraft is not running" -ForegroundColor Gray
    } else {
        # known-good DLL whitelist - system, JVM, and common legit libs
        $knownGoodPatterns = @(
            # Windows system paths
            '\Windows\System32\',
            '\Windows\SysWOW64\',
            '\Windows\Microsoft.NET\',
            '\Windows\WinSxS\',
            # JVM / Java runtime
            '\jre\', '\jdk\', '\java\', '\openjdk\', '\zulu\',
            '\graalvm\', '\liberica\', '\corretto\', '\temurin\',
            '\adoptium\', '\semeru\',
            # Minecraft launcher locations
            '\Minecraft Launcher\', '\.minecraft\', '\minecraft\',
            '\MultiMC\', '\PrismLauncher\', '\ATLauncher\',
            # Common legit injections
            'nvidia', 'nvd3d', 'nvcuda', 'nvoglv', 'ig4icd', 'igdumd',
            'amdvlk', 'atig6pxx', 'd3d', 'dxgi', 'opengl',
            'discord', 'steam', 'gameoverlayrenderer',
            'msvcp', 'msvcr', 'vcruntime', 'ucrtbase',
            'kernel32', 'ntdll', 'user32', 'gdi32', 'shell32',
            'advapi32', 'ole32', 'oleaut32', 'comctl32', 'comdlg32',
            'ws2_32', 'wininet', 'winhttp', 'crypt32', 'bcrypt',
            'sechost', 'rpcrt4', 'shlwapi', 'wldap32',
            'dwmapi', 'uxtheme', 'imm32', 'msctf', 'textinputframework',
            'coreclr', 'clr.dll', 'clrjit',
            'lwjgl', 'openal', 'jinput', 'jna-',
            'xaudio', 'audioses', 'mmdevapi'
        )

        $modules     = $mcProcDll.Modules | Sort-Object FileName
        $suspectDlls = [System.Collections.Generic.List[object]]::new()

        foreach ($mod in $modules) {
            $path  = $mod.FileName
            $lower = $path.ToLower()
            $isKnown = $false
            foreach ($pattern in $knownGoodPatterns) {
                if ($lower -contains $pattern.ToLower() -or $lower -like "*$($pattern.ToLower())*") {
                    $isKnown = $true; break
                }
            }
            if (-not $isKnown) { $suspectDlls.Add($mod) }
        }

        Write-Host ("  Total DLLs loaded: {0}" -f $modules.Count) -ForegroundColor White
        Write-Host "  - Don't ban for this its just helpful cus sometimes its real but it can also false flag to manualy check it" -ForegroundColor Gray

        if ($suspectDlls.Count -eq 0) {
            Write-Host "  No unexpected DLLs found" -ForegroundColor Green
        } else {
            Write-Host ("  UNEXPECTED DLLs: {0}" -f $suspectDlls.Count) -ForegroundColor Red
            foreach ($dll in $suspectDlls) {
                Write-Host "    ! " -NoNewline -ForegroundColor Red
                Write-Host ("{0,-35}" -f $dll.ModuleName) -NoNewline -ForegroundColor Yellow
                Write-Host $dll.FileName -ForegroundColor Gray
            }
            $verdictFlags.Add("Unexpected DLLs loaded into javaw.exe ($($suspectDlls.Count) found)")
        }
    }
} catch {
    Write-Host "  Error reading DLL list: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Process Tree Analysis --------------------------------------
Write-Host "`nPROCESS TREE ANALYSIS" -ForegroundColor Cyan
try {
    $mcProc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $mcProc) { $mcProc = Get-Process java -ErrorAction SilentlyContinue }

    if (-not $mcProc) {
        Write-Host "  Minecraft is not running - cannot analyze process tree" -ForegroundColor Gray
    } else {
        Write-Host ("  Minecraft PID: {0}" -f $mcProc.Id) -ForegroundColor White
        Write-Host ("  Process Name: {0}" -f $mcProc.ProcessName) -ForegroundColor White
        Write-Host ("  Started: {0}" -f $mcProc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White

        # Get parent process
        $parentProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($mcProc.Id)" | ForEach-Object { 
            if ($_.ParentProcessId) { Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue }
        }

        if ($parentProc) {
            Write-Host ("  Parent Process: {0} (PID: {1})" -f $parentProc.ProcessName, $parentProc.Id) -ForegroundColor Yellow
            Write-Host ("  Parent Started: {0}" -f $parentProc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Yellow
            
            # Check if parent is suspicious
            $suspiciousParents = @("cmd", "powershell", "wscript", "cscript", "rundll32", "mshta")
            if ($suspiciousParents -contains $parentProc.ProcessName.ToLower()) {
                Write-Host "  ! WARNING: Minecraft launched from suspicious parent process!" -ForegroundColor Red
                $verdictFlags.Add("Minecraft launched from suspicious parent process ($($parentProc.ProcessName))")
            }
        } else {
            Write-Host "  Parent Process: Unknown" -ForegroundColor Gray
        }

        # Get child processes
        $childProcs = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ParentProcessId -eq $mcProc.Id }
        if ($childProcs) {
            Write-Host ("  Child Processes: {0} found" -f $childProcs.Count) -ForegroundColor Yellow
            foreach ($child in $childProcs) {
                try {
                    $childProc = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                    if ($childProc) {
                        Write-Host ("    * {0} (PID: {1}) - Started: {2}" -f $childProc.ProcessName, $childProc.Id, $childProc.StartTime.ToString("HH:mm:ss")) -ForegroundColor White
                        
                        # Check if child is suspicious
                        $suspiciousChildren = @("cmd", "powershell", "wscript", "cscript", "rundll32", "mshta", "regsvr32")
                        if ($suspiciousChildren -contains $childProc.ProcessName.ToLower()) {
                            Write-Host "      ! WARNING: Suspicious child process detected!" -ForegroundColor Red
                            $verdictFlags.Add("Suspicious child process spawned by Minecraft ($($childProc.ProcessName))")
                        }
                    }
                } catch { }
            }
        } else {
            Write-Host "  Child Processes: None" -ForegroundColor Green
        }

        # Analyze process tree depth and injection chains
        $processChain = @()
        $currentProc = $mcProc
        
        # Build process chain backwards
        for ($i = 0; $i -lt 5; $i++) {  # Limit depth to prevent infinite loops
            $parent = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($currentProc.Id)" | ForEach-Object { 
                if ($_.ParentProcessId) { Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue }
            }
            if ($parent) {
                $processChain = @($parent) + $processChain
                $currentProc = $parent
            } else {
                break
            }
        }

        if ($processChain.Count -gt 0) {
            Write-Host "  Process Chain (Parent -> Child):" -ForegroundColor Yellow
            $chainStr = $processChain.ProcessName -join " -> "
            $chainStr += " -> $($mcProc.ProcessName)"
            Write-Host ("    {0}" -f $chainStr) -ForegroundColor White
            
            # Check for suspicious chain patterns
            $chainStrLower = $chainStr.ToLower()
            if ($chainStrLower -match "cmd.*powershell.*java" -or $chainStrLower -match "wscript.*java") {
                Write-Host "    ! WARNING: Potential injection chain detected!" -ForegroundColor Red
                $verdictFlags.Add("Suspicious process injection chain detected")
            }
        }

        Write-Host "  Used to detect injection chains and suspicious parent/child relationships" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Error during process tree analysis: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Hidden Files Detection in Mods Folder --------------------
Write-Host "`nHIDDEN FILES DETECTION" -ForegroundColor Cyan
try {
    $modsRoot = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    if (Test-Path $modsRoot) {
        $allFiles = Get-ChildItem -Path $modsRoot -Recurse -Force -ErrorAction SilentlyContinue
        $hiddenFiles = [System.Collections.Generic.List[object]]::new()
        $systemFiles = [System.Collections.Generic.List[object]]::new()
        $hiddenAndSystemFiles = [System.Collections.Generic.List[object]]::new()
        
        foreach ($file in $allFiles) {
            $isHidden = $file.Attributes -band [System.IO.FileAttributes]::Hidden
            $isSystem = $file.Attributes -band [System.IO.FileAttributes]::System
            
            if ($isHidden -and $isSystem) {
                $hiddenAndSystemFiles += $file
            } elseif ($isHidden) {
                $hiddenFiles += $file
            } elseif ($isSystem) {
                $systemFiles += $file
            }
        }
        
        Write-Host "  Scanning: $modsRoot" -ForegroundColor Gray
        Write-Host "  Total files found: $($allFiles.Count)" -ForegroundColor White
        
        if ($hiddenAndSystemFiles.Count -gt 0) {
            Write-Host "  Hidden + System Files: $($hiddenAndSystemFiles.Count) found" -ForegroundColor Red
            foreach ($file in $hiddenAndSystemFiles) {
                Write-Host "    !! " -NoNewline -ForegroundColor Red
                Write-Host ("{0,-50}" -f $file.Name) -NoNewline -ForegroundColor Yellow
                Write-Host (" | Modified: {0}" -f $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Gray
            }
            $verdictFlags.Add("Hidden AND System files in mods folder ($($hiddenAndSystemFiles.Count) found)")
        }
        
        if ($hiddenFiles.Count -gt 0) {
            Write-Host "  Hidden Files: $($hiddenFiles.Count) found" -ForegroundColor Yellow
            foreach ($file in $hiddenFiles) {
                Write-Host "    ! " -NoNewline -ForegroundColor Yellow
                Write-Host ("{0,-50}" -f $file.Name) -NoNewline -ForegroundColor Yellow
                Write-Host (" | Modified: {0}" -f $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Gray
            }
            $verdictWarnings.Add("Hidden files in mods folder ($($hiddenFiles.Count) found)")
        }
        
        if ($systemFiles.Count -gt 0) {
            Write-Host "  System Files: $($systemFiles.Count) found" -ForegroundColor Yellow
            foreach ($file in $systemFiles) {
                Write-Host "    ! " -NoNewline -ForegroundColor Yellow
                Write-Host ("{0,-50}" -f $file.Name) -NoNewline -ForegroundColor Yellow
                Write-Host (" | Modified: {0}" -f $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Gray
            }
            $verdictWarnings.Add("System files in mods folder ($($systemFiles.Count) found)")
        }
        
        if ($hiddenAndSystemFiles.Count -eq 0 -and $hiddenFiles.Count -eq 0 -and $systemFiles.Count -eq 0) {
            Write-Host "  No hidden or system files found" -ForegroundColor Green
        }
        
        # Check for suspicious file extensions that might be hidden
        $suspiciousExtensions = @(".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".ps1", ".dll", ".com", ".pif")
        $suspiciousHiddenFiles = @()
        
        foreach ($file in $allFiles) {
            if ($file.Extension -in $suspiciousExtensions -and ($file.Attributes -band [System.IO.FileAttributes]::Hidden)) {
                $suspiciousHiddenFiles += $file
            }
        }
        
        if ($suspiciousHiddenFiles.Count -gt 0) {
            Write-Host "  !! WARNING: Suspicious hidden executables found !!" -ForegroundColor Red
            foreach ($file in $suspiciousHiddenFiles) {
                Write-Host "    !!! " -NoNewline -ForegroundColor Red
                Write-Host ("{0,-50}" -f $file.Name) -NoNewline -ForegroundColor Red
                Write-Host (" | Size: {0} bytes" -f $file.Length) -ForegroundColor Gray
            }
            $verdictFlags.Add("Suspicious hidden executables in mods folder ($($suspiciousHiddenFiles.Count) found)")
        }
        
        Write-Host "  Used to detect cheat files hidden by attackers" -ForegroundColor Gray
    } else {
        Write-Host "  Mods folder not found: $modsRoot" -ForegroundColor Gray
    }
} catch {
    Write-Host "  Error during hidden files detection: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Collect verdict signals from Part 1 -----------------------
# Defender off
$rtpOff = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
$polOff = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
if ($rtpOff -eq 1 -or $polOff -eq 1) { $verdictFlags.Add("Windows Defender real-time protection is OFF") }

# Prefetch suspicious files
if ($suspiciousFiles.Count -gt 0) { $verdictWarnings.Add("Suspicious prefetch files found ($($suspiciousFiles.Count))") }

# Late JAR injection (reuse $suspiciousJars if in scope)
if ($suspiciousJars -and $suspiciousJars.Count -gt 0) { $verdictFlags.Add("Late-loaded JARs detected ($($suspiciousJars.Count))") }

# Event log cleared
$logCleared = Get-WinEvent -FilterHashtable @{LogName="System"; Id=@(104,1102)} -MaxEvents 1 -ErrorAction SilentlyContinue
if ($logCleared) { $verdictWarnings.Add("Event log was cleared recently") }

Write-Host "`ndone." -ForegroundColor Cyan


# ============================================================
#  TRANSITION TO PART 2
# ============================================================
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "  Press any key to continue to the Mod Analyzer..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


# ============================================================
#  PART 2 - VOID MOD ANALYZER
# ============================================================

$Banner = @"
I have aura
"@

Write-Host $Banner -ForegroundColor Magenta
Write-Host ""
Write-Host "                hate bypass " -ForegroundColor Gray -NoNewline
Write-Host "<3 "           -ForegroundColor Magenta -NoNewline
Write-Host "by "           -ForegroundColor Gray -NoNewline
Write-Host "exortenne"  -ForegroundColor Magenta
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host

Write-Host "Enter path to the mods folder: " -NoNewline
Write-Host "(press Enter to use default)" -ForegroundColor Gray
$modsPath = Read-Host "PATH"
Write-Host

if ([string]::IsNullOrWhiteSpace($modsPath)) {
    $modsPath = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    Write-Host "Continuing with " -NoNewline
    Write-Host $modsPath -ForegroundColor White
    Write-Host
}

if (-not (Test-Path $modsPath -PathType Container)) {
    Write-Host "Invalid Path!" -ForegroundColor Red
    Write-Host "The directory does not exist or is not accessible." -ForegroundColor Yellow
    Write-Host
    Write-Host "Tried to access: $modsPath" -ForegroundColor Gray
    Write-Host
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "Scanning directory: $modsPath" -ForegroundColor Magenta
Write-Host

$mcProcess = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $mcProcess) { $mcProcess = Get-Process java -ErrorAction SilentlyContinue }
if ($mcProcess) {
    try {
        $startTime = $mcProcess.StartTime
        $uptime    = (Get-Date) - $startTime
        Write-Host "{ Minecraft Uptime }" -ForegroundColor Gray
        Write-Host "   $($mcProcess.Name) PID $($mcProcess.Id) started at $startTime" -ForegroundColor Gray
        Write-Host "   Running for: $($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s" -ForegroundColor Gray
        Write-Host ""
    } catch { }
}

# -- Helper functions -----------------------------------------
# Obfuscated function names
function AV-Show-Progress {
    param(
        [int]$Current,
        [int]$Total,
        [string]$Activity,
        [string]$Status = "Processing"
    )
    
    $percentComplete = if ($Total -gt 0) { [math]::Round(($Current / $Total) * 100) } else { 0 }
    $progressBar = "[$percentComplete%] "
    $barLength = 30
    $filledLength = [math]::Round(($percentComplete / 100) * $barLength)
    $emptyLength = $barLength - $filledLength
    
    $progressBar += "[" + ("#" * $filledLength) + (" " * $emptyLength) + "]"
    
    Write-Host "`r$progressBar $Activity - $Status ($Current/$Total)" -NoNewline -ForegroundColor Cyan
    if ($Current -eq $Total) { Write-Host "" }
}

function Get-FileSHA1 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA1).Hash
}

function Get-DownloadSource {
    param([string]$Path)
    $zoneData = Get-Content -Raw -Stream Zone.Identifier $Path -ErrorAction SilentlyContinue
    if ($zoneData -match "HostUrl=(.+)") {
        $url = $matches[1].Trim()
        if ($url -match "mediafire\.com")                                        { return "MediaFire" }
        elseif ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { return "Discord" }
        elseif ($url -match "dropbox\.com")                                      { return "Dropbox" }
        elseif ($url -match "drive\.google\.com")                                { return "Google Drive" }
        elseif ($url -match "mega\.nz|mega\.co\.nz")                             { return "MEGA" }
        elseif ($url -match "github\.com")                                       { return "GitHub" }
        elseif ($url -match "modrinth\.com")                                     { return "Modrinth" }
        elseif ($url -match "curseforge\.com")                                   { return "CurseForge" }
        elseif ($url -match "anydesk\.com")                                      { return "AnyDesk" }
        elseif ($url -match "doomsdayclient\.com")                               { return "DoomsdayClient" }
        elseif ($url -match "prestigeclient\.vip")                               { return "PrestigeClient" }
        elseif ($url -match "198macros\.com")                                    { return "198Macros" }
        else {
            if ($url -match "https?://(?:www\.)?([^/]+)") { return $matches[1] }
            return $url
        }
    }
    return $null
}

function Query-Modrinth {
    param([string]$Hash)
    try {
        $versionInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($versionInfo.project_id) {
            $projectInfo = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($versionInfo.project_id)" -Method Get -UseBasicParsing -ErrorAction Stop
            return @{ Name = $projectInfo.title; Slug = $projectInfo.slug }
        }
    } catch { }
    return @{ Name = ""; Slug = "" }
}

function Query-Megabase {
    param([string]$Hash)
    try {
        $result = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$Hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if (-not $result.error) { return $result.data }
    } catch { }
    return $null
}

# -- Detection lists -------------------------------------------
$suspiciousPatterns = @(
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "Hitboxes", "JumpReset", "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "Velocity", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer",
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod", "Reach",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag",
    "BlockESP", "dev.krypton", "Virgin", "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "AntiBot",
    "ElytraSwap", "FastXP", "FastExp", "Refill", "NoJumpDelay", "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "PackSpoof", "Antiknockback", "scrim", "catlean", "Argon",
    "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "Grim", "grim",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui", "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Flight", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "ji.class", "hu.class", "bu.class", "pu.class", "ta.class",
    "ne.class", "so.class", "na.class", "do.class", "gu.class",
    "zu.class", "de.class", "tsu.class", "be.class", "se.class",
    "to.class", "mi.class", "bi.class", "su.class", "no.class"
)

$cheatStrings = @(
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal",
    "dontPlaceCrystal", "dontBreakCrystal",
    "AutoHitCrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor",
    "hasGlowstone", "HasAnchor", "anchortweaks", "anchor macro", "safe anchor", "safeanchor",
    "AutoTotem", "autototem", "auto totem", "InventoryTotem",
    "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor",
    "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "AutoDoubleHand", "autodoublehand", "auto double hand",
    "AutoClicker",
    "Failed to switch to mace after axe!",
    "Breaking shield with axe...",
    "Donut", "JumpReset", "axespam", "axe spam",
    "shieldbreaker", "shield breaker", "EndCrystalItemMixin",
    "findKnockbackSword", "attackRegisteredThisClick",
    "AimAssist", "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "FakeInv", "Friends", "swapBackToOriginalSlot",
    "FakeLag", "pingspoof", "ping spoof", "velocity",
    "webmacro", "web macro",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct",
    "AutoMace", "AutoFirework", "MaceSwap", "AirAnchor",
    "ElytraSwap", "FastXP", "FastExp", "NoJumpDelay",
    "PackSpoof", "Antiknockback", "scrim", "catlean",
    "AuthBypass", "obfuscatedAuth", "LicenseCheckMixin",
    "BaseFinder", "invsee", "ItemExploit",
    "NoFall", "nofall",
    "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
    "autoCrystalPlaceClock",
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown",
    "onBlockBreaking", "setItemUseCooldown",
    "setSelectedSlot", "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onTickMovement", "onPushOutOfBlocks", "onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString", "POT_CHEATS",
    "Dqrkis Client", "Entity.isGlowing"
)

# -- Bypass / injection scan -----------------------------------
function Invoke-BypassScan {
    param([string]$FilePath)

    $flags = [System.Collections.Generic.List[string]]::new()
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $mavenPrefixes = @(
        "com_","org_","net_","io_","dev_","gs_","xyz_",
        "app_","me_","tv_","uk_","be_","fr_","de_"
    )

    function Test-SuspiciousJarName {
        param([string]$JarName)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName)
        if ($base -match '\d') { return $false }
        foreach ($pfx in $mavenPrefixes) { if ($base.ToLower().StartsWith($pfx)) { return $false } }
        if ($base.Length -gt 20) { return $false }
        return $true
    }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $nestedJars   = @($zip.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })
        $outerClasses = @($zip.Entries | Where-Object { $_.FullName -match "\.class$" })

        $suspiciousNestedJars = @()
        foreach ($nj in $nestedJars) {
            $njBase = [System.IO.Path]::GetFileName($nj.FullName)
            if (Test-SuspiciousJarName -JarName $njBase) { $suspiciousNestedJars += $njBase }
        }
        foreach ($sj in $suspiciousNestedJars) {
            $flags.Add("Suspicious nested JAR - no version number, not a known dependency: $sj")
        }

        if ($nestedJars.Count -eq 1 -and $outerClasses.Count -lt 3) {
            $njName = [System.IO.Path]::GetFileName(($nestedJars | Select-Object -First 1).FullName)
            $flags.Add("Hollow shell - outer JAR has only $($outerClasses.Count) own class(es) but wraps: $njName")
        }

        $outerModId = ""
        $fmje = $zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
        if ($fmje) {
            try {
                $s = $fmje.Open(); $r = New-Object System.IO.StreamReader($s)
                $t = $r.ReadToEnd(); $r.Close(); $s.Close()
                if ($t -match '"id"\s*:\s*"([^"]+)"') { $outerModId = $matches[1] }
            } catch { }
        }

        $allEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $zip.Entries) { $allEntries.Add($e) }

        $innerZips = [System.Collections.Generic.List[object]]::new()
        foreach ($nj in $nestedJars) {
            try {
                $ns = $nj.Open(); $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close(); $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerZips.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch { }
        }

        $runtimeExecFound  = $false
        $httpDownloadFound = $false
        $httpExfilFound    = $false
        $obfuscatedCount   = 0
        $totalClassCount   = 0

        foreach ($entry in $allEntries) {
            $name = $entry.FullName
            if ($name -match "\.class$") {
                $totalClassCount++
                $segs = ($name -replace "\.class$","") -split "/"
                $consecutiveSingle = 0; $maxConsecutive = 0
                foreach ($seg in $segs) {
                    if ($seg.Length -eq 1) { $consecutiveSingle++; if ($consecutiveSingle -gt $maxConsecutive) { $maxConsecutive = $consecutiveSingle } }
                    else { $consecutiveSingle = 0 }
                }
                if ($maxConsecutive -ge 3) { $obfuscatedCount++ }

                try {
                    $st = $entry.Open(); $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2); $st.Close()
                    $rawBytes = $ms2.ToArray(); $ms2.Dispose()
                    $ct = [System.Text.Encoding]::ASCII.GetString($rawBytes)

                    if ($ct -match "java/lang/Runtime" -and $ct -match "getRuntime" -and $ct -match "exec") { $runtimeExecFound = $true }
                    if ($ct -match "openConnection" -and $ct -match "HttpURLConnection" -and $ct -match "FileOutputStream") { $httpDownloadFound = $true }
                    if ($ct -match "openConnection" -and $ct -match "setDoOutput" -and $ct -match "getOutputStream" -and $ct -match "getProperty") { $httpExfilFound = $true }
                } catch { }
            }
        }

        foreach ($iz in $innerZips) { try { $iz.Dispose() } catch { } }
        $zip.Dispose()

        $obfPct = if ($totalClassCount -ge 10) { [math]::Round(($obfuscatedCount / $totalClassCount) * 100) } else { 0 }

        if ($runtimeExecFound -and $obfPct -ge 40) {
            $flags.Add("Runtime.exec() inside obfuscated code - mod can execute arbitrary OS commands (combined with heavy obfuscation this is a strong malice indicator)")
        }
        if ($httpDownloadFound) {
            $flags.Add("HTTP file download - mod fetches and writes files from a remote server at runtime (no legitimate Fabric mod does this)")
        }
        if ($httpExfilFound) {
            $flags.Add("HTTP POST exfiltration - mod reads system properties and sends data to an external server (possible token/session theft)")
        }
        if ($totalClassCount -ge 10 -and $obfPct -ge 40) {
            $flags.Add("Heavy obfuscation - $obfPct% of classes have 3+ consecutive single-letter path segments (a/b/c style). Legitimate mods never do this.")
        }

        $knownLegitModIds = @(
            "vmp-fabric","vmp","lithium","sodium","iris","fabric-api",
            "modmenu","ferrite-core","lazydfu","starlight","entityculling",
            "memoryleakfix","krypton","c2me-fabric","smoothboot-fabric",
            "immediatelyfast","noisium","threadtweak"
        )
        $dangerCount = ($flags | Where-Object { $_ -match "Runtime\.exec|HTTP file download|HTTP POST|Heavy obfuscation|Suspicious nested JAR" }).Count
        if ($outerModId -and ($knownLegitModIds -contains $outerModId) -and $dangerCount -gt 0) {
            $flags.Add("Fake mod identity - outer JAR claims to be '$outerModId' but dangerous code was found inside (trojanized build)")
        }
    } catch { }

    return $flags
}

# -- Pattern + string scan -------------------------------------
function Invoke-ModScan {
    param([string]$FilePath)

    $foundPatterns = [System.Collections.Generic.HashSet[string]]::new()
    $foundStrings  = [System.Collections.Generic.HashSet[string]]::new()
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    try {
        $patternRegex = [regex]::new(
            '(?<![A-Za-z])(' + ($suspiciousPatterns -join '|') + ')(?![A-Za-z])',
            [System.Text.RegularExpressions.RegexOptions]::Compiled
        )
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        foreach ($entry in $archive.Entries) {
            foreach ($m in $patternRegex.Matches($entry.FullName)) { [void]$foundPatterns.Add($m.Value) }
            if ($entry.FullName -match '\.(class|json)$' -or $entry.FullName -match 'MANIFEST\.MF') {
                try {
                    $stream  = $entry.Open(); $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd(); $reader.Close(); $stream.Close()
                    foreach ($m in $patternRegex.Matches($content)) { [void]$foundPatterns.Add($m.Value) }
                } catch { }
            }
        }
        $archive.Dispose()
    } catch { }

    try {
        $stringsExe = @(
            "C:\Program Files\Git\usr\bin\strings.exe",
            "C:\Program Files\Git\mingw64\bin\strings.exe",
            "$env:ProgramFiles\Git\usr\bin\strings.exe",
            "C:\msys64\usr\bin\strings.exe",
            "C:\cygwin64\bin\strings.exe"
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($stringsExe) {
            $tmp = Join-Path $env:TEMP "void_str_$(Get-Random).txt"
            & $stringsExe $FilePath 2>$null | Out-File $tmp -Encoding UTF8
            if (Test-Path $tmp) {
                $raw = Get-Content $tmp -Raw
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                foreach ($s in $cheatStrings) {
                    if ($s -eq "velocity") {
                        if ($raw -match "velocity(?:hack|module|cheat|bypass|packet|horizontal|vertical|amount|factor|setting)") { [void]$foundStrings.Add($s) }
                    } elseif ($raw -match [regex]::Escape($s)) { [void]$foundStrings.Add($s) }
                }
            }
        } else {
            $rawText = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($FilePath))
            foreach ($s in $cheatStrings) {
                if ($s -eq "velocity") {
                    if ($rawText -match "velocity(?:hack|module|cheat|bypass|packet|horizontal|vertical|amount|factor|setting)") { [void]$foundStrings.Add($s) }
                } elseif ($rawText -match [regex]::Escape($s)) { [void]$foundStrings.Add($s) }
            }
            try {
                $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
                foreach ($entry in ($zip.Entries | Where-Object { $_.Name -like "*.class" })) {
                    try {
                        $stream = $entry.Open(); $reader = New-Object System.IO.StreamReader($stream)
                        $classText = $reader.ReadToEnd(); $reader.Close(); $stream.Close()
                        foreach ($s in $cheatStrings) {
                            if ($s -eq "velocity") {
                                if ($classText -match "velocity(?:hack|module|cheat|bypass|packet|horizontal|vertical|amount|factor|setting)") { [void]$foundStrings.Add($s) }
                            } elseif ($classText -match [regex]::Escape($s)) { [void]$foundStrings.Add($s) }
                        }
                    } catch { }
                }
                $zip.Dispose()
            } catch { }
        }
    } catch { }

    return @{ Patterns = $foundPatterns; Strings = $foundStrings }
}

# -- Scan passes -----------------------------------------------
$verifiedMods   = @()
$unknownMods    = @()
$suspiciousMods = @()
$bypassMods     = @()

try {
    $jarFiles = Get-ChildItem -Path $modsPath -Filter *.jar -ErrorAction Stop
} catch {
    Write-Host "Error accessing directory: $_" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

if ($jarFiles.Count -eq 0) {
    Write-Host "No JAR files found in: $modsPath" -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}

$fileWord      = if ($jarFiles.Count -eq 1) { "file" } else { "files" }
Write-Host "Found $($jarFiles.Count) JAR $fileWord to analyze" -ForegroundColor Magenta
Write-Host

$spinnerFrames = @("","|","/","-","\")
$totalFiles    = $jarFiles.Count
$idx           = 0

# Pass 1 - hash lookup
Write-Host "Verifying mod hashes against Modrinth/Megabase databases..." -ForegroundColor Magenta
Write-Host ""
foreach ($jar in $jarFiles) {
    $idx++
    AV-Show-Progress -Current $idx -Total $totalFiles -Activity "Hash Verification" -Status "Checking $($jar.Name)"

    $hash = Get-FileSHA1 -Path $jar.FullName
    if ($hash) {
        $modrinthData = Query-Modrinth -Hash $hash
        if ($modrinthData.Slug) { $verifiedMods += [PSCustomObject]@{ ModName = $modrinthData.Name; FileName = $jar.Name; FilePath = $jar.FullName }; continue }
        $megabaseData = Query-Megabase -Hash $hash
        if ($megabaseData.name) { $verifiedMods += [PSCustomObject]@{ ModName = $megabaseData.Name; FileName = $jar.Name; FilePath = $jar.FullName }; continue }
    }

    $src = Get-DownloadSource $jar.FullName
    $unknownMods += [PSCustomObject]@{ FileName = $jar.Name; FilePath = $jar.FullName; DownloadSource = $src }
}

Write-Host ""

# Pass 2 - deep scan
$modWord = if ($totalFiles -eq 1) { "mod" } else { "mods" }
Write-Host "Deep-scanning for suspicious patterns and strings..." -ForegroundColor Magenta
Write-Host ""
$idx = 0

foreach ($jar in $jarFiles) {
    $idx++
    AV-Show-Progress -Current $idx -Total $totalFiles -Activity "Pattern Scan" -Status "Analyzing $($jar.Name)"

    $result = Invoke-ModScan -FilePath $jar.FullName
    if ($result.Patterns.Count -gt 0 -or $result.Strings.Count -gt 0) {
        $suspiciousMods += [PSCustomObject]@{ FileName = $jar.Name; Patterns = $result.Patterns; Strings = $result.Strings }
        $verifiedMods    = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
    }
}

Write-Host ""

# Pass 3 - bypass scan
Write-Host "Running bypass/injection analysis..." -ForegroundColor Gray
Write-Host ""
$idx = 0

foreach ($jar in $jarFiles) {
    $idx++
    AV-Show-Progress -Current $idx -Total $totalFiles -Activity "Bypass Analysis" -Status "Scanning $($jar.Name)"

    $bypassFlags = Invoke-BypassScan -FilePath $jar.FullName
    if ($bypassFlags.Count -gt 0) {
        $bypassMods  += [PSCustomObject]@{ FileName = $jar.Name; Flags = $bypassFlags }
        $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $jar.Name }
        $unknownMods  = $unknownMods  | Where-Object { $_.FileName -ne $jar.Name }
    }
}

Write-Host "`r$(' ' * 100)`r" -NoNewline

# -- Results --------------------------------------------------
Write-Host "`n" + ("=" * 76) -ForegroundColor Gray

if ($verifiedMods.Count -gt 0) {
    Write-Host "VERIFIED MODS ($($verifiedMods.Count))" -ForegroundColor Magenta
    Write-Host ("-" * 76) -ForegroundColor Gray
    foreach ($mod in $verifiedMods) {
        Write-Host "  v " -ForegroundColor Magenta -NoNewline
        Write-Host "$($mod.ModName)" -ForegroundColor White -NoNewline
        Write-Host " -> " -ForegroundColor Gray -NoNewline
        Write-Host "$($mod.FileName)" -ForegroundColor Gray
    }
    Write-Host ""
}

if ($unknownMods.Count -gt 0) {
    Write-Host "UNKNOWN MODS ($($unknownMods.Count))" -ForegroundColor Yellow
    Write-Host ("-" * 76) -ForegroundColor Gray
    foreach ($mod in $unknownMods) {
        $name = $mod.FileName
        if ($name.Length -gt 50) { $name = $name.Substring(0,47) + "..." }
        $topLine    = "  +- ? " + $name + " " + ("-" * (65 - $name.Length)) + "+"
        $sourceText = if ($mod.DownloadSource) { "Source: $($mod.DownloadSource)" } else { "Source: ?" }
        $bottomLine = "  +- " + $sourceText + " " + ("-" * (67 - $sourceText.Length)) + "+"
        Write-Host $topLine    -ForegroundColor Yellow
        Write-Host $bottomLine -ForegroundColor Yellow
        Write-Host ""
    }
}

if ($suspiciousMods.Count -gt 0) {
    Write-Host "SUSPICIOUS MODS ($($suspiciousMods.Count))" -ForegroundColor Red
    Write-Host ("-" * 76) -ForegroundColor Gray
    Write-Host ""
    foreach ($mod in $suspiciousMods) {
        Write-Host "  +--- " -ForegroundColor Red -NoNewline
        Write-Host "FLAGGED" -ForegroundColor White -BackgroundColor DarkRed -NoNewline
        Write-Host " -----------------------------------------------------" -ForegroundColor Red
        Write-Host "  |" -ForegroundColor Red
        Write-Host "  |  File: " -ForegroundColor Red -NoNewline
        Write-Host "$($mod.FileName)" -ForegroundColor Yellow
        if ($mod.Patterns.Count -gt 0) {
            Write-Host "  |" -ForegroundColor Red
            Write-Host "  |  Detected Patterns:" -ForegroundColor Red
            foreach ($p in ($mod.Patterns | Sort-Object)) {
                Write-Host "  |    * " -ForegroundColor Red -NoNewline; Write-Host "$p" -ForegroundColor White
            }
        }
        $uniqueStrings = $mod.Strings | Where-Object { $mod.Patterns -notcontains $_ } | Sort-Object
        if ($uniqueStrings.Count -gt 0) {
            Write-Host "  |" -ForegroundColor Red
            Write-Host "  |  Detected Strings:" -ForegroundColor DarkRed
            foreach ($s in $uniqueStrings) {
                Write-Host "  |    * " -ForegroundColor DarkRed -NoNewline; Write-Host "$s" -ForegroundColor DarkRed
            }
        }
        Write-Host "  |" -ForegroundColor Red
        Write-Host "  +-----------------------------------------------------------" -ForegroundColor Red
        Write-Host ""
    }
}

if ($bypassMods.Count -gt 0) {
    Write-Host "BYPASS / INJECTION DETECTED ($($bypassMods.Count))" -ForegroundColor Magenta
    Write-Host ("-" * 76) -ForegroundColor Gray
    Write-Host ""
    foreach ($mod in $bypassMods) {
        Write-Host "  +--- " -ForegroundColor Magenta -NoNewline
        Write-Host "INJECTION" -ForegroundColor White -BackgroundColor DarkMagenta -NoNewline
        Write-Host " ---------------------------------------------------" -ForegroundColor Magenta
        Write-Host "  |" -ForegroundColor Magenta
        Write-Host "  |  File: " -ForegroundColor Magenta -NoNewline
        Write-Host "$($mod.FileName)" -ForegroundColor Yellow
        Write-Host "  |" -ForegroundColor Magenta
        Write-Host "  |  Bypass Flags:" -ForegroundColor Magenta
        foreach ($flag in $mod.Flags) {
            Write-Host "  |    ! " -ForegroundColor Magenta -NoNewline; Write-Host "$flag" -ForegroundColor White
        }
        Write-Host "  |" -ForegroundColor Magenta
        Write-Host "  +---------------------------------------------------------" -ForegroundColor Magenta
        Write-Host ""
    }
}

Write-Host "SUMMARY" -ForegroundColor Magenta
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host "  Total files scanned: " -ForegroundColor Gray -NoNewline; Write-Host "$totalFiles"              -ForegroundColor White
Write-Host "  Verified mods:       " -ForegroundColor Gray -NoNewline; Write-Host "$($verifiedMods.Count)"   -ForegroundColor Green
Write-Host "  Unknown mods:        " -ForegroundColor Gray -NoNewline; Write-Host "$($unknownMods.Count)"    -ForegroundColor Yellow
Write-Host "  Suspicious mods:     " -ForegroundColor Gray -NoNewline; Write-Host "$($suspiciousMods.Count)" -ForegroundColor Red
Write-Host "  Bypass/Injected:     " -ForegroundColor Gray -NoNewline; Write-Host "$($bypassMods.Count)"     -ForegroundColor Magenta
Write-Host
Write-Host ("=" * 76) -ForegroundColor Gray

# -- Collect Part 2 verdict signals ----------------------------
if ($suspiciousMods.Count -gt 0) { $verdictFlags.Add("Suspicious mods detected ($($suspiciousMods.Count))") }
if ($bypassMods.Count -gt 0)     { $verdictFlags.Add("Bypass/injected mods detected ($($bypassMods.Count))") }
if ($unknownMods.Count -gt 0)    { $verdictWarnings.Add("Unknown mods not on Modrinth/Megabase ($($unknownMods.Count))") }

# -- FINAL VERDICT ---------------------------------------------
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host "  FINAL VERDICT" -ForegroundColor Cyan
Write-Host ("=" * 76) -ForegroundColor Gray

if ($verdictFlags.Count -gt 0) {
    Write-Host ""
    Write-Host "  * FLAGGED *" -ForegroundColor White -BackgroundColor DarkRed
    Write-Host ""
    Write-Host "  Hard flags:" -ForegroundColor Red
    foreach ($f in $verdictFlags) {
        Write-Host "    * $f" -ForegroundColor Red
    }
    if ($verdictWarnings.Count -gt 0) {
        Write-Host ""
        Write-Host "  Also worth reviewing:" -ForegroundColor Yellow
        foreach ($w in $verdictWarnings) {
            Write-Host "    * $w" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "  Note: Some flags can false flag legitimate software - manual verification recommended" -ForegroundColor Gray
    Write-Host "  for highly suspicious items before taking any action" -ForegroundColor Gray
} elseif ($verdictWarnings.Count -gt 0) {
    Write-Host ""
    Write-Host "  * REVIEW *" -ForegroundColor White -BackgroundColor DarkYellow
    Write-Host ""
    Write-Host "  Nothing confirmed but worth checking:" -ForegroundColor Yellow
    foreach ($w in $verdictWarnings) {
        Write-Host "    * $w" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "  * CLEAN *" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host ""
    Write-Host "  No flags or warnings raised across both tools" -ForegroundColor Green
}
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "  Analysis complete! " -ForegroundColor Magenta
Write-Host ""
Write-Host "  Created by: "  -ForegroundColor White    -NoNewline
Write-Host "exortenne"    -ForegroundColor Magenta
Write-Host "  My Socials: "  -ForegroundColor White    -NoNewline
Write-Host "Discord  : "     -ForegroundColor Magenta  -NoNewline
Write-Host "хуй вам"        -ForegroundColor Magenta
Write-Host "  GitHub   : "     -ForegroundColor Gray -NoNewline
Write-Host "https://github.com/exortenne/" -ForegroundColor White
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "Analysis complete. Results displayed above." -ForegroundColor Green


# ============================================================
#  TRANSITION TO PART 3
# ============================================================
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "  Press any key to continue to the Command History Analyzer..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


# ============================================================
#  PART 3 - COMMAND HISTORY ANALYZER
# ============================================================

$Banner = @"
Checking command history since Minecraft launch...
"@

Write-Host $Banner -ForegroundColor Cyan
Write-Host ""
Write-Host "                hate bypass " -ForegroundColor Gray -NoNewline
Write-Host "<3 "           -ForegroundColor Magenta -NoNewline
Write-Host "by "           -ForegroundColor Gray -NoNewline
Write-Host "exortenne"  -ForegroundColor Magenta
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""

# -- Get Minecraft start time ----------------------------------
$mcProc = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $mcProc) { $mcProc = Get-Process java -ErrorAction SilentlyContinue }

if (-not $mcProc) {
    Write-Host "  Minecraft is not running - cannot analyze commands since launch" -ForegroundColor Yellow
    Write-Host "  Showing recent command history instead..." -ForegroundColor Gray
    $mcStartTime = (Get-Date).AddHours(-2)  # Fallback: show last 2 hours
} else {
    $mcStartTime = $mcProc.StartTime
    Write-Host ("  Minecraft started: {0}" -f $mcStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
    Write-Host "  Analyzing commands executed since this time..." -ForegroundColor Gray
    Write-Host ""
}

# -- Suspicious command patterns --------------------------------
$suspiciousCommands = @(
    # File/download operations
    "powershell -enc", "cmd /c", "certutil -decode", "certutil -urlcache",
    "bitsadmin /transfer", "Invoke-WebRequest", "curl -o", "wget -O",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    
    # Process/memory operations
    "taskkill /f", "taskkill /im", "Stop-Process -Force", "Get-Process",
    "Inject", "LoadLibrary", "VirtualAlloc", "WriteProcessMemory",
    
    # Network operations
    "netsh", "net use", "net user", "net localgroup", "net share",
    "Port forwarding", "proxy", "tunnel", "socks",
    
    # Registry operations
    "reg add", "reg delete", "reg query", "Set-ItemProperty",
    "Remove-ItemProperty", "New-ItemProperty",
    
    # System manipulation
    "bcdedit", "wmic", "wevtutil", "cipher", "sfc", "chkdsk",
    
    # Cheat-related commands
    "cheat", "hack", "inject", "bypass", "crack", "patch",
    "mod menu", "trainer", "esp", "aimbot", "wallhack",
    
    # File hiding/encryption
    "attrib +h", "attrib +s", "cipher /e", "cipher /d",
    "hidden", "invisible", "stealth",
    
    # Suspicious PowerShell patterns
    "IEX", "Invoke-Expression", "Start-BitsTransfer",
    "DownloadString", "DownloadFile", "FromBase64String"
)

# -- PowerShell History Analysis -------------------------------
Write-Host "POWERSHELL HISTORY ANALYSIS" -ForegroundColor Cyan
Write-Host ""

$psHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$psCommandsFound = 0
$suspiciousPsCommands = @()

if (Test-Path $psHistoryPath) {
    try {
        $psHistory = Get-Content $psHistoryPath -ErrorAction SilentlyContinue
        Write-Host "  PowerShell history file found: $psHistoryPath" -ForegroundColor White
        Write-Host ("  Total entries: {0}" -f $psHistory.Count) -ForegroundColor White
        Write-Host ""
        
        foreach ($line in $psHistory) {
            if ($line.Trim() -eq "") { continue }
            
            # Try to extract timestamp if available (PowerShell 7+ includes timestamps)
            $timestamp = $null
            $command = $line
            
            if ($line -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}') {
                $timestamp = [datetime]::Parse($line.Substring(0, 19))
                $command = $line.Substring(20).Trim()
            }
            
            # Check if command was executed after Minecraft started
            $commandTime = if ($timestamp) { $timestamp } else { $mcStartTime.AddMinutes(-1) }
            
            if ($commandTime -ge $mcStartTime) {
                $psCommandsFound++
                
                # Check for suspicious patterns
                $isSuspicious = $false
                $suspiciousPattern = $null
                
                foreach ($pattern in $suspiciousCommands) {
                    if ($command -like "*$pattern*" -or $command -match [regex]::Escape($pattern)) {
                        $isSuspicious = $true
                        $suspiciousPattern = $pattern
                        break
                    }
                }
                
                if ($isSuspicious) {
                    $suspiciousPsCommands += [PSCustomObject]@{
                        Time = $commandTime
                        Command = $command
                        Pattern = $suspiciousPattern
                    }
                }
            }
        }
        
        if ($psCommandsFound -eq 0) {
            Write-Host "  No PowerShell commands executed since Minecraft launch" -ForegroundColor Green
        } else {
            Write-Host ("  PowerShell commands executed since Minecraft launch: {0}" -f $psCommandsFound) -ForegroundColor Yellow
            
            if ($suspiciousPsCommands.Count -gt 0) {
                Write-Host ""
                Write-Host ("  SUSPICIOUS POWERSHELL COMMANDS DETECTED: {0}" -f $suspiciousPsCommands.Count) -ForegroundColor Red
                Write-Host ""
                foreach ($cmd in $suspiciousPsCommands) {
                    Write-Host "    ! " -NoNewline -ForegroundColor Red
                    Write-Host ("{0}" -f $cmd.Time.ToString("HH:mm:ss")) -NoNewline -ForegroundColor Yellow
                    Write-Host " | " -NoNewline -ForegroundColor Gray
                    Write-Host ("Pattern: {0}" -f $cmd.Pattern) -ForegroundColor Magenta
                    Write-Host "      {0}" -f $cmd.Command -ForegroundColor White
                    Write-Host ""
                }
                $verdictFlags.Add("Suspicious PowerShell commands executed since Minecraft launch ($($suspiciousPsCommands.Count))")
            } else {
                Write-Host "  No suspicious PowerShell commands detected" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Host "  Error reading PowerShell history: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  PowerShell history file not found" -ForegroundColor Yellow
    Write-Host "  This could mean:" -ForegroundColor Gray
    Write-Host "    - PowerShell history is disabled" -ForegroundColor Gray
    Write-Host "    - PowerShell has never been used" -ForegroundColor Gray
    Write-Host "    - History file was cleared" -ForegroundColor Gray
}

# -- CMD History Analysis --------------------------------------
Write-Host ""
Write-Host "CMD HISTORY ANALYSIS" -ForegroundColor Cyan
Write-Host ""

# CMD doesn't have a built-in history file, so we check other sources
$cmdCommandsFound = 0
$suspiciousCmdCommands = @()

# Check recent event logs for CMD execution
try {
    $cmdEvents = Get-WinEvent -LogName "Microsoft-Windows-ProcessCreation/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4688 }
    
    if ($cmdEvents) {
        Write-Host "  Analyzing recent process creation events..." -ForegroundColor White
        
        foreach ($event in $cmdEvents) {
            $eventTime = $event.TimeCreated
            
            if ($eventTime -ge $mcStartTime) {
                $processData = $event.Message
                $commandLine = ""
                
                # Extract command line from event data
                if ($processData -match "Command Line:\s*(.+?)\s*Process") {
                    $commandLine = $matches[1].Trim()
                } elseif ($processData -match "Command Line:\s*(.+)") {
                    $commandLine = $matches[1].Trim()
                }
                
                if ($commandLine -and ($commandLine -like "*cmd.exe*" -or $commandLine -like "*command.com*")) {
                    $cmdCommandsFound++
                    
                    # Check for suspicious patterns
                    $isSuspicious = $false
                    $suspiciousPattern = $null
                    
                    foreach ($pattern in $suspiciousCommands) {
                        if ($commandLine -like "*$pattern*" -or $commandLine -match [regex]::Escape($pattern)) {
                            $isSuspicious = $true
                            $suspiciousPattern = $pattern
                            break
                        }
                    }
                    
                    if ($isSuspicious) {
                        $suspiciousCmdCommands += [PSCustomObject]@{
                            Time = $eventTime
                            Command = $commandLine
                            Pattern = $suspiciousPattern
                        }
                    }
                }
            }
        }
        
        if ($cmdCommandsFound -eq 0) {
            Write-Host "  No CMD processes detected since Minecraft launch" -ForegroundColor Green
        } else {
            Write-Host ("  CMD processes executed since Minecraft launch: {0}" -f $cmdCommandsFound) -ForegroundColor Yellow
            
            if ($suspiciousCmdCommands.Count -gt 0) {
                Write-Host ""
                Write-Host ("  SUSPICIOUS CMD COMMANDS DETECTED: {0}" -f $suspiciousCmdCommands.Count) -ForegroundColor Red
                Write-Host ""
                foreach ($cmd in $suspiciousCmdCommands) {
                    Write-Host "    ! " -NoNewline -ForegroundColor Red
                    Write-Host ("{0}" -f $cmd.Time.ToString("HH:mm:ss")) -NoNewline -ForegroundColor Yellow
                    Write-Host " | " -NoNewline -ForegroundColor Gray
                    Write-Host ("Pattern: {0}" -f $cmd.Pattern) -ForegroundColor Magenta
                    Write-Host "      {0}" -f $cmd.Command -ForegroundColor White
                    Write-Host ""
                }
                $verdictFlags.Add("Suspicious CMD commands executed since Minecraft launch ($($suspiciousCmdCommands.Count))")
            } else {
                Write-Host "  No suspicious CMD commands detected" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "  Process creation events not available" -ForegroundColor Yellow
        Write-Host "  This requires audit policy to be enabled" -ForegroundColor Gray
    }
    
} catch {
    Write-Host "  Error analyzing process creation events: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Additional Analysis ----------------------------------------
Write-Host ""
Write-Host "ADDITIONAL ANALYSIS" -ForegroundColor Cyan
Write-Host ""

# Check for recent script executions
try {
    $scriptEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4103 -or $_.Id -eq 4104 }
    
    $scriptCount = 0
    $suspiciousScripts = @()
    
    if ($scriptEvents) {
        Write-Host "  Analyzing PowerShell script execution..." -ForegroundColor White
        
        foreach ($event in $scriptEvents) {
            if ($event.TimeCreated -ge $mcStartTime) {
                $scriptCount++
                
                $scriptContent = $event.Message
                if ($scriptContent.Length -gt 200) {
                    $scriptContent = $scriptContent.Substring(0, 200) + "..."
                }
                
                # Check for suspicious script content
                $isSuspicious = $false
                foreach ($pattern in $suspiciousCommands) {
                    if ($scriptContent -like "*$pattern*") {
                        $isSuspicious = $true
                        break
                    }
                }
                
                if ($isSuspicious) {
                    $suspiciousScripts += [PSCustomObject]@{
                        Time = $event.TimeCreated
                        Content = $scriptContent
                    }
                }
            }
        }
        
        Write-Host ("  PowerShell scripts executed since Minecraft launch: {0}" -f $scriptCount) -ForegroundColor Yellow
        
        if ($suspiciousScripts.Count -gt 0) {
            Write-Host ""
            Write-Host ("  SUSPICIOUS SCRIPT EXECUTIONS DETECTED: {0}" -f $suspiciousScripts.Count) -ForegroundColor Red
            Write-Host ""
            foreach ($script in $suspiciousScripts) {
                Write-Host "    ! " -NoNewline -ForegroundColor Red
                Write-Host ("{0}" -f $script.Time.ToString("HH:mm:ss")) -ForegroundColor Yellow
                Write-Host "      {0}" -f $script.Content -ForegroundColor White
                Write-Host ""
            }
            $verdictFlags.Add("Suspicious PowerShell scripts executed since Minecraft launch ($($suspiciousScripts.Count))")
        }
    }
    
} catch {
    Write-Host "  Error analyzing script execution: $($_.Exception.Message)" -ForegroundColor Red
}

# -- Summary --------------------------------------------------
Write-Host ""
Write-Host "COMMAND HISTORY SUMMARY" -ForegroundColor Magenta
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host "  Analysis period: " -ForegroundColor Gray -NoNewline
Write-Host ("{0} to {1}" -f $mcStartTime.ToString("yyyy-MM-dd HH:mm:ss"), (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
Write-Host "  PowerShell commands: " -ForegroundColor Gray -NoNewline
Write-Host $psCommandsFound -ForegroundColor White
Write-Host "  CMD processes: " -ForegroundColor Gray -NoNewline
Write-Host $cmdCommandsFound -ForegroundColor White
Write-Host "  Suspicious PowerShell: " -ForegroundColor Gray -NoNewline
if ($suspiciousPsCommands.Count -gt 0) {
    Write-Host $suspiciousPsCommands.Count -ForegroundColor Red
} else {
    Write-Host $suspiciousPsCommands.Count -ForegroundColor Green
}
Write-Host "  Suspicious CMD: " -ForegroundColor Gray -NoNewline
if ($suspiciousCmdCommands.Count -gt 0) {
    Write-Host $suspiciousCmdCommands.Count -ForegroundColor Red
} else {
    Write-Host $suspiciousCmdCommands.Count -ForegroundColor Green
}
Write-Host ""

# -- Final verdict update ---------------------------------------
if ($suspiciousPsCommands.Count -gt 0 -or $suspiciousCmdCommands.Count -gt 0) {
    $totalSuspicious = $suspiciousPsCommands.Count + $suspiciousCmdCommands.Count
    Write-Host "  COMMAND HISTORY ANALYSIS: " -ForegroundColor Gray -NoNewline
    Write-Host ("{0} suspicious commands detected" -f $totalSuspicious) -ForegroundColor Red
} else {
    Write-Host "  COMMAND HISTORY ANALYSIS: " -ForegroundColor Gray -NoNewline
    Write-Host "Clean" -ForegroundColor Green
}

Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "Command History Analysis complete!" -ForegroundColor Cyan
Write-Host ""

# -- FINAL VERDICT ---------------------------------------------
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host "  FINAL VERDICT" -ForegroundColor Cyan
Write-Host ("=" * 76) -ForegroundColor Gray

if ($verdictFlags.Count -gt 0) {
    Write-Host ""
    Write-Host "  * FLAGGED *" -ForegroundColor White -BackgroundColor DarkRed
    Write-Host ""
    Write-Host "  Hard flags:" -ForegroundColor Red
    foreach ($f in $verdictFlags) {
        Write-Host "    * $f" -ForegroundColor Red
    }
    if ($verdictWarnings.Count -gt 0) {
        Write-Host ""
        Write-Host "  Also worth reviewing:" -ForegroundColor Yellow
        foreach ($w in $verdictWarnings) {
            Write-Host "    * $w" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "  Note: Some flags can false flag legitimate software - manual verification recommended" -ForegroundColor Gray
    Write-Host "  for highly suspicious items before taking any action" -ForegroundColor Gray
} elseif ($verdictWarnings.Count -gt 0) {
    Write-Host ""
    Write-Host "  * REVIEW *" -ForegroundColor White -BackgroundColor DarkYellow
    Write-Host ""
    Write-Host "  Nothing confirmed but worth checking:" -ForegroundColor Yellow
    foreach ($w in $verdictWarnings) {
        Write-Host "    * $w" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "  * CLEAN *" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host ""
    Write-Host "  No flags or warnings raised across all tools" -ForegroundColor Green
}
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "  Complete analysis finished! " -ForegroundColor Magenta
Write-Host ""
Write-Host "  Created by: "  -ForegroundColor White    -NoNewline
Write-Host "exortenne"    -ForegroundColor Magenta
Write-Host "  My Socials: "  -ForegroundColor White    -NoNewline
Write-Host "Discord: "     -ForegroundColor Magenta  -NoNewline
Write-Host "хуй вам"        -ForegroundColor Magenta
Write-Host "  GitHub: "     -ForegroundColor Gray -NoNewline
Write-Host "https://github.com/exortenne" -ForegroundColor White
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "All analysis complete. Results displayed above." -ForegroundColor Green

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""
Write-Host "exortenne owns all cheaters, the undeniable daddy of every last one of them, standing above the rest as the king who dominates the entire scene, the god-tier presence that overshadows anyone trying to compete — every cheater falls under exortenne’s rule, outclassed, outplayed, and completely controlled, with no exceptions, no rivals, and no one even close to touching that level of supremacy."              -ForegroundColor Magenta


# ============================================================
#  TRANSITION TO PART 3
# ============================================================
Write-Host ""
Write-Host ("=" * 76) -ForegroundColor Gray
Write-Host ""
Write-Host "  Press any key to continue to the JVM Checker..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# ============================================================
#  PART 3 - JVM CHECKER
# ============================================================
Write-Host "`nJVM CHECKER" -ForegroundColor Cyan

Get-CimInstance Win32_Process | Where-Object { $_.Name -in @("javaw.exe", "java.exe") } | ForEach-Object {
    $cmd = $_.CommandLine

    if (-not $cmd) { return }

    $argList = $cmd -split ' (?=-)'

    $filteredArgs = $argList | Where-Object {
        $_ -like "-Xmx*" -or 
        $_ -like "-Xms*" -or 
        $_ -like "-javaagent*" -or 
        $_ -like "-Dfabric.addMods*" -or 
        $_ -like "-Dloader.addMods*"
    }

    if ($filteredArgs) {
        Write-Host "`n[Process ID: $($_.ProcessId)] --- Minecraft JVM / Mod Arguments ---" -ForegroundColor Cyan
        $filteredArgs | ForEach-Object { Write-Host $_.Trim() }
    } else {
        Write-Host "No specific JVM/Mod arguments found for process: $($_.ProcessId)" -ForegroundColor Yellow
    }
}
