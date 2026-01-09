# Game Network Analyzer - Quick Start Guide
# ============================================

# 0. INTERACTIVE MENU (RECOMMENDED FOR BEGINNERS)
# ------------------------------------------------
# Run the script without parameters to launch the guided menu
.\game_net_analyzer.ps1

# The menu offers:
#  [1] Analyze existing PCAP file
#  [2] Live capture game traffic
#  [3] Compare multiple sessions
#  [4] Analyze PCAP with time filter (Fight Segment)
#  [5] Analyze PCAP with network diagnostics
#  [6] Bufferbloat test (latency under load)
#  [H] Help - Show advanced command examples
#  [Q] Exit


# 1. BASIC PCAP ANALYSIS (COMMAND LINE)
# --------------------------------------
# Analyze an existing PCAP file
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\fortnite_match1.pcapng" -GameName "Fortnite"

# With detailed logging
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -Verbose

# With network diagnostics (ping + traceroute)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -EnableDiagnostics


# 2. LIVE CAPTURE
# ---------------
# List available network interfaces
Get-NetAdapter | Where-Object Status -eq 'Up' | Format-Table Name, InterfaceDescription, LinkSpeed

# Capture 30 seconds of traffic during a match
.\game_net_analyzer.ps1 -Mode live -Interface "Ethernet" -CaptureSeconds 30 -GameName "Fortnite"

# Longer capture (5 minutes) with diagnostics
.\game_net_analyzer.ps1 -Mode live -Interface "Wi-Fi" -CaptureSeconds 300 -GameName "Valorant" -EnableDiagnostics


# 3. COMPARE MULTIPLE SESSIONS
# ----------------------------
# Compare all Fortnite reports
.\game_net_analyzer.ps1 -Mode compare -ComparePattern "netreport_Fortnite_*.json"

# Generate comparative HTML
.\game_net_analyzer.ps1 -Mode compare -ComparePattern "netreport_*.json" -CompareOutHtml "all_games_compare.html"

# Compare only today's reports
$today = Get-Date -Format "yyyyMMdd"
.\game_net_analyzer.ps1 -Mode compare -ComparePattern "netreport_*_${today}_*.json" -CompareOutHtml "today_compare.html"


# 4. COMPLETE WORKFLOW FOR SINGLE ANALYSIS
# -----------------------------------------
# Step 1: Open Wireshark and start capture on correct interface with filter "udp or quic"
# Step 2: Play a match (at least 2-3 minutes)
# Step 3: Stop capture and save as "match.pcapng"
# Step 4: Analyze
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -EnableDiagnostics

# Step 5: Open HTML in browser
Start-Process "netreport_Fortnite_$(Get-Date -Format 'yyyyMMdd')*.html"


# 5. OTHER SUPPORTED GAMES
# -------------------------
# Valorant
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\valorant.pcapng" -GameName "Valorant"

# Counter-Strike 2
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\cs2.pcapng" -GameName "CS2"

# Call of Duty Warzone
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\warzone.pcapng" -GameName "Warzone"

# League of Legends
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\lol.pcapng" -GameName "LeagueOfLegends"

# Generic game (still works, but without specific profile)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\game.pcapng" -GameName "ApexLegends"


# 6. CUSTOM TSHARK FILTERS
# -------------------------
# Analyze only traffic to specific IP
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -CustomFilter "ip.dst == 18.157.42.2 && udp"

# QUIC traffic only
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -CustomFilter "quic"

# UDP on specific ports
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -CustomFilter "udp && (udp.port == 9000 || udp.port == 9060)"


# 7. TROUBLESHOOTING
# ------------------
# Verify tshark installation
& "C:\Program Files\Wireshark\tshark.exe" -v

# Verify available interfaces for live capture
& "C:\Program Files\Wireshark\tshark.exe" -D

# Test simulation (WhatIf - doesn't write anything)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Test" -WhatIf

# Check script errors
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Test" -Verbose -ErrorAction Stop


# 8. UTILITY COMMANDS
# -------------------
# Open all HTML reports generated today
$today = Get-Date -Format "yyyyMMdd"
Get-ChildItem "netreport_*_${today}_*.html" | ForEach-Object { Start-Process $_.FullName }

# Clean old reports (older than 7 days)
$oldDate = (Get-Date).AddDays(-7)
Get-ChildItem "netreport_*.json","netreport_*.html" | Where-Object LastWriteTime -lt $oldDate | Remove-Item -WhatIf

# Export statistics of all reports to CSV
Get-ChildItem "netreport_*.json" | ForEach-Object {
    $json = Get-Content $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{
        File = $_.Name
        Date = $json.Timestamp
        Game = $json.Game
        Server = $json.RemoteIP
        Region = $json.RegionHint
        JitterMs = $json.Flow.AvgJitterMs
        BurstRatio = $json.Flow.BurstRatio
        SpikeRatio = $json.Flow.SpikeRatio
        OverallScore = $json.Scores.Overall
    }
} | Export-Csv -Path "reports_summary.csv" -NoTypeInformation

# Find report with worst jitter
Get-ChildItem "netreport_*.json" | ForEach-Object {
    $json = Get-Content $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{
        File = $_.Name
        JitterMs = $json.Flow.AvgJitterMs
        Score = $json.Scores.Overall
    }
} | Sort-Object JitterMs -Descending | Select-Object -First 5 | Format-Table

# Find report with best score
Get-ChildItem "netreport_*.json" | ForEach-Object {
    $json = Get-Content $_.FullName | ConvertFrom-Json
    [PSCustomObject]@{
        File = $_.Name
        DateTime = [datetime]$json.Timestamp
        Score = $json.Scores.Overall
        JitterMs = $json.Flow.AvgJitterMs
    }
} | Where-Object Score -match "S" | Sort-Object DateTime -Descending | Format-Table


# 9. ADVANCED FEATURES (PHASE 6)
# -------------------------------
# Separate QUIC analysis (for games with QUIC traffic)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Stadia" -AnalyzeQUIC

# Fight Segment: analyze only 60-180 second window (minutes 1-3)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -FightStartSec 60 -FightEndSec 180

# Fight Segment: skip first 45 seconds (lobby/loading)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -FightStartSec 45

# HUD Mode: show real-time metrics during live capture
.\game_net_analyzer.ps1 -Mode live -Interface "Ethernet" -CaptureSeconds 120 -GameName "Valorant" -HudMode

# Combine QUIC + Fight Segment
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -AnalyzeQUIC -FightStartSec 30 -FightEndSec 150

# Advanced workflow: compare early-game vs end-game
# Capture complete match, then analyze 2 separate windows
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\full_match.pcapng" -GameName "Fortnite" -FightStartSec 30 -FightEndSec 120 -OutputDir ".\analysis_early"
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\full_match.pcapng" -GameName "Fortnite" -FightStartSec 300 -FightEndSec 480 -OutputDir ".\analysis_endgame"
# Compare resulting JSONs to see early vs late game differences


# 10. AUTOMATION
# --------------
# Automatically analyze all PCAPs in a folder
Get-ChildItem -Filter "*.pcapng" | ForEach-Object {
    Write-Host "Analyzing: $($_.Name)" -ForegroundColor Cyan
    .\game_net_analyzer.ps1 -Mode pcap -PcapPath $_.FullName -GameName "Auto"
}

# Scheduled task: capture every evening at 9:00 PM
# (run as administrator once)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"C:\path\to\game_net_analyzer.ps1`" -Mode live -Interface Ethernet -CaptureSeconds 60 -GameName Fortnite"
$trigger = New-ScheduledTaskTrigger -Daily -At 21:00
Register-ScheduledTask -TaskName "GameNetMonitor" -Action $action -Trigger $trigger -Description "Daily gaming network quality capture"


# 11. TIPS & TRICKS
# -----------------
# Copy script and PCAP to Desktop for quick access
# Create alias for frequent command
Set-Alias -Name gna -Value "C:\Users\Lorenzo\Desktop\New folder\game_net_analyzer.ps1"

# Use with alias
gna -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite"

# Save alias permanently (add to PowerShell profile)
# Edit: notepad $PROFILE
# Add: Set-Alias -Name gna -Value "C:\path\to\game_net_analyzer.ps1"
