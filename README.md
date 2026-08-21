<div align="center">
  <img src="readme-banner.svg" alt="Game Network Analyzer — PCAP, jitter, spikes and competitive network scoring" width="100%">
  <p><strong>Advanced PowerShell network-quality analysis for gaming sessions.</strong></p>
  <p>
    <a href="https://github.com/PrimeBuild-pc/GameNetAnalyzer/commits/main"><img alt="Last commit" src="https://img.shields.io/github/last-commit/PrimeBuild-pc/GameNetAnalyzer?style=plastic&amp;logo=git&amp;logoColor=white"></a>
    <a href="https://github.com/PrimeBuild-pc/GameNetAnalyzer/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/PrimeBuild-pc/GameNetAnalyzer?style=plastic&amp;logo=github"></a>
    <a href="https://github.com/PrimeBuild-pc/GameNetAnalyzer/issues"><img alt="Open issues" src="https://img.shields.io/github/issues/PrimeBuild-pc/GameNetAnalyzer?style=plastic&amp;logo=github"></a>
  </p>
  <p>
    <a href="https://github.com/PrimeBuild-pc/GameNetAnalyzer/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/PrimeBuild-pc/GameNetAnalyzer?include_prereleases&amp;style=plastic&amp;logo=github"></a>
    <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-2ea44f?style=plastic"></a>
    <a href="https://github.com/PowerShell/PowerShell"><img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE?style=plastic&amp;logo=powershell&amp;logoColor=white"></a>
    <img alt="Windows 10 and 11" src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=plastic&amp;logo=windows&amp;logoColor=white">
    <a href="https://www.wireshark.org/"><img alt="Wireshark 3 or newer" src="https://img.shields.io/badge/Wireshark-3.0%2B-1679A7?style=plastic&amp;logo=wireshark&amp;logoColor=white"></a>
  </p>
  <p><a href="#-features">Features</a> · <a href="#-installation--requirements">Installation</a> · <a href="#-usage">Usage</a> · <a href="#-wireshark-integration---advanced-workflow">Documentation</a> · <a href="#-contributing">Contributing</a></p>

</div>

---

## ⚡ Quick Start

**First time users**: The script automatically checks for prerequisites on first run.

```powershell
# Run without parameters for interactive menu
.\game_net_analyzer.ps1

# Or use CLI directly
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite"
```

If Wireshark/tshark is not installed, the tool will display installation instructions automatically.

## 📦 Installation & Requirements

### System Requirements

- **Operating System**: Windows 10/11 (x64)
- **PowerShell**: Version 5.1 or 7.x (included in Windows)
- **Wireshark/tshark**: Version 3.0 or higher
- **Administrator Rights**: Required for live network capture only

### Installing Wireshark

#### Option 1: Using winget (Recommended)

```powershell
# Install Wireshark via Windows Package Manager
winget install WiresharkFoundation.Wireshark
```

#### Option 2: Manual Download

1. Download from official website: https://www.wireshark.org/download.html
2. Run installer as Administrator
3. **IMPORTANT**: During installation, ensure "TShark" component is selected
4. Complete installation and restart if prompted

### Installing Npcap Drivers (If Missing)

Wireshark requires Npcap drivers for packet capture. If you encounter capture errors:

1. Download Npcap: https://npcap.com/dist/npcap-1.86.exe
2. Run installer as Administrator
3. Enable "Install Npcap in WinPcap API-compatible Mode" (recommended)
4. Restart your computer after installation

### Verifying Installation

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Verify tshark is installed and in PATH
tshark -v

# Manual path check
Test-Path "C:\Program Files\Wireshark\tshark.exe"

# Run prerequisite check
.\game_net_analyzer.ps1 -Verbose
```

### First Run Configuration

1. **Execution Policy**: If you see "script execution is disabled" error:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **Network Interface**: Identify your active interface:
   ```powershell
   Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed
   ```

3. **Test Run**: Launch interactive menu to verify setup:
   ```powershell
   .\game_net_analyzer.ps1
   ```

## ✨ Features

- 📊 **Detailed UDP/QUIC Flow Analysis**: Automatically identifies main game server
- 🎯 **Gaming-Oriented Metrics**: Jitter, Burst Ratio, Spike Ratio with S+/S/A/B/C scoring
- 🌍 **Region Recognition**: Automatically identifies AWS, Riot Games, and other regions
- 🎮 **Game Profiles**: Built-in support for Fortnite, Valorant, CS2, Warzone, League of Legends
- 📈 **Interactive HTML Reports**: Chart.js graphs with detailed timelines and intelligent interpretation
- 🔍 **Multi-Run Comparison**: Compare multiple sessions over time with trend graphs
- 🔧 **Network Diagnostics**: Integrated ping and traceroute (optional)
- 💻 **Cross-Compatible**: PowerShell 5.1 and 7.x on Windows
- 🚀 **Bufferbloat Testing**: Latency-under-load testing for network congestion detection



## 🚀 Usage

### Interactive Menu (Recommended for Beginners)

Run the script without parameters to launch the guided menu:

```powershell
.\game_net_analyzer.ps1
```

The interactive menu offers:
- **[1]** Analyze existing PCAP file
- **[2]** Live capture game traffic
- **[3]** Compare multiple sessions
- **[4]** Time-filtered analysis (Fight Segment)
- **[5]** PCAP analysis with network diagnostics
- **[6]** Bufferbloat test (latency under load)
- **[H]** Help and advanced commands

Each option guides you step-by-step with interactive input.

### Basic Usage - Command Line

#### 1️⃣ Analyze Existing PCAP File

```powershell
# Basic analysis
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\fortnite_match1.pcapng" -GameName "Fortnite"

# With network diagnostics (ping + traceroute)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -EnableDiagnostics

# With verbose logging
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Valorant" -Verbose
```

#### 2️⃣ Live Traffic Capture

```powershell
# Capture 30 seconds during a match
.\game_net_analyzer.ps1 -Mode live -Interface "Ethernet" -CaptureSeconds 30 -GameName "Warzone"

# List available interfaces
Get-NetAdapter | Select-Object Name, Status, LinkSpeed
```

#### 3️⃣ Compare Multiple Sessions

```powershell
# Compare all reports in folder
.\game_net_analyzer.ps1 -Mode compare -ComparePattern "netreport_*.json"

# Generate comparative HTML
.\game_net_analyzer.ps1 -Mode compare -ComparePattern "netreport_Fortnite_*.json" -CompareOutHtml "fortnite_trend.html"
```

## � Organizzazione Output

I report sono **automaticamente organizzati** nella cartella `game_net_reports/`:

```
game_net_reports/
├── pcap_analysis/          # Analisi PCAP suddivise per gioco
│   ├── Fortnite/
│   │   ├── netreport_Fortnite_20260108_203952.json
│   │   └── netreport_Fortnite_20260108_203952.html
│   ├── Valorant/
│   ├── CS2/
│   └── Other/              # Giochi non riconosciuti
├── live_captures/          # Catture live e relativi report
├── comparisons/            # Report comparativi multi-sessione
└── diagnostics/            # Diagnostica di rete (ping/traceroute)
```

**Vantaggi**:
- Facile navigazione: ogni gioco ha la sua cartella
- Backup semplice: copia l'intera cartella `game_net_reports`
- Confronti veloci: tutti i JSON di un gioco sono insieme
- Pulizia automatica: aggiungi `game_net_reports/` al .gitignore

**Nota**: Per backward compatibility, `-OutputDir` personalizzato è ancora supportato.

## �📊 Output Generati

### 1. JSON Report (machine-readable)

Contiene tutte le metriche dettagliate:
- Metadata: timestamp, versione tool, gioco
- Server info: IP, hostname, porta, regione
- Flow stats: packet count, duration, tick rate
- Metriche: jitter, burst, spike con tutti i valori
- Timeline: delta inter-arrival per ogni pacchetto
- Scores: valutazioni S+/S/A/B/C

Esempio: `netreport_Fortnite_20260108_203952.json`

### 2. HTML Report (human-readable)

Report interattivo con:
- **Tabelle metriche** organizzate in card
- **Grafico timeline** con Chart.js
  - Δt line (inter-arrival time)
  - Highlighted spikes
  - Target tick rate line
- **Performance Scores** with colored badges
- **Intelligent interpretation**
  - Personalized recommendations based on scores
  - Problem recognition (Wi-Fi, congestion, etc.)

Example: `netreport_Fortnite_20260108_203952.html`

### 3. Diagnostics JSON (optional)

With `-EnableDiagnostics`:
- Ping results: min/max/avg latency, packet loss
- Traceroute: hop by hop with latencies
- TCP connection test

Example: `diagnostics_18.157.42.2_20260108_204643.json`

### 4. Compare HTML (multi-run)

Comparative report with:
- Metric trend chart over time
- Comparative table of all sessions

Example: `compare_reports.html`

## 🎮 Supported Game Profiles

The tool automatically recognizes tick rate and optimal regions for:

| Game | Tick Rate | Target Regions |
|-------|-----------|----------------|
| **Fortnite** | 20ms (50Hz) | AWS FRA, AWS DUB |
| **Valorant** | 8ms (128Hz) | Riot EUW |
| **CS2** | 7.8ms (subtick) | EU Luxembourg |
| **Warzone** | 16.7ms (60Hz) | AMS, FRA |
| **League of Legends** | 33.3ms (30Hz) | EUW, EUNE |

For other games, the tool works the same but without expected tick rate comparison.

## 📖 Complete Parameters

### Mode: pcap
```powershell
-Mode pcap                    # PCAP file analysis
-PcapPath <path>              # Path to .pcap/.pcapng file (REQUIRED)
-GameName <name>              # Game name (default: "Auto")
-OutputDir <path>             # Output directory (default: ".")
-CustomFilter <tshark_filter> # Custom tshark filter (default: "ip && (udp || quic)")
-EnableDiagnostics            # Enable ping/traceroute
-AnalyzeQUIC                  # Separate QUIC traffic analysis (PHASE 6)
-FightStartSec <seconds>      # Analysis window start (PHASE 6)
-FightEndSec <seconds>        # Analysis window end (PHASE 6)
-TestBufferbloat              # Run bufferbloat test after analysis (PHASE 6)
-Verbose                      # Detailed logging
-WhatIf                       # Simulation (don't write files)
```

### Mode: live
```powershell
-Mode live                    # Live traffic capture
-Interface <name>             # Interface name (e.g. "Ethernet")
-CaptureSeconds <int>         # Capture duration in seconds (5-600, default: 30)
-GameName <name>              # Game name
-OutputDir <path>             # Output directory
-EnableDiagnostics            # Enable diagnostics after capture
-HudMode                      # Show real-time metrics during capture (PHASE 6)
```

### Mode: compare
```powershell
-Mode compare                 # Compare multiple reports
-ComparePattern <pattern>     # JSON file pattern (e.g. "*.json")
-CompareOutHtml <path>        # Comparative HTML output (optional)
```

### Mode: bufferbloat
```powershell
-Mode bufferbloat             # Bufferbloat test (latency under load)
-TestTarget <ip>              # Target IP for ping test (default: game server from last report)
```

## 🔍 Score Interpretation

### Average Jitter (AvgJitterMs)
- **S+**: ≤ 1ms - Perfect stability, ideal for competitive
- **S**: ≤ 2ms - Excellent, imperceptible
- **A**: ≤ 4ms - Very good, occasional micro-stuttering
- **B**: ≤ 8ms - Acceptable, visible stuttering
- **C**: > 8ms - Problematic, unstable gameplay

### Burst Ratio
Percentage of "compressed" packets (arrived too close together):
- **S+**: ≤ 1% - Optimal pacing
- **S**: ≤ 3% - Good
- **A**: ≤ 6% - Acceptable
- **B**: ≤ 10% - Some bursts
- **C**: > 10% - Too many bursts, possible congestion

### Spike Ratio
Percentage of sudden delays (>2.5x tick rate):
- **S+**: ≤ 0.5% - Very rare spikes
- **S**: ≤ 1% - Few spikes
- **A**: ≤ 3% - Some visible spikes
- **B**: ≤ 6% - Frequent spikes
- **C**: > 6% - Constant lag

### Overall Score
Weighted average of the three metrics:
- **S+/S**: Perfect for competitive gaming
- **A**: Good for casual/ranked gaming
- **B/C**: Requires optimization

## 🚀 Advanced Features (PHASE 6)

### Separate QUIC Analysis (`-AnalyzeQUIC`)

Some modern games use the QUIC protocol (e.g., some Google Stadia titles, cloud gaming). With this option, you activate parallel analysis of QUIC traffic:

```powershell
.\game_net_analyzer.ps1 -Mode pcap -PcapPath "match.pcapng" -AnalyzeQUIC
```

**Output**: In the JSON, you'll find a `QUICFlow` section with separate metrics (jitter, burst, spike) for QUIC traffic, useful for comparing UDP vs QUIC.

### Fight Segment Filter (`-FightStartSec`, `-FightEndSec`)

Analyze only a specific time window of the PCAP. Useful for:
- Excluding lobby/loading (first 30-60 seconds)
- Focusing on specific fights
- Comparing early-game vs end-game phase

```powershell
# Analyze only from second 60 to 180 (minutes 1-3)
.\game_net_analyzer.ps1 -Mode pcap -PcapPath "match.pcapng" -FightStartSec 60 -FightEndSec 180

# Analyze only after first 45 seconds
.\game_net_analyzer.ps1 -Mode pcap -PcapPath "match.pcapng" -FightStartSec 45
```

**Note**: The filter is applied before analysis, so metrics (jitter, spike) reflect only that window.

### HUD Mode (`-HudMode`)

During live capture, shows real-time metrics in the console:

```powershell
.\game_net_analyzer.ps1 -Mode live -Interface "Ethernet" -CaptureSeconds 120 -HudMode
```

**Real-time output**:
- Instantaneous jitter (last 5 seconds)
- Current burst/spike ratio
- Packet rate (pkt/s)
- Visual indicator (🟢 good / 🟡 warning / 🔴 bad)

**Practical use**: Keep the console on a second monitor while gaming to see immediately when the connection degrades.

## 💡 Recommended Workflow

### For Single Match Analysis

1. **Avvia Wireshark** prima di entrare in partita
   - Interfaccia: seleziona la tua scheda di rete
   - Filtro cattura: `udp or quic`
2. **Gioca una partita** (almeno 2-3 minuti)
3. **Ferma cattura** e salva come `.pcapng`
4. **Analizza** con lo script:
   ```powershell
   .\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -GameName "Fortnite" -EnableDiagnostics
   ```
5. **Apri HTML** nel browser per visualizzare i risultati

### For Trend Analysis (Multiple Matches)

1. Capture and analyze **3-5 matches** on different days/times
2. Use **compare mode** to see the trend:
   ```powershell
   .\game_net_analyzer.ps1 -Mode compare -ComparePattern "netreport_Fortnite_*.json" -CompareOutHtml "trend.html"
   ```
3. Identify **temporal patterns**: 
   - Worse network in the evening? (ISP congestion)
   - Weekend vs weekdays
   - Before vs after router/QoS change

### For Debugging Sudden Lag

If you notice lag only at certain times:
1. Capture a long session (10+ minutes)
2. Analyze the timeline chart in the HTML
3. Look for **spike clusters** in red in the chart
4. Compare with in-game timestamps of perceived lag
5. If spikes are **regular**: possible QoS/bufferbloat
6. If spikes are **random**: possible Wi-Fi interference

## 🐛 Troubleshooting

### "tshark.exe not found"
- Install Wireshark using winget: `winget install WiresharkFoundation.Wireshark`
- Or download manually: https://www.wireshark.org/download.html
- Or add to PATH: `$env:Path += ";C:\Program Files\Wireshark"`
- Or set in script: `$Global:TsharkPathOverride = "C:\...\tshark.exe"`
- **Missing npcap drivers**: Download from https://npcap.com/dist/npcap-1.86.exe

### "No UDP flows found"
- The PCAP may not contain game traffic
- Verify you captured **during** the match, not in menu
- Some games use TCP initially (lobby), UDP only in-game

### "Too few packets"
- The capture is too short (< 5 seconds)
- Increase `-CaptureSeconds` or capture manually longer
- Verify filtering only relevant traffic

### Live Capture Permissions
Capturing traffic requires **administrator permissions**:
```powershell
# Run PowerShell as administrator
Start-Process powershell -Verb RunAs
```

### HTML Chart Not Visible
- Requires **internet connection** (Chart.js loaded from CDN)
- Or download Chart.js locally and modify HTML

## 🔧 Advanced Customizations

### Add New Game Profile

Modify the `$Global:GameProfiles` section in the script:

```powershell
$Global:GameProfiles = @{
    "ApexLegends" = @{
        ExpectedTickMs = 50.0  # 20Hz server
        TargetRegions = @("AWS Frankfurt", "AWS London")
        Notes = "Battle Royale - 20Hz tickrate"
    }
    # ... other profiles
}
```

### Custom tshark Filter

To analyze only traffic to specific IP:

```powershell
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\match.pcapng" -CustomFilter "ip.dst == 18.157.42.2 && udp"
```

### Modify Scoring Thresholds

Cerca la funzione `Score-Metric` nello script e modifica i threshold:

```powershell
function Score-Metric {
    # ...
    "AvgJitterMs" {
        if ($Value -le 1.0) { return "S+" }  # <-- modify these values
        elseif ($Value -le 2.0) { return "S" }
        # ...
    }
}
```

## 📚 JSON Report Format

Complete JSON schema:

```jsonc
{
  "ToolVersion": "1.0.0",
  "Timestamp": "2026-01-08T20:43:32+01:00",
  "Game": "Fortnite",
  "GameProfile": {
    "ExpectedTickMs": 20.0,
    "TargetRegions": ["AWS FRA", "AWS DUB", "eu-central-1", "eu-west-1"],
    "Notes": "Performance mode, UDP/QUIC mix"
  },
  "PcapFile": "C:\\Users\\...\\fortnite_match1.pcapng",
  "LocalIP": "192.168.1.2",
  "RemoteIP": "18.157.42.2",
  "RemotePort": "9060",
  "RemoteHost": "ec2-18-157-42-2.eu-central-1.compute.amazonaws.com",
  "RegionHint": "AWS Frankfurt (eu-central-1)",
  "DiagnosticsFile": "C:\\...\\diagnostics_18.157.42.2_20260108_204643.json",
  "Flow": {
    "PacketCount": 36967,
    "DurationSec": 602.008,
    "PktPerSec": 61.4,
    "AvgDeltaMs": 16.285,
    "MinDeltaMs": 0.0,
    "MaxDeltaMs": 238.684,
    "AvgJitterMs": 1.74,
    "MaxJitterMs": 222.399,
    "BurstRatio": 0.029,
    "SpikeRatio": 0.001,
    "LenStats": {
      "min": 63.0,
      "max": 1004.0,
      "avg": 179.05
    },
    "Timeline": [
      {"t": 0.033, "d": 32.915},
      {"t": 0.068, "d": 34.957},
      // ... array completo di delta inter-arrival
    ]
  },
  "Scores": {
    "AvgJitter": "S",
    "Burst": "S",
    "Spike": "S+",
    "Overall": "S"
  }
}
```

## � Wireshark Integration - Advanced Workflow

### Capturing Traffic with Wireshark for Analysis

This tool works best with properly captured PCAP files. Here's how to use Wireshark for precise game traffic sniffing:

#### Step 1: Start Wireshark Capture

1. **Open Wireshark** as Administrator (required for packet capture)
2. **Select your network interface**:
   - Ethernet → Wired connection
   - Wi-Fi → Wireless connection
   - Use `ipconfig` to verify which interface has your active IP

3. **Apply capture filter** (optional but recommended):
   ```
   udp or quic
   ```
   This reduces file size by capturing only gaming protocols

#### Step 2: Play Your Game

- Start capture BEFORE entering the match
- Play for at least **2-3 minutes** of actual gameplay
- Avoid capturing lobby/menu time (or use Fight Segment filter later)

#### Step 3: Stop and Save

1. Stop capture (Red square button)
2. **Save As** → Choose `.pcapng` format
3. Name descriptively: `fortnite_ranked_evening.pcapng`

#### Step 4: Analyze with This Tool

```powershell
.\game_net_analyzer.ps1 -Mode pcap -PcapPath ".\fortnite_ranked_evening.pcapng" -GameName "Fortnite"
```

### Advanced Wireshark Techniques

#### Display Filters for Game Server Identification

After capture, use Wireshark display filters to identify game servers:

```
# Show only UDP traffic to/from specific port
udp.port == 9060

# Show traffic to specific IP (if you know game server)
ip.addr == 18.157.42.2

# Show only large packets (likely game state updates)
frame.len > 500 && udp

# Time-based filtering (after 60 seconds)
frame.time_relative > 60
```

#### Extract Specific Time Windows

If you want to analyze only a specific match segment:

1. **Right-click on packet** → Copy → "Time" → Note timestamp
2. Use **Fight Segment** feature in this tool:
   ```powershell
   .\game_net_analyzer.ps1 -Mode pcap -PcapPath "match.pcapng" -FightStartSec 120 -FightEndSec 300
   ```

#### Export Filtered Traffic

To reduce file size before analysis:

1. Apply display filter in Wireshark
2. **File → Export Specified Packets**
3. Select "Displayed" packets only
4. Save as new `.pcapng`

### Troubleshooting Common Issues

#### "No UDP flows found"
- **Cause**: Capture started after game traffic began
- **Solution**: Start Wireshark BEFORE launching game, or use longer capture

#### "Too few packets"
- **Cause**: Capture duration too short
- **Solution**: Capture for at least 2-3 minutes of active gameplay

#### "Permission denied" during live capture
- **Cause**: Wireshark/PowerShell not run as Administrator
- **Solution**: Right-click → "Run as Administrator"

#### Encrypted Traffic (HTTPS/TLS)
- **Note**: This tool analyzes UDP game traffic, not encrypted HTTPS
- Game servers use UDP for real-time data (position, actions)
- Login/authentication uses HTTPS (cannot be analyzed)

### Integration with CI/CD

For automated network monitoring:

```powershell
# Scheduled task: nightly game session analysis
$pcaps = Get-ChildItem "C:\GameCaptures\*.pcapng"
foreach ($pcap in $pcaps) {
    .\game_net_analyzer.ps1 -Mode pcap -PcapPath $pcap.FullName -GameName "Auto"
}

# Compare all captures
.\game_net_analyzer.ps1 -Mode compare -ComparePattern "*.json"
```

## 🗺️ Implemented Roadmap

- ✅ **PHASE 0**: Script stabilization (validation, error handling, automatic tshark detection)
- ✅ **PHASE 1**: Analyzer core v1 (UDP flow analysis, jitter/burst/spike metrics)
- ✅ **PHASE 2**: Improved HTML + JSON reports (interactive charts, interpretation)
- ✅ **PHASE 3**: Multi-run and comparison (compare mode with trend charts)
- ✅ **PHASE 4**: Game profiles & region (automatic AWS/Riot region recognition)
- ✅ **PHASE 5**: Diagnostics integration (optional ping/traceroute)
- ✅ **PHASE 6**: Extra PRO features (QUIC analysis, Fight Segments, Bufferbloat test)

## 🤝 Contributing

Contributions welcome! To improve the tool:
1. Fork the repository
2. Create a branch for your feature
3. Test changes locally
4. Submit a Pull Request with detailed description

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

**Dependencies**:
- **Wireshark/tshark**: GPL-2.0 License
- **Chart.js**: MIT License (embedded in HTML reports)

## 🎯 Credits & Distribution

**Author**: Developed for in-depth gaming network quality analysis  
**Platform**: Windows 10/11 + PowerShell 5.1/7.x  
**Distribution**: Open-source tool, free for personal and commercial use  

### System Requirements
- ✅ Windows 10/11 (x64)
- ✅ PowerShell 5.1+ or PowerShell 7.x
- ✅ Wireshark/tshark 3.0+
- ✅ Administrator permissions (only for live capture)

---

**Version**: 1.0.0  
**Last Updated**: January 2026  
**Repository**: GitHub (coming soon)
