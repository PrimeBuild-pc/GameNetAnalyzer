# Installation Guide - Game Network Analyzer

## System Requirements

- **Operating System**: Windows 10 or Windows 11 (64-bit)
- **PowerShell**: Version 5.1 or higher (included in Windows) or PowerShell 7.x
- **Wireshark**: Version 3.0 or higher (with tshark component)
- **Administrator Rights**: Required for live packet capture only

## Step-by-Step Installation

### 1. Install Wireshark

1. Download Wireshark from official website:
   - https://www.wireshark.org/download.html
   - Select the **Windows x64 Installer**

2. During installation:
   - ✅ **IMPORTANT**: Check "TShark" component
   - ✅ Install Npcap when prompted (required for packet capture)
   - Default installation path: `C:\Program Files\Wireshark`

3. Verify installation:
   ```powershell
   # Open PowerShell and run:
   tshark -v
   
   # Should display: TShark (Wireshark) 4.x.x
   ```

### 2. Download Game Network Analyzer

**Option A: Download from GitHub**
```powershell
# Clone repository (if using Git)
git clone https://github.com/yourusername/game-network-analyzer.git
cd game-network-analyzer

# Or download ZIP and extract
```

**Option B: Direct Download**
1. Download the ZIP file from GitHub releases
2. Extract to a folder (e.g., `C:\Tools\GameNetAnalyzer`)
3. Unblock files if needed:
   ```powershell
   Get-ChildItem -Recurse | Unblock-File
   ```

### 3. First Run

```powershell
# Navigate to script directory
cd "C:\Tools\GameNetAnalyzer"

# Run script (will check prerequisites automatically)
.\game_net_analyzer.ps1
```

**If prerequisites check fails**, you'll see clear instructions on what's missing.

## Execution Policy (First-Time Setup)

If you get an "execution policy" error:

```powershell
# Check current policy
Get-ExecutionPolicy

# If it says "Restricted", run as Administrator:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for this session only:
powershell -ExecutionPolicy Bypass -File .\game_net_analyzer.ps1
```

## Troubleshooting

### "tshark not found"

**Solution 1**: Add Wireshark to PATH
```powershell
$env:Path += ";C:\Program Files\Wireshark"
```

**Solution 2**: The script auto-detects common Wireshark locations:
- `C:\Program Files\Wireshark\tshark.exe`
- `C:\Program Files (x86)\Wireshark\tshark.exe`

**Solution 3**: Set custom path in script (line 67):
```powershell
$Global:TsharkPathOverride = "C:\Your\Custom\Path\tshark.exe"
```

### "Administrator rights required" (Live Capture Only)

For `-Mode live` captures:
1. Right-click PowerShell icon
2. Select "Run as Administrator"
3. Navigate to script directory
4. Run the command

**Note**: PCAP file analysis does NOT require admin rights.

### Slow Performance

If analysis is slow on large PCAP files:
1. Use Fight Segment filter to analyze specific time windows
2. Pre-filter PCAP in Wireshark (export only game traffic)
3. Ensure SSD storage for better I/O performance

## Uninstallation

To remove the tool:
1. Delete the script folder
2. (Optional) Uninstall Wireshark if not needed:
   - Control Panel → Programs → Uninstall Wireshark

## Updates

To update to the latest version:

```powershell
# If using Git
cd game-network-analyzer
git pull origin main

# If manual download
# Download new version and replace old files
# Your reports in game_net_reports/ folder will be preserved
```

## Network Security Note

This tool:
- ✅ Analyzes local PCAP files and network traffic
- ✅ Does NOT send data to external servers
- ✅ All reports are stored locally in `game_net_reports/` folder
- ✅ Optional diagnostics (ping/traceroute) use standard Windows tools

For privacy: Add `game_net_reports/` to `.gitignore` if sharing the folder.

## Getting Help

- 📖 Read the [README.md](README.md) for usage examples
- 💡 Check [EXAMPLES.ps1](EXAMPLES.ps1) for 50+ command examples
- 🐛 Report issues on GitHub Issues page
- 📝 See inline help: `Get-Help .\game_net_analyzer.ps1 -Full`

---

**Installation complete!** Run `.\game_net_analyzer.ps1` to start analyzing your gaming network quality.
