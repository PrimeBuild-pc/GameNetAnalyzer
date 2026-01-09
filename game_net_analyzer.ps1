[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("pcap","live","compare","menu")]
    [string]$Mode = "menu",

    # Per Mode=pcap -> file da analizzare
    [Parameter(Mandatory=$false)]
    [string]$PcapPath,

    # Per Mode=live -> interfaccia e durata
    [Parameter(Mandatory=$false)]
    [string]$Interface = "Ethernet",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(5,600)]
    [int]$CaptureSeconds = 30,

    # Nome gioco (serve solo per etichetta, detection è auto)
    [Parameter(Mandatory=$false)]
    [string]$GameName = "Auto",

    # Cartella output report (ora relativa a game_net_reports)
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "",

    # Filtro tshark personalizzato
    [Parameter(Mandatory=$false)]
    [string]$CustomFilter = "ip && (udp || quic)",
    
    # Per Mode=compare -> pattern files JSON
    [Parameter(Mandatory=$false)]
    [string]$ComparePattern = "*.json",
    
    # Per Mode=compare -> output HTML compare
    [Parameter(Mandatory=$false)]
    [string]$CompareOutHtml,
    
    # Abilita diagnostica rete (ping/traceroute)
    [Parameter(Mandatory=$false)]
    [switch]$EnableDiagnostics,
    
    # Analisi separata traffico QUIC
    [Parameter(Mandatory=$false)]
    [switch]$AnalyzeQUIC,
    
    # Fight segment: tempo inizio (secondi dall'inizio capture)
    [Parameter(Mandatory=$false)]
    [double]$FightStartSec = 0,
    
    # Fight segment: tempo fine (secondi dall'inizio capture, 0 = fino alla fine)
    [Parameter(Mandatory=$false)]
    [double]$FightEndSec = 0,
    
    # HUD mode: mostra metriche real-time durante capture live
    [Parameter(Mandatory=$false)]
    [switch]$HudMode,
    
    # Test bufferbloat: misura latenza sotto carico
    [Parameter(Mandatory=$false)]
    [switch]$TestBufferbloat
)

# ================== CONFIG ==================
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Path a tshark se non è nel PATH (altrimenti lascia $null)
$Global:TsharkPathOverride = $null  # es. "C:\Program Files\Wireshark\tshark.exe"

$Global:ScriptVersion = "1.0.0"

# Profili gioco con tick rates e regioni target
$Global:GameProfiles = @{
    "Fortnite" = @{
        ExpectedTickMs = 20.0
        TargetRegions = @("AWS FRA", "AWS DUB", "eu-central-1", "eu-west-1")
        Notes = "Performance mode, UDP/QUIC mix"
    }
    "Warzone" = @{
        ExpectedTickMs = 16.7
        TargetRegions = @("AMS", "FRA")
        Notes = "Call of Duty: Warzone"
    }
    "Valorant" = @{
        ExpectedTickMs = 8.0
        TargetRegions = @("EU West", "euw1")
        Notes = "Riot Games - 128-tick servers"
    }
    "CS2" = @{
        ExpectedTickMs = 7.8
        TargetRegions = @("EU", "Luxembourg")
        Notes = "Counter-Strike 2 - 128-tick subtick"
    }
    "LeagueOfLegends" = @{
        ExpectedTickMs = 33.3
        TargetRegions = @("EUW", "EUNE")
        Notes = "30Hz tick rate"
    }
}
# ============================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
    Checks system requirements and dependencies
    #>
    [CmdletBinding()]
    param()
    
    $issues = @()
    
    # Check OS
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        $issues += "This tool requires Windows (detected: $($PSVersionTable.OS))"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell 5.1 or higher required (current: $($PSVersionTable.PSVersion))"
    }
    
    # Check tshark
    try {
        $tshark = Get-TsharkPath -ErrorAction Stop
        Write-Verbose "tshark found at: $tshark"
    }
    catch {
        $issues += "Wireshark/tshark not found. Please install from: https://www.wireshark.org/download.html"
    }
    
    if ($issues.Count -gt 0) {
        Write-Host "`n❌ PREREQUISITES CHECK FAILED" -ForegroundColor Red
        Write-Host "The following issues were detected:`n" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "  • $issue" -ForegroundColor Yellow
        }
        Write-Host "`n📋 Installation Guide:" -ForegroundColor Cyan
        Write-Host "  1. Install Wireshark: https://www.wireshark.org/download.html" -ForegroundColor White
        Write-Host "     - During installation, ensure 'TShark' component is selected" -ForegroundColor Gray
        Write-Host "  2. Add Wireshark to PATH, or the tool will auto-detect common locations" -ForegroundColor White
        Write-Host "  3. For live captures, run PowerShell as Administrator`n" -ForegroundColor White
        
        return $false
    }
    
    Write-Verbose "All prerequisites met"
    return $true
}

function Initialize-OutputStructure {
    <#
    .SYNOPSIS
    Crea la struttura di cartelle organizzata per i report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$BaseDir = "."
    )
    
    $baseReportDir = Join-Path $BaseDir "game_net_reports"
    
    # Crea cartella principale se non esiste
    if (-not (Test-Path $baseReportDir)) {
        New-Item -ItemType Directory -Path $baseReportDir -Force | Out-Null
        Write-Verbose "Creata cartella principale: $baseReportDir"
    }
    
    # Crea sottocartelle
    $subDirs = @(
        "pcap_analysis",
        "live_captures",
        "comparisons",
        "diagnostics"
    )
    
    foreach ($dir in $subDirs) {
        $path = Join-Path $baseReportDir $dir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-Verbose "Creata sottocartella: $path"
        }
    }
    
    return $baseReportDir
}

function Get-OutputDirectory {
    <#
    .SYNOPSIS
    Determina la directory di output in base al tipo di analisi
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("pcap","live","compare","diagnostics")]
        [string]$AnalysisType,
        
        [Parameter(Mandatory=$false)]
        [string]$GameName = "Other",
        
        [Parameter(Mandatory=$false)]
        [string]$CustomOutputDir = ""
    )
    
    # Se specificata custom dir, usala (per backward compatibility CLI)
    if ($CustomOutputDir -and $CustomOutputDir -ne "") {
        return $CustomOutputDir
    }
    
    # Altrimenti usa struttura organizzata
    $scriptDir = Split-Path -Parent $PSCommandPath
    $baseReportDir = Initialize-OutputStructure -BaseDir $scriptDir
    
    switch ($AnalysisType) {
        "pcap" {
            $subDir = Join-Path (Join-Path $baseReportDir "pcap_analysis") $GameName
            if (-not (Test-Path $subDir)) {
                New-Item -ItemType Directory -Path $subDir -Force | Out-Null
            }
            return $subDir
        }
        "live" {
            return Join-Path $baseReportDir "live_captures"
        }
        "compare" {
            return Join-Path $baseReportDir "comparisons"
        }
        "diagnostics" {
            return Join-Path $baseReportDir "diagnostics"
        }
    }
}

function Get-TsharkPath {
    <#
    .SYNOPSIS
    Trova il percorso di tshark.exe
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Searching for tshark.exe..."
    
    if ($Global:TsharkPathOverride -and (Test-Path $Global:TsharkPathOverride)) {
        Write-Verbose "Uso TsharkPathOverride: $Global:TsharkPathOverride"
        return $Global:TsharkPathOverride
    }
    
    # Prova Get-Command prima
    $cmd = Get-Command tshark -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Verbose "tshark found in PATH: $($cmd.Source)"
        return $cmd.Source
    }
    
    # Cerca in percorsi comuni su Windows
    $commonPaths = @(
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe",
        "$env:ProgramFiles\Wireshark\tshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-Verbose "tshark found at: $path"
            return $path
        }
    }
    
    # Non trovato
    $errMsg = @"
tshark.exe non trovato nel PATH o nelle directory comuni.

Soluzioni:
1. Installa Wireshark da https://www.wireshark.org/download.html
2. Aggiungi 'C:\Program Files\Wireshark' al PATH di sistema
3. Oppure imposta `$Global:TsharkPathOverride nello script

PATH attuale: $env:PATH
"@
    throw $errMsg
}

function Get-LocalIPv4 {
    <#
    .SYNOPSIS
    Ottiene tutti gli IP locali IPv4 (escluso loopback)
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Collecting local IP addresses..."
    
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp,Manual -ErrorAction Stop `
            | Where-Object { $_.IPAddress -ne "127.0.0.1" } `
            | Select-Object -ExpandProperty IPAddress
        
        if (-not $ips) {
            throw "Nessun indirizzo IPv4 valido trovato (escluso loopback)"
        }
        
        Write-Verbose "Local IPs found: $($ips -join ', ')"
        return $ips
    }
    catch {
        throw "Errore nel recupero degli indirizzi locali: $_"
    }
}

function Invoke-TsharkCsv {
    <#
    .SYNOPSIS
    Esegue tshark e restituisce CSV parsato
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Pcap,
        
        [Parameter(Mandatory=$false)]
        [string]$Filter = "ip && (udp || quic)"
    )
    
    if (-not (Test-Path $Pcap)) {
        throw "File PCAP non trovato: $Pcap"
    }
    
    $pcapResolved = Resolve-Path $Pcap -ErrorAction Stop
    Write-Verbose "PCAP analysis: $pcapResolved"
    Write-Verbose "Filtro: $Filter"
    
    $tshark = Get-TsharkPath
    $tsharkArgs = @(
        "-r", $pcapResolved.Path,
        "-Y", $Filter,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "frame.len"
    )

    Write-Verbose "Esecuzione: $tshark $($tsharkArgs -join ' ')"
    
    try {
        $csvText = & $tshark @tsharkArgs 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "tshark exit code: $LASTEXITCODE. Output: $csvText"
        }
        
        if (-not $csvText) {
            throw "tshark non ha prodotto output. Il file potrebbe essere vuoto o il filtro troppo restrittivo."
        }
        
        $csv = $csvText | ConvertFrom-Csv
        Write-Verbose "Packets read: $($csv.Count)"
        
        return $csv
    }
    catch {
        throw "Errore esecuzione tshark: $_"
    }
}

function Analyze-Flow {
    <#
    .SYNOPSIS
    Analizza un singolo flusso UDP server->client
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Packets,
        
        [Parameter(Mandatory=$true)]
        [string]$LocalIP,
        
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        
        [Parameter(Mandatory=$true)]
        [string]$RemotePort
    )

    Write-Verbose "Flow analysis: ${RemoteIP}:${RemotePort} -> $LocalIP"

    # Filtra solo traffico Server -> Client
    $svrPkts = $Packets | Where-Object {
        $_."ip.src" -eq $RemoteIP -and 
        $_."ip.dst" -eq $LocalIP -and 
        $_."udp.srcport" -eq $RemotePort
    } | Sort-Object {[double]$_."frame.time_epoch"}

    if ($svrPkts.Count -lt 5) {
        Write-Warning "Troppi pochi pacchetti server->client ($($svrPkts.Count)). Serve almeno 5 pacchetti."
        return $null
    }

    Write-Verbose "Pacchetti server->client: $($svrPkts.Count)"

    $times = @()
    $lens  = @()
    foreach ($p in $svrPkts) {
        $times += [double]$p."frame.time_epoch"
        $lens  += [int]$p."frame.len"
    }

    $first = $times[0]
    $last  = $times[-1]
    $duration = $last - $first

    # inter-arrival
    $deltas = @()
    for ($i=1; $i -lt $times.Count; $i++) {
        $d = ($times[$i] - $times[$i-1]) * 1000.0  # ms
        $deltas += $d
    }

    $avgDelta = ($deltas | Measure-Object -Average).Average
    $minDelta = ($deltas | Measure-Object -Minimum).Minimum
    $maxDelta = ($deltas | Measure-Object -Maximum).Maximum

    # jitter = deviazione assoluta media
    $jitterAbs = @()
    foreach ($d in $deltas) {
        $jitterAbs += [math]::Abs($d - $avgDelta)
    }
    $avgJitter = ($jitterAbs | Measure-Object -Average).Average
    $maxJitter = ($jitterAbs | Measure-Object -Maximum).Maximum

    # burst detection: delta < avgDelta/3
    $burstThreshold = $avgDelta / 3.0
    $burstCount = @($deltas | Where-Object { $_ -lt $burstThreshold }).Count
    $burstRatio = if ($deltas.Count -gt 0) { $burstCount / $deltas.Count } else { 0 }

    # spike detection: delta > avgDelta * 2.5
    $spikeThreshold = $avgDelta * 2.5
    $spikeCount = @($deltas | Where-Object { $_ -gt $spikeThreshold }).Count
    $spikeRatio = if ($deltas.Count -gt 0) { $spikeCount / $deltas.Count } else { 0 }

    Write-Verbose "Metriche: AvgDelta=$([math]::Round($avgDelta,2))ms, AvgJitter=$([math]::Round($avgJitter,2))ms, Burst=$([math]::Round($burstRatio,3)), Spike=$([math]::Round($spikeRatio,3))"

    # jitter timeline per grafico
    $timeline = @()
    for ($i=0; $i -lt $deltas.Count; $i++) {
        $timeline += [pscustomobject]@{
            t = [math]::Round(($times[$i+1] - $first),3)  # secondi dall'inizio
            d = [math]::Round($deltas[$i],3)             # delta ms
        }
    }

    # lunghezze pacchetti (packet size distribuzione)
    $lenStats = @{
        min = ($lens | Measure-Object -Minimum).Minimum
        max = ($lens | Measure-Object -Maximum).Maximum
        avg = ($lens | Measure-Object -Average).Average
    }

    return [pscustomobject]@{
        LocalIP      = $LocalIP
        RemoteIP     = $RemoteIP
        RemotePort   = $RemotePort
        PacketCount  = $svrPkts.Count
        DurationSec  = [math]::Round($duration,3)
        PktPerSec    = if ($duration -gt 0) { [math]::Round($svrPkts.Count / $duration,1) } else { 0 }
        AvgDeltaMs   = [math]::Round($avgDelta,3)
        MinDeltaMs   = [math]::Round($minDelta,3)
        MaxDeltaMs   = [math]::Round($maxDelta,3)
        AvgJitterMs  = [math]::Round($avgJitter,3)
        MaxJitterMs  = [math]::Round($maxJitter,3)
        BurstRatio   = [math]::Round($burstRatio,3)
        SpikeRatio   = [math]::Round($spikeRatio,3)
        LenStats     = $lenStats
        Timeline     = $timeline
    }
}

function Score-Metric {
    <#
    .SYNOPSIS
    Assegna un grade (S+/S/A/B/C) a una metrica
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [double]$Value
    )
    
    switch ($Name) {
        "AvgJitterMs" {
            if ($Value -le 1.0) { return "S+" }
            elseif ($Value -le 2.0) { return "S" }
            elseif ($Value -le 4.0) { return "A" }
            elseif ($Value -le 8.0) { return "B" }
            else { return "C" }
        }
        "BurstRatio" {
            if ($Value -le 0.01) { return "S+" }
            elseif ($Value -le 0.03) { return "S" }
            elseif ($Value -le 0.06) { return "A" }
            elseif ($Value -le 0.1) { return "B" }
            else { return "C" }
        }
        "SpikeRatio" {
            if ($Value -le 0.005) { return "S+" }
            elseif ($Value -le 0.01) { return "S" }
            elseif ($Value -le 0.03) { return "A" }
            elseif ($Value -le 0.06) { return "B" }
            else { return "C" }
        }
        default { return "N/A" }
    }
}

function Get-OverallScore {
    <#
    .SYNOPSIS
    Calcola lo score complessivo da più grades
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Grades
    )
    
    $map = @{
        "S+" = 5.0
        "S"  = 4.5
        "A"  = 4.0
        "B"  = 3.0
        "C"  = 2.0
        "N/A"= 0.0
    }
    
    $vals = $Grades | ForEach-Object { $map[$_] }
    if ($vals.Count -eq 0) { return "N/A" }
    
    $avg = ($vals | Measure-Object -Average).Average
    
    if ($avg -ge 4.75) { return "S+" }
    elseif ($avg -ge 4.3) { return "S" }
    elseif ($avg -ge 3.5) { return "A" }
    elseif ($avg -ge 2.5) { return "B" }
    else { return "C" }
}

function Resolve-HostnameSafe {
    <#
    .SYNOPSIS
    Risolve hostname da IP (con timeout e gestione errori)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$IP
    )
    
    Write-Verbose "Resolving hostname for $IP..."
    
    try {
        $h = [System.Net.Dns]::GetHostEntry($IP)
        Write-Verbose "Hostname resolved: $($h.HostName)"
        return $h.HostName
    }
    catch {
        Write-Verbose "Impossibile risolvere hostname per ${IP}: $_"
        return ""
    }
}

function Get-RegionFromHostname {
    <#
    .SYNOPSIS
    Identifica la regione AWS/Cloud dal hostname
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )
    
    if (-not $Hostname) { return "" }
    
    # Mappa regioni AWS
    $awsRegions = @{
        "eu-central-1" = "AWS Frankfurt (eu-central-1)"
        "eu-west-1" = "AWS Dublin (eu-west-1)"
        "eu-west-2" = "AWS London (eu-west-2)"
        "eu-south-1" = "AWS Milan (eu-south-1)"
        "us-east-1" = "AWS Virginia (us-east-1)"
        "us-west-1" = "AWS California (us-west-1)"
        "us-west-2" = "AWS Oregon (us-west-2)"
        "ap-southeast-1" = "AWS Singapore (ap-southeast-1)"
        "ap-northeast-1" = "AWS Tokyo (ap-northeast-1)"
    }
    
    foreach ($region in $awsRegions.Keys) {
        if ($Hostname -match $region) {
            return $awsRegions[$region]
        }
    }
    
    # Riot Games
    if ($Hostname -match "euw1") { return "Riot Games EUW (Europe West)" }
    if ($Hostname -match "eune1") { return "Riot Games EUNE (Europe Nordic & East)" }
    if ($Hostname -match "na1") { return "Riot Games NA (North America)" }
    
    # Altri pattern
    if ($Hostname -match "amsterdam|ams") { return "Amsterdam" }
    if ($Hostname -match "frankfurt|fra") { return "Frankfurt" }
    if ($Hostname -match "london|lon") { return "London" }
    if ($Hostname -match "paris|par") { return "Paris" }
    
    return "Unknown"
}

function Get-GameProfile {
    <#
    .SYNOPSIS
    Ottiene il profilo di un gioco se esiste
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$GameName
    )
    
    if ($Global:GameProfiles.ContainsKey($GameName)) {
        return $Global:GameProfiles[$GameName]
    }
    return $null
}

function Invoke-NetworkDiagnostics {
    <#
    .SYNOPSIS
    Esegue diagnostica di rete (ping, traceroute) verso un server
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        
        [Parameter(Mandatory=$false)]
        [int]$RemotePort = 0,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "."
    )
    
    Write-Host "`n>> Network diagnostics to ${RemoteIP}..." -ForegroundColor Magenta
    
    $results = @{
        Timestamp = (Get-Date).ToString("o")
        RemoteIP = $RemoteIP
        RemotePort = $RemotePort
        Ping = @{}
        Traceroute = @()
        TcpConnection = @{}
    }
    
    # Ping test
    try {
        Write-Host "   Running ping..." -ForegroundColor Yellow
        $pingResults = Test-Connection -ComputerName $RemoteIP -Count 4 -ErrorAction Stop
        
        $latencies = $pingResults | ForEach-Object { $_.Latency }
        $results.Ping = @{
            Sent = 4
            Received = $pingResults.Count
            Lost = 4 - $pingResults.Count
            MinMs = ($latencies | Measure-Object -Minimum).Minimum
            MaxMs = ($latencies | Measure-Object -Maximum).Maximum
            AvgMs = ($latencies | Measure-Object -Average).Average
        }
        
        Write-Host "   Ping: Avg=$([math]::Round($results.Ping.AvgMs,1))ms Min=$($results.Ping.MinMs)ms Max=$($results.Ping.MaxMs)ms" -ForegroundColor Green
    }
    catch {
        Write-Warning "Ping fallito: $_"
        $results.Ping = @{ Error = $_.Exception.Message }
    }
    
    # Traceroute (tracert)
    try {
        Write-Host "   Running traceroute (may take ~30s)..." -ForegroundColor Yellow
        $tracertOutput = & tracert -d -h 15 -w 2000 $RemoteIP 2>&1
        
        $hops = @()
        foreach ($line in $tracertOutput) {
            if ($line -match '^\s*(\d+)\s+(.+)$') {
                $hopNum = $Matches[1]
                $hopData = $Matches[2].Trim()
                
                # Parse latenze
                $times = @()
                if ($hopData -match '(\d+)\s*ms') {
                    $times = [regex]::Matches($hopData, '(\d+)\s*ms') | ForEach-Object { [int]$_.Groups[1].Value }
                }
                
                # Parse IP
                $ip = ""
                if ($hopData -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    $ip = $Matches[1]
                }
                
                $hops += [pscustomobject]@{
                    Hop = [int]$hopNum
                    IP = $ip
                    Latencies = $times
                    AvgMs = if ($times.Count -gt 0) { ($times | Measure-Object -Average).Average } else { $null }
                }
            }
        }
        
        $results.Traceroute = $hops
        Write-Host "   Traceroute: $($hops.Count) hops detected" -ForegroundColor Green
    }
    catch {
        Write-Warning "Traceroute fallito: $_"
        $results.Traceroute = @()
    }
    
    # TCP connection test (if port specified)
    if ($RemotePort -gt 0) {
        try {
            Write-Host "   TCP connection test port ${RemotePort}..." -ForegroundColor Yellow
            $tcpTest = Test-NetConnection -ComputerName $RemoteIP -Port $RemotePort -WarningAction SilentlyContinue -ErrorAction Stop
            
            $results.TcpConnection = @{
                Port = $RemotePort
                Success = $tcpTest.TcpTestSucceeded
                PingSuccess = $tcpTest.PingSucceeded
                Latency = if ($tcpTest.PingReplyDetails) { $tcpTest.PingReplyDetails.RoundtripTime } else { $null }
            }
            
            if ($tcpTest.TcpTestSucceeded) {
                Write-Host "   TCP:$RemotePort connection successful" -ForegroundColor Green
            } else {
                Write-Host "   TCP:$RemotePort connection failed (port may be UDP-only)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Test TCP fallito: $_"
            $results.TcpConnection = @{ Error = $_.Exception.Message }
        }
    }
    
    # Save diagnostics JSON
    $diagFile = Join-Path $OutputDir "diagnostics_${RemoteIP}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $diagFile -Encoding UTF8
    Write-Host "   Diagnostics saved: $diagFile" -ForegroundColor Yellow
    
    return $diagFile
}

function Test-Bufferbloat {
    <#
    .SYNOPSIS
    Test dedicato per misurare bufferbloat (latenza sotto carico)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )
    
    Write-Host "\n>> Bufferbloat Test" -ForegroundColor Magenta
    Write-Host "   This test measures latency increase under network load" -ForegroundColor Yellow
    Write-Host "   Duration: ~20 seconds" -ForegroundColor Yellow
    
    # Preliminary check that server responds to ping
    Write-Host "   Checking server ICMP response..." -ForegroundColor Cyan
    $testPing = Test-Connection -ComputerName $RemoteIP -Count 2 -ErrorAction SilentlyContinue
    if (-not $testPing) {
        Write-Warning "Server $RemoteIP does not respond to ICMP ping"
        Write-Host "   Many game servers block ping for security." -ForegroundColor Yellow
        Write-Host "   Bufferbloat test skipped. Use an alternative server (e.g., 8.8.8.8) for generic test." -ForegroundColor Yellow
        return $null
    }
    
    $results = @{
        TestType = "Bufferbloat"
        TargetIP = $RemoteIP
        BaselineRTT = $null
        LoadedRTT = $null
        LatencyIncrease = $null
        Grade = $null
        Timestamp = (Get-Date).ToString("o")
    }
    
    try {
        # PHASE 1: Baseline (idle) - 10 ping
        Write-Host "   [1/3] Measuring baseline (idle)..." -ForegroundColor Cyan
        $baselinePings = @()
        for ($i = 1; $i -le 10; $i++) {
            $ping = Test-Connection -ComputerName $RemoteIP -Count 1 -ErrorAction SilentlyContinue
            if ($ping) {
                # PowerShell 5.1 usa ResponseTime, PowerShell 7+ usa Latency
                $latency = if ($ping.PSObject.Properties['Latency']) { $ping.Latency } else { $ping.ResponseTime }
                $baselinePings += $latency
            }
            Start-Sleep -Milliseconds 200
        }
        
        if ($baselinePings.Count -lt 5) {
            throw "Baseline ping failed: too many packets lost"
        }
        
        $baselineRTT = ($baselinePings | Measure-Object -Average).Average
        $results.BaselineRTT = [math]::Round($baselineRTT, 2)
        Write-Host "   Baseline RTT: $($results.BaselineRTT)ms" -ForegroundColor Green
        
        # PHASE 2: Generate load (simultaneous download + upload)
        Write-Host "   [2/3] Generating network load..." -ForegroundColor Cyan
        
        # Start continuous ping in background
        $pingJob = Start-Job -ScriptBlock {
            param($ip)
            $pings = @()
            for ($i = 1; $i -le 40; $i++) {
                $p = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
                if ($p) {
                    # PowerShell 5.1 vs 7.x compatibility
                    $latency = if ($p.PSObject.Properties['Latency']) { $p.Latency } else { $p.ResponseTime }
                    $pings += $latency
                }
                Start-Sleep -Milliseconds 250
            }
            return $pings
        } -ArgumentList $RemoteIP
        
        # Generate load with multiple downloads
        Start-Sleep -Seconds 2  # Wait for ping stabilization
        
        $loadJobs = @()
        $testUrls = @(
            "https://speed.cloudflare.com/__down?bytes=10000000",
            "https://speed.cloudflare.com/__down?bytes=10000000",
            "https://speed.cloudflare.com/__down?bytes=10000000"
        )
        
        foreach ($url in $testUrls) {
            $loadJobs += Start-Job -ScriptBlock {
                param($u)
                try {
                    Invoke-WebRequest -Uri $u -Method GET -TimeoutSec 15 -UseBasicParsing | Out-Null
                } catch {
                    # Ignora errori, serve solo per generare carico
                }
            } -ArgumentList $url
        }
        
        Write-Host "   Carico attivo... attendere" -ForegroundColor Yellow
        
        # Attendi completamento ping (10 secondi)
        $pingResult = @(Wait-Job -Job $pingJob -Timeout 15 | Receive-Job)
        Remove-Job -Job $pingJob -Force
        
        # Termina job di carico
        $loadJobs | Stop-Job
        $loadJobs | Remove-Job -Force
        
        # PHASE 3: RTT analysis under load
        Write-Host "   [3/3] Analyzing results..." -ForegroundColor Cyan
        
        if (-not $pingResult -or $pingResult.Count -lt 10) {
            throw "Loaded ping failed: too many packets lost ($($pingResult.Count) received)"
        }
        
        # Use only central 50% of pings (ignore first/last for stabilization)
        $validPings = $pingResult | Select-Object -Skip 5 | Select-Object -First 20
        $loadedRTT = ($validPings | Measure-Object -Average).Average
        $results.LoadedRTT = [math]::Round($loadedRTT, 2)
        
        $latencyIncrease = $loadedRTT - $baselineRTT
        $results.LatencyIncrease = [math]::Round($latencyIncrease, 2)
        
        # Grading bufferbloat
        if ($latencyIncrease -le 10) {
            $results.Grade = "A"
            $interpretation = "Excellent - No significant bufferbloat"
            $color = "Green"
        }
        elseif ($latencyIncrease -le 30) {
            $results.Grade = "B"
            $interpretation = "Good - Slight bufferbloat, acceptable for gaming"
            $color = "Yellow"
        }
        elseif ($latencyIncrease -le 50) {
            $results.Grade = "C"
            $interpretation = "Moderate - Noticeable bufferbloat, possible lag under load"
            $color = "Yellow"
        }
        else {
            $results.Grade = "D"
            $interpretation = "Severo - Bufferbloat critico, latenza instabile"
            $color = "Red"
        }
        
        Write-Host "\n   === RISULTATI BUFFERBLOAT ===" -ForegroundColor Cyan
        Write-Host "   Baseline RTT    : $($results.BaselineRTT)ms" -ForegroundColor White
        Write-Host "   Loaded RTT      : $($results.LoadedRTT)ms" -ForegroundColor White
        Write-Host "   Aumento Latenza : +$($results.LatencyIncrease)ms" -ForegroundColor $color
        Write-Host "   Grade           : $($results.Grade)" -ForegroundColor $color
        Write-Host "   Interpretazione : $interpretation" -ForegroundColor $color
        Write-Host ""
        
        if ($latencyIncrease -gt 30) {
            Write-Host "   💡 SUGGERIMENTO: Abilita SQM/QoS sul router o considera router con migliore QoS" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Test bufferbloat fallito: $_"
        $results.Error = $_.Exception.Message
    }
    
    # Salva risultati
    $bufferbloatFile = Join-Path $OutputDir "bufferbloat_${RemoteIP}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $bufferbloatFile -Encoding UTF8
    Write-Host "   Bufferbloat test saved: $bufferbloatFile" -ForegroundColor Yellow
    
    return $bufferbloatFile
}

function Analyze-QUICFlow {
    <#
    .SYNOPSIS
    Analyze QUIC traffic separately for specific patterns
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Packets,
        
        [Parameter(Mandatory=$true)]
        [string]$LocalIP,
        
        [Parameter(Mandatory=$true)]
        [string]$RemoteIP
    )

    Write-Host "\n>> Separate QUIC traffic analysis" -ForegroundColor Magenta
    
    # Filtra solo pacchetti QUIC - force array con @()
    $quicPkts = @($Packets | Where-Object {
        $proto = $_.PSObject.Properties['_ws.col.Protocol'].Value
        if (-not $proto) { $proto = $_.PSObject.Properties['_ws_col_Protocol'].Value }
        $proto -match "QUIC"
    })
    
    if ($quicPkts.Count -lt 10) {
        Write-Warning "Too few QUIC packets ($($quicPkts.Count)) for meaningful analysis"
        return $null
    }
    
    Write-Verbose "Pacchetti QUIC totali: $($quicPkts.Count)"
    
    # Filtra server -> client - force array con @()
    $svrQuic = @($quicPkts | Where-Object {
        $srcIP = if ($_.PSObject.Properties['ip.src']) { $_.'ip.src' } else { $_.'ip_src' }
        $dstIP = if ($_.PSObject.Properties['ip.dst']) { $_.'ip.dst' } else { $_.'ip_dst' }
        $srcIP -eq $RemoteIP -and $dstIP -eq $LocalIP
    } | Sort-Object {
        if ($_.PSObject.Properties['frame.time_epoch']) {
            [double]$_.'frame.time_epoch'
        } else {
            [double]$_.'frame_time_epoch'
        }
    })
    
    if ($svrQuic.Count -lt 5) {
        Write-Warning "Troppi pochi pacchetti QUIC server->client"
        return $null
    }
    
    Write-Host "   Pacchetti QUIC server->client: $($svrQuic.Count)" -ForegroundColor Yellow
    
    # Calcola metriche QUIC (simile a UDP)
    $times = @()
    $lens = @()
    foreach ($p in $svrQuic) {
        $timeVal = if ($p.PSObject.Properties['frame.time_epoch']) {
            [double]$p.'frame.time_epoch'
        } else {
            [double]$p.'frame_time_epoch'
        }
        $lenVal = if ($p.PSObject.Properties['frame.len']) {
            [int]$p.'frame.len'
        } else {
            [int]$p.'frame_len'
        }
        $times += $timeVal
        $lens += $lenVal
    }
    
    $first = $times[0]
    $last = $times[-1]
    $duration = $last - $first
    
    # Deltas
    $deltas = @()
    for ($i=1; $i -lt $times.Count; $i++) {
        $deltas += ($times[$i] - $times[$i-1]) * 1000.0
    }
    
    if ($deltas.Count -eq 0) { return $null }
    
    $avgDelta = ($deltas | Measure-Object -Average).Average
    $minDelta = ($deltas | Measure-Object -Minimum).Minimum
    $maxDelta = ($deltas | Measure-Object -Maximum).Maximum
    
    # Jitter
    $jitterAbs = @()
    foreach ($d in $deltas) {
        $jitterAbs += [math]::Abs($d - $avgDelta)
    }
    $avgJitter = ($jitterAbs | Measure-Object -Average).Average
    
    # Burst/Spike
    $burstThreshold = $avgDelta / 3.0
    $spikeThreshold = $avgDelta * 2.5
    $burstCount = ($deltas | Where-Object { $_ -lt $burstThreshold }).Count
    $spikeCount = ($deltas | Where-Object { $_ -gt $spikeThreshold }).Count
    $burstRatio = if ($deltas.Count -gt 0) { $burstCount / $deltas.Count } else { 0 }
    $spikeRatio = if ($deltas.Count -gt 0) { $spikeCount / $deltas.Count } else { 0 }
    
    Write-Host "   QUIC AvgDelta: $([math]::Round($avgDelta,2))ms" -ForegroundColor Cyan
    Write-Host "   QUIC Jitter: $([math]::Round($avgJitter,2))ms" -ForegroundColor Cyan
    Write-Host "   QUIC Burst: $([math]::Round($burstRatio,3))" -ForegroundColor Cyan
    Write-Host "   QUIC Spike: $([math]::Round($spikeRatio,3))" -ForegroundColor Cyan
    
    return [pscustomobject]@{
        Protocol = "QUIC"
        PacketCount = $svrQuic.Count
        DurationSec = [math]::Round($duration,3)
        PktPerSec = if ($duration -gt 0) { [math]::Round($svrQuic.Count / $duration,1) } else { 0 }
        AvgDeltaMs = [math]::Round($avgDelta,3)
        MinDeltaMs = [math]::Round($minDelta,3)
        MaxDeltaMs = [math]::Round($maxDelta,3)
        AvgJitterMs = [math]::Round($avgJitter,3)
        BurstRatio = [math]::Round($burstRatio,3)
        SpikeRatio = [math]::Round($spikeRatio,3)
        LenStats = @{
            min = ($lens | Measure-Object -Minimum).Minimum
            max = ($lens | Measure-Object -Maximum).Maximum
            avg = ($lens | Measure-Object -Average).Average
        }
    }
}

function Apply-FightSegmentFilter {
    <#
    .SYNOPSIS
    Filter packets for a specific time window (fight segment)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Packets,
        
        [Parameter(Mandatory=$true)]
        [double]$StartSec,
        
        [Parameter(Mandatory=$true)]
        [double]$EndSec
    )
    
    if ($StartSec -eq 0 -and $EndSec -eq 0) {
        Write-Verbose "Nessun filtro fight segment applicato"
        return $Packets
    }
    
    Write-Host "\n>> Applicazione filtro Fight Segment" -ForegroundColor Magenta
    Write-Host "   Finestra: ${StartSec}s - ${EndSec}s" -ForegroundColor Yellow
    
    # Trova il primo timestamp - gestisci nomi proprietà con punto o underscore
    $firstPacket = $Packets | Select-Object -First 1
    $firstTime = if ($firstPacket.PSObject.Properties['frame.time_epoch']) {
        [double]$firstPacket.'frame.time_epoch'
    } else {
        [double]$firstPacket.'frame_time_epoch'
    }
    
    # Calcola range assoluto
    $absStart = $firstTime + $StartSec
    $absEnd = if ($EndSec -gt 0) { $firstTime + $EndSec } else { [double]::MaxValue }
    
    Write-Verbose "First packet time: $firstTime"
    Write-Verbose "Absolute range: $absStart - $absEnd"
    
    # Filtra pacchetti
    $filtered = $Packets | Where-Object {
        $t = if ($_.PSObject.Properties['frame.time_epoch']) {
            [double]$_.'frame.time_epoch'
        } else {
            [double]$_.'frame_time_epoch'
        }
        $t -ge $absStart -and $t -le $absEnd
    }
    
    Write-Host "   Pacchetti originali: $($Packets.Count)" -ForegroundColor Cyan
    Write-Host "   Pacchetti nel segment: $($filtered.Count)" -ForegroundColor Green
    Write-Host "   Percentuale: $([math]::Round(($filtered.Count / $Packets.Count) * 100, 1))%" -ForegroundColor Green
    
    return $filtered
}

function Show-LiveHUD {
    <#
    .SYNOPSIS
    Mostra HUD real-time con metriche durante capture live
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PcapFile,
        
        [Parameter(Mandatory=$true)]
        [string]$LocalIP,
        
        [Parameter(Mandatory=$false)]
        [int]$RefreshSeconds = 2
    )
    
    Write-Host "\n╔══════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║     LIVE HUD - Gaming Network Monitor        ║" -ForegroundColor Yellow
    Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host "Aggiornamento ogni ${RefreshSeconds}s - Premi Ctrl+C per terminare\n" -ForegroundColor Gray
    
    $iteration = 0
    $lastPacketCount = 0
    
    while ($true) {
        Start-Sleep -Seconds $RefreshSeconds
        $iteration++
        
        try {
            # Analizza PCAP corrente
            $tshark = Get-TsharkPath
            $csvText = & $tshark -r $PcapFile -Y "ip && udp" -T fields -E header=y -E separator=, -e "frame.time_epoch" -e "ip.src" -e "ip.dst" -e "frame.len" 2>&1
            
            if (-not $csvText) { continue }
            
            $rows = $csvText | ConvertFrom-Csv
            
            # Filtra traffico locale
            $relevantPkts = $rows | Where-Object {
                $_."ip.src" -eq $LocalIP -or $_."ip.dst" -eq $LocalIP
            }
            
            $currentCount = $relevantPkts.Count
            $newPackets = $currentCount - $lastPacketCount
            $lastPacketCount = $currentCount
            
            # Calcola metriche ultimi 5 secondi
            $now = [double]($relevantPkts | Select-Object -Last 1)."frame.time_epoch"
            $recentPkts = $relevantPkts | Where-Object {
                ([double]$_."frame.time_epoch") -gt ($now - 5)
            }
            
            # Calcola jitter approssimato
            if ($recentPkts.Count -gt 10) {
                $times = @()
                foreach ($p in $recentPkts) {
                    $times += [double]$p."frame.time_epoch"
                }
                $times = $times | Sort-Object
                
                $deltas = @()
                for ($i=1; $i -lt $times.Count; $i++) {
                    $deltas += ($times[$i] - $times[$i-1]) * 1000.0
                }
                
                if ($deltas.Count -gt 0) {
                    $avgDelta = ($deltas | Measure-Object -Average).Average
                    $jitters = @()
                    foreach ($d in $deltas) {
                        $jitters += [math]::Abs($d - $avgDelta)
                    }
                    $avgJitter = ($jitters | Measure-Object -Average).Average
                    
                    # Display HUD
                    Clear-Host
                    Write-Host "\n╔══════════════════════════════════════════════╗" -ForegroundColor Yellow
                    Write-Host "║     LIVE HUD - Gaming Network Monitor        ║" -ForegroundColor Yellow
                    Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Yellow
                    Write-Host "Update #$iteration | Ultimi 5 secondi\n" -ForegroundColor Gray
                    
                    Write-Host "📊 Pacchetti Totali: " -NoNewline -ForegroundColor Cyan
                    Write-Host "$currentCount " -NoNewline -ForegroundColor White
                    Write-Host "(+$newPackets nuovi)" -ForegroundColor Green
                    
                    Write-Host "⚡ Packet Rate: " -NoNewline -ForegroundColor Cyan
                    Write-Host "$([math]::Round($recentPkts.Count / 5.0, 1)) pkt/s" -ForegroundColor White
                    
                    Write-Host "⏱️  Δt Medio: " -NoNewline -ForegroundColor Cyan
                    Write-Host "$([math]::Round($avgDelta, 2)) ms" -ForegroundColor White
                    
                    Write-Host "📈 Jitter: " -NoNewline -ForegroundColor Cyan
                    $jitterColor = if ($avgJitter -lt 2) { "Green" } elseif ($avgJitter -lt 5) { "Yellow" } else { "Red" }
                    Write-Host "$([math]::Round($avgJitter, 2)) ms" -ForegroundColor $jitterColor
                    
                    # Quality indicator
                    Write-Host "\n🎮 Qualità: " -NoNewline -ForegroundColor Cyan
                    if ($avgJitter -lt 2) {
                        Write-Host "██████████" -NoNewline -ForegroundColor Green
                        Write-Host " OTTIMA" -ForegroundColor Green
                    } elseif ($avgJitter -lt 5) {
                        Write-Host "███████░░░" -NoNewline -ForegroundColor Yellow
                        Write-Host " BUONA" -ForegroundColor Yellow
                    } else {
                        Write-Host "████░░░░░░" -NoNewline -ForegroundColor Red
                        Write-Host " PROBLEMI" -ForegroundColor Red
                    }
                    
                    Write-Host "\n⌨️  Press Ctrl+C to exit" -ForegroundColor DarkGray
                }
            }
        }
        catch {
            Write-Verbose "Errore HUD iteration: $_"
        }
    }
}

function Compare-Reports {
    <#
    .SYNOPSIS
    Confronta più report JSON e genera report comparativo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Pattern,
        
        [Parameter(Mandatory=$false)]
        [string]$OutHtml
    )
    
    Write-Host "`n>> Searching reports with pattern: $Pattern" -ForegroundColor Cyan
    
    $files = Get-ChildItem -Path $Pattern -ErrorAction SilentlyContinue
    
    if (-not $files -or $files.Count -eq 0) {
        throw "No JSON files found with pattern: $Pattern"
    }
    
    Write-Host ">> Found $($files.Count) reports" -ForegroundColor Yellow
    
    $reports = @()
    
    foreach ($file in $files) {
        try {
            $json = Get-Content $file.FullName -Raw | ConvertFrom-Json
            
            $reports += [pscustomobject]@{
                File = $file.Name
                Timestamp = $json.Timestamp
                Game = $json.Game
                RemoteIP = $json.RemoteIP
                RemoteHost = $json.RemoteHost
                Region = if ($json.PSObject.Properties['RegionHint']) { $json.RegionHint } else { "N/A" }
                PacketCount = $json.Flow.PacketCount
                DurationSec = $json.Flow.DurationSec
                AvgDeltaMs = $json.Flow.AvgDeltaMs
                AvgJitterMs = $json.Flow.AvgJitterMs
                BurstRatio = $json.Flow.BurstRatio
                SpikeRatio = $json.Flow.SpikeRatio
                ScoreJitter = $json.Scores.AvgJitter
                ScoreBurst = $json.Scores.Burst
                ScoreSpike = $json.Scores.Spike
                Overall = $json.Scores.Overall
            }
        }
        catch {
            Write-Warning "Errore lettura $($file.Name): $_"
        }
    }
    
    if ($reports.Count -eq 0) {
        throw "Nessun report valido caricato"
    }
    
    # Ordina per timestamp
    $reports = $reports | Sort-Object Timestamp
    
    # Tabella console
    Write-Host "`n=== COMPARE REPORTS ===" -ForegroundColor Cyan
    $reports | Format-Table -Property @(
        @{Label="Data/Ora"; Expression={([datetime]$_.Timestamp).ToString("yyyy-MM-dd HH:mm")}; Width=16},
        @{Label="Gioco"; Expression={$_.Game}; Width=12},
        @{Label="Server"; Expression={$_.RemoteIP}; Width=15},
        @{Label="Jitter"; Expression={"$($_.AvgJitterMs)ms"}; Width=10},
        @{Label="Burst"; Expression={$_.BurstRatio}; Width=8},
        @{Label="Spike"; Expression={$_.SpikeRatio}; Width=8},
        @{Label="Score"; Expression={$_.Overall}; Width=6}
    ) -AutoSize
    
    # HTML se richiesto
    if ($OutHtml) {
        Write-Host ">> Generazione HTML comparativo..." -ForegroundColor Cyan
        
        $reportData = $reports | ConvertTo-Json -Depth 4 -Compress
        
        $htmlCompare = @"
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Game Net Analyzer - Compare Reports</title>
<style>
 body { font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:20px; }
 h1,h2 { color:#58a6ff; }
 .card { background:#161b22; border-radius:12px; padding:16px 20px; margin-bottom:20px; box-shadow:0 0 8px rgba(0,0,0,0.4); }
 canvas { background:#010409; border-radius:8px; padding:8px; }
 table { width:100%; border-collapse: collapse; margin-top:12px; }
 th { background:#21262d; padding:10px; text-align:left; color:#58a6ff; border-bottom:2px solid #30363d; }
 td { padding:8px; border-bottom:1px solid #21262d; }
 tr:hover { background:#0d1117; }
 .grade-SP { color:#39d353; }
 .grade-S  { color:#3fb950; }
 .grade-A  { color:#58a6ff; }
 .grade-B  { color:#d29922; }
 .grade-C  { color:#f85149; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
</head>
<body>

<h1>🎮 Game Network Analyzer - Compare Reports</h1>

<div class="card">
  <h2>📊 Metrics Trend</h2>
  <canvas id="compareChart" height="100"></canvas>
</div>

<div class="card">
  <h2>📋 Report Details</h2>
  <table id="reportTable"></table>
</div>

<script>
const reports = $reportData;

// Tabella
const table = document.getElementById('reportTable');
let tableHtml = '<thead><tr><th>Data/Ora</th><th>Gioco</th><th>Server</th><th>Regione</th><th>Jitter (ms)</th><th>Burst</th><th>Spike</th><th>Overall</th></tr></thead><tbody>';

reports.forEach(r => {
  const dt = new Date(r.Timestamp);
  tableHtml += '<tr>';
  tableHtml += '<td>' + dt.toLocaleString('it-IT') + '</td>';
  tableHtml += '<td>' + r.Game + '</td>';
  tableHtml += '<td>' + r.RemoteIP + '</td>';
  tableHtml += '<td>' + (r.Region || 'N/A') + '</td>';
  tableHtml += '<td>' + r.AvgJitterMs + '</td>';
  tableHtml += '<td>' + r.BurstRatio + '</td>';
  tableHtml += '<td>' + r.SpikeRatio + '</td>';
  tableHtml += '<td class="grade-' + r.Overall.replace('+','P') + '">' + r.Overall + '</td>';
  tableHtml += '</tr>';
});

tableHtml += '</tbody>';
table.innerHTML = tableHtml;

// Grafico trend
const labels = reports.map(r => new Date(r.Timestamp).toLocaleDateString('it-IT'));
const jitterData = reports.map(r => r.AvgJitterMs);
const burstData = reports.map(r => r.BurstRatio * 100);
const spikeData = reports.map(r => r.SpikeRatio * 100);

const ctx = document.getElementById('compareChart').getContext('2d');
new Chart(ctx, {
  type: 'line',
  data: {
    labels: labels,
    datasets: [
      {
        label: 'Jitter Medio (ms)',
        data: jitterData,
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88, 166, 255, 0.1)',
        yAxisID: 'y',
        tension: 0.3
      },
      {
        label: 'Burst Ratio (%)',
        data: burstData,
        borderColor: '#d29922',
        backgroundColor: 'rgba(210, 153, 34, 0.1)',
        yAxisID: 'y1',
        tension: 0.3
      },
      {
        label: 'Spike Ratio (%)',
        data: spikeData,
        borderColor: '#f85149',
        backgroundColor: 'rgba(248, 81, 73, 0.1)',
        yAxisID: 'y1',
        tension: 0.3
      }
    ]
  },
  options: {
    responsive: true,
    interaction: {
      mode: 'index',
      intersect: false
    },
    scales: {
      y: {
        type: 'linear',
        display: true,
        position: 'left',
        title: { display: true, text: 'Jitter (ms)', color: '#8b949e' },
        ticks: { color: '#8b949e' },
        grid: { color: '#21262d' }
      },
      y1: {
        type: 'linear',
        display: true,
        position: 'right',
        title: { display: true, text: 'Burst/Spike (%)', color: '#8b949e' },
        ticks: { color: '#8b949e' },
        grid: { drawOnChartArea: false }
      },
      x: {
        ticks: { color: '#8b949e' },
        grid: { color: '#21262d' }
      }
    },
    plugins: {
      legend: {
        labels: { color: '#e6edf3' }
      }
    }
  }
});
</script>

</body>
</html>
"@
        
        $htmlCompare | Out-File -FilePath $OutHtml -Encoding UTF8
        Write-Host ">> HTML saved: $OutHtml" -ForegroundColor Green
    }
}

function Analyze-Pcap {
    <#
    .SYNOPSIS
    Main PCAP analysis function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PcapToAnalyze,
        
        [Parameter(Mandatory=$true)]
        [string]$GameName,
        
        [Parameter(Mandatory=$false)]
        [string]$Filter = "ip && (udp || quic)",
        
        [Parameter(Mandatory=$false)]
        [bool]$RunDiagnostics = $false,
        
        [Parameter(Mandatory=$false)]
        [bool]$AnalyzeQUIC = $false,
        
        [Parameter(Mandatory=$false)]
        [double]$FightStartSec = 0,
        
        [Parameter(Mandatory=$false)]
        [double]$FightEndSec = 0,
        
        [Parameter(Mandatory=$false)]
        [bool]$TestBufferbloat = $false
    )

    Write-Host "`n>> PCAP Analysis: $PcapToAnalyze" -ForegroundColor Cyan

    # Validation
    if (-not (Test-Path $PcapToAnalyze)) {
        throw "PCAP not found: $PcapToAnalyze"
    }

    $localIPs = Get-LocalIPv4
    if (-not $localIPs) {
        throw "Unable to determine local IP"
    }

    Write-Host ">> Local IPs detected: $($localIPs -join ', ')" -ForegroundColor Yellow

    # Parse CSV da tshark
    $rows = Invoke-TsharkCsv -Pcap $PcapToAnalyze -Filter $Filter
    
    # Apply fight segment filter if specified
    if ($FightStartSec -gt 0 -or $FightEndSec -gt 0) {
        $rows = Apply-FightSegmentFilter -Packets $rows -StartSec $FightStartSec -EndSec $FightEndSec
        if ($rows.Count -lt 10) {
            throw "Too few packets in specified fight segment"
        }
    }

    # Build UDP flows where one endpoint is a local IP
    $udpRows = $rows | Where-Object { 
        $proto = $_.'_ws.col.Protocol'
        if (-not $proto) { $proto = $_.'_ws_col_Protocol' }
        $proto -match "UDP" 
    }

    if ($udpRows.Count -lt 5) {
        Write-Warning "Only $($udpRows.Count) UDP packets found. The PCAP may not contain a complete match."
    }

    Write-Host ">> UDP packets found: $($udpRows.Count)" -ForegroundColor Cyan

    # Build flow map
    $flows = @{}

    foreach ($r in $udpRows) {
        $src = $r."ip.src"
        $dst = $r."ip.dst"
        $sp  = $r."udp.srcport"
        $dp  = $r."udp.dstport"

        # Almeno uno degli endpoint deve essere locale
        if (-not ($localIPs -contains $src) -and -not ($localIPs -contains $dst)) {
            continue
        }

        if ($localIPs -contains $src) {
            $local = $src
            $remote = $dst
            $remotePort = $dp
            $direction = "out"
        } else {
            $local = $dst
            $remote = $src
            $remotePort = $sp
            $direction = "in"
        }

        $key = "$local|$remote|$remotePort"
        if (-not $flows.ContainsKey($key)) {
            $flows[$key] = @{
                Local  = $local
                Remote = $remote
                Port   = $remotePort
                CountTotal = 0
                CountFromServer = 0
                CountFromClient = 0
            }
        }
        
        $flows[$key].CountTotal++
        
        if ($direction -eq "in") {
            $flows[$key].CountFromServer++
        } else {
            $flows[$key].CountFromClient++
        }
    }

    if ($flows.Count -eq 0) {
        throw "No UDP flows with local endpoint found in PCAP"
    }

    Write-Host ">> Unique UDP flows found: $($flows.Count)" -ForegroundColor Cyan

    # Choose main flow (max server->client packets)
    $mainFlow = $flows.GetEnumerator() | 
        Sort-Object { $_.Value.CountFromServer } -Descending | 
        Select-Object -First 1

    $localIP    = $mainFlow.Value.Local
    $remoteIP   = $mainFlow.Value.Remote
    $remotePort = $mainFlow.Value.Port
    $pktCount   = $mainFlow.Value.CountTotal
    $pktFromSvr = $mainFlow.Value.CountFromServer

    Write-Host "`n>> Main flow detected (likely game server):" -ForegroundColor Green
    Write-Host "   LocalIP         : $localIP" -ForegroundColor White
    Write-Host "   RemoteIP        : $remoteIP" -ForegroundColor White
    Write-Host "   RemotePort      : $remotePort" -ForegroundColor White
    Write-Host "   Packets Total   : $pktCount" -ForegroundColor White
    Write-Host "   Packets Svr->Cli: $pktFromSvr" -ForegroundColor White

    # Detailed analysis
    $flowAnalysis = Analyze-Flow -Packets $rows -LocalIP $localIP -RemoteIP $remoteIP -RemotePort $remotePort
    
    if (-not $flowAnalysis) {
        throw "Unable to analyze server->client flow (insufficient data)"
    }
    
    # Separate QUIC analysis if requested
    $quicAnalysis = $null
    if ($AnalyzeQUIC) {
        $quicAnalysis = Analyze-QUICFlow -Packets $rows -LocalIP $localIP -RemoteIP $remoteIP
    }

    # Risoluzione hostname
    $hostname = Resolve-HostnameSafe -IP $remoteIP
    
    # Riconoscimento regione
    $regionHint = Get-RegionFromHostname -Hostname $hostname
    Write-Verbose "Region identified: $regionHint"
    
    # Profilo gioco
    $gameProfile = Get-GameProfile -GameName $GameName
    if ($gameProfile) {
        Write-Host "`n>> Profilo gioco '$GameName' caricato" -ForegroundColor Magenta
        Write-Host "   ExpectedTickMs: $($gameProfile.ExpectedTickMs) ms" -ForegroundColor White
        Write-Host "   Target Regions: $($gameProfile.TargetRegions -join ', ')" -ForegroundColor White
        
        # Confronto tick rate
        $deltaVsExpected = [math]::Abs($flowAnalysis.AvgDeltaMs - $gameProfile.ExpectedTickMs)
        if ($deltaVsExpected -gt 5) {
            Write-Warning "Δt medio ($($flowAnalysis.AvgDeltaMs)ms) differisce dal tick atteso ($($gameProfile.ExpectedTickMs)ms) di $([math]::Round($deltaVsExpected,1))ms"
        }
    }

    # Calcolo scores
    $gradeJitter = Score-Metric -Name "AvgJitterMs" -Value $flowAnalysis.AvgJitterMs
    $gradeBurst  = Score-Metric -Name "BurstRatio"  -Value $flowAnalysis.BurstRatio
    $gradeSpike  = Score-Metric -Name "SpikeRatio"  -Value $flowAnalysis.SpikeRatio
    $overall     = Get-OverallScore -Grades @($gradeJitter,$gradeBurst,$gradeSpike)

    Write-Host "`n>> Calculated scores:" -ForegroundColor Cyan
    Write-Host "   Jitter  : $gradeJitter" -ForegroundColor White
    Write-Host "   Burst   : $gradeBurst" -ForegroundColor White
    Write-Host "   Spike   : $gradeSpike" -ForegroundColor White
    Write-Host "   Overall : $overall" -ForegroundColor Green

    # Preparazione output
    $now = Get-Date
    $runId = $now.ToString("yyyyMMdd_HHmmss")
    $baseName = "netreport_${GameName}_${runId}"

    $outputDirFull = (Resolve-Path $OutputDir).Path
    $jsonPath = Join-Path $outputDirFull ($baseName + ".json")
    $htmlPath = Join-Path $outputDirFull ($baseName + ".html")
    
    # Diagnostica rete opzionale
    $diagFile = $null
    if ($RunDiagnostics) {
        try {
            # Usa directory diagnostics separata
            $diagDir = Get-OutputDirectory -AnalysisType "diagnostics"
            if (-not (Test-Path $diagDir)) {
                New-Item -ItemType Directory -Path $diagDir -Force | Out-Null
            }
            $diagFile = Invoke-NetworkDiagnostics -RemoteIP $remoteIP -RemotePort $remotePort -OutputDir $diagDir
        }
        catch {
            Write-Warning "Errore durante diagnostica: $_"
        }
    }
    
    # Test bufferbloat opzionale
    $bufferbloatFile = $null
    if ($PSBoundParameters.ContainsKey('TestBufferbloat') -and $TestBufferbloat) {
        try {
            $diagDir = Get-OutputDirectory -AnalysisType "diagnostics"
            if (-not (Test-Path $diagDir)) {
                New-Item -ItemType Directory -Path $diagDir -Force | Out-Null
            }
            $bufferbloatFile = Test-Bufferbloat -RemoteIP $remoteIP -OutputDir $diagDir
        }
        catch {
            Write-Warning "Errore durante test bufferbloat: $_"
        }
    }

    # Oggetto JSON
    $jsonObj = [pscustomobject]@{
        ToolVersion = $Global:ScriptVersion
        Timestamp   = $now.ToString("o")
        Game        = $GameName
        GameProfile = $gameProfile
        PcapFile    = (Resolve-Path $PcapToAnalyze).Path
        LocalIP     = $localIP
        RemoteIP    = $remoteIP
        RemotePort  = $remotePort
        RemoteHost  = $hostname
        RegionHint  = $regionHint
        DiagnosticsFile = $diagFile
        BufferbloatFile = $bufferbloatFile
        FightSegment = if ($FightStartSec -gt 0 -or $FightEndSec -gt 0) {
            @{
                StartSec = $FightStartSec
                EndSec = $FightEndSec
                Enabled = $true
            }
        } else { $null }
        Flow        = $flowAnalysis
        QUICFlow    = $quicAnalysis
        Scores      = @{
            AvgJitter = $gradeJitter
            Burst     = $gradeBurst
            Spike     = $gradeSpike
            Overall   = $overall
        }
    }

    # Salva JSON
    if ($PSCmdlet.ShouldProcess($jsonPath, "Salvataggio JSON report")) {
        $jsonObj | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host ">> JSON saved: $jsonPath" -ForegroundColor Yellow
    }

    # Genera HTML
    $timelineJson = ($flowAnalysis.Timeline | ConvertTo-Json -Depth 4 -Compress)
    
    $html = @"
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Game Net Report - $GameName - $runId</title>
<style>
 body { font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:20px; }
 h1,h2 { color:#58a6ff; margin-top:0; }
 .card { background:#161b22; border-radius:12px; padding:16px 20px; margin-bottom:20px; box-shadow:0 0 8px rgba(0,0,0,0.4); }
 .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:16px; }
 .tag { display:inline-block; padding:4px 10px; border-radius:999px; font-size:13px; font-weight:600; margin-right:8px; }
 .grade-SP { background:#39d35333; border:1px solid #39d353; color:#39d353; }
 .grade-S  { background:#23863633; border:1px solid #238636; color:#3fb950; }
 .grade-A  { background:#2f81f733; border:1px solid #2f81f7; color:#58a6ff; }
 .grade-B  { background:#bb800933; border:1px solid #bb8009; color:#d29922; }
 .grade-C  { background:#f8514933; border:1px solid #f85149; color:#f85149; }
 code { background:#111827; padding:2px 6px; border-radius:4px; font-family:'Consolas',monospace; }
 canvas { background:#010409; border-radius:8px; padding:8px; }
 .metric-row { display:flex; justify-content:space-between; margin:8px 0; }
 .metric-label { color:#8b949e; }
 .metric-value { font-weight:600; color:#e6edf3; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script><script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-annotation@3"></script></head>
<body>

<h1>🎮 Game Network Report - $GameName</h1>
<div class="card">
  <p><strong>Run ID:</strong> $runId</p>
  <p><strong>Data/Ora:</strong> $($now.ToString("yyyy-MM-dd HH:mm:ss"))</p>
  <p><strong>PCAP:</strong> <code>$(Split-Path $PcapToAnalyze -Leaf)</code></p>
  <p><strong>Tool Version:</strong> v$Global:ScriptVersion</p>
</div>

<div class="grid">
  <div class="card">
    <h2>📡 Endpoint</h2>
    <div class="metric-row"><span class="metric-label">Local IP:</span> <code>$localIP</code></div>
    <div class="metric-row"><span class="metric-label">Server IP:</span> <code>$remoteIP</code></div>
    <div class="metric-row"><span class="metric-label">Server Host:</span> <code>$hostname</code></div>
    <div class="metric-row"><span class="metric-label">Server Port:</span> <code>${remotePort} (UDP)</code></div>
  </div>
  
  <div class="card">
    <h2>📊 Flow Stats</h2>
    <div class="metric-row"><span class="metric-label">Packets (svr→cli):</span> <span class="metric-value">$($flowAnalysis.PacketCount)</span></div>
    <div class="metric-row"><span class="metric-label">Durata:</span> <span class="metric-value">$($flowAnalysis.DurationSec) s</span></div>
    <div class="metric-row"><span class="metric-label">Packet rate:</span> <span class="metric-value">$($flowAnalysis.PktPerSec) pkt/s</span></div>
    <div class="metric-row"><span class="metric-label">Packet size:</span> <span class="metric-value">$([math]::Round($flowAnalysis.LenStats.avg,1))/$($flowAnalysis.LenStats.min)/$($flowAnalysis.LenStats.max) bytes</span></div>
  </div>
  
  <div class="card">
    <h2>⏱️ Timing</h2>
    <div class="metric-row"><span class="metric-label">Δt medio:</span> <span class="metric-value">$($flowAnalysis.AvgDeltaMs) ms</span></div>
    <div class="metric-row"><span class="metric-label">Δt min/max:</span> <span class="metric-value">$($flowAnalysis.MinDeltaMs) / $($flowAnalysis.MaxDeltaMs) ms</span></div>
    <div class="metric-row"><span class="metric-label">Jitter medio:</span> <span class="metric-value">$($flowAnalysis.AvgJitterMs) ms</span></div>
    <div class="metric-row"><span class="metric-label">Jitter max:</span> <span class="metric-value">$($flowAnalysis.MaxJitterMs) ms</span></div>
  </div>
  
  <div class="card">
    <h2>📈 Pattern</h2>
    <div class="metric-row"><span class="metric-label">Burst ratio:</span> <span class="metric-value">$($flowAnalysis.BurstRatio)</span></div>
    <div class="metric-row"><span class="metric-label">Spike ratio:</span> <span class="metric-value">$($flowAnalysis.SpikeRatio)</span></div>
  </div>
</div>

<div class="card">
  <h2>🏆 Performance Score</h2>
  <p>
    <span class="tag grade-$($gradeJitter.Replace('+','P'))">Jitter: $gradeJitter</span>
    <span class="tag grade-$($gradeBurst.Replace('+','P'))">Burst: $gradeBurst</span>
    <span class="tag grade-$($gradeSpike.Replace('+','P'))">Spike: $gradeSpike</span>
    <span class="tag grade-$($overall.Replace('+','P'))">Overall: $overall</span>
  </p>
</div>

<div class="card">
  <h2>📝 Interpretazione</h2>
  $(if ($overall -match "S") {
    "<p style='color:#3fb950;font-weight:600;'>✅ Ottima qualità di rete per gaming competitivo!</p>"
    "<p>La tua connessione al server è eccellente:"
    "<ul>"
    "<li>Jitter medio <strong>$($flowAnalysis.AvgJitterMs) ms</strong> - Stabilità eccellente per gameplay fluido</li>"
    "<li>Burst ratio <strong>$($flowAnalysis.BurstRatio)</strong> - Pochi pacchetti compressi</li>"
    "<li>Spike ratio <strong>$($flowAnalysis.SpikeRatio)</strong> - Rarissimi ritardi improvvisi</li>"
    if ($hostname -match "eu-central-1") {
      "<li>Server regione: <strong>EU Central (Francoforte)</strong> - Ottimale per Italia</li>"
    } elseif ($hostname -match "eu-west-1") {
      "<li>Server regione: <strong>EU West (Dublino)</strong> - Buona per Europa occidentale</li>"
    }
    "</ul>"
    "<p style='color:#58a6ff;'>💡 <strong>Suggerimento:</strong> Mantieni questa configurazione di rete per risultati ottimali in ranked/competitive.</p>"
    "</p>"
  } elseif ($overall -eq "A") {
    "<p style='color:#58a6ff;font-weight:600;'>✔️ Buona qualità di rete</p>"
    "<p>La connessione è più che adeguata per gaming:"
    "<ul>"
    if ($gradeJitter -match "[BC]") {
      "<li>⚠️ Jitter medio <strong>$($flowAnalysis.AvgJitterMs) ms</strong> - Potresti notare qualche micro-stuttering</li>"
    }
    if ($gradeBurst -match "[BC]") {
      "<li>⚠️ Burst ratio elevato - Il server sta comprimendo molti pacchetti insieme</li>"
    }
    if ($gradeSpike -match "[BC]") {
      "<li>⚠️ Spike ratio $($flowAnalysis.SpikeRatio) - Ci sono alcuni ritardi improvvisi</li>"
    }
    "</ul>"
    "<p style='color:#d29922;'>💡 <strong>Suggerimento:</strong> Chiudi applicazioni in background che usano la rete (browser, download, streaming).</p>"
    "</p>"
  } else {
    "<p style='color:#f85149;font-weight:600;'>⚠️ Qualità di rete da migliorare</p>"
    "<p>La connessione presenta problemi significativi:"
    "<ul>"
    if ($flowAnalysis.AvgJitterMs -gt 8) {
      "<li>❌ Jitter molto alto (<strong>$($flowAnalysis.AvgJitterMs) ms</strong>) - Gameplay instabile</li>"
    }
    if ($flowAnalysis.BurstRatio -gt 0.1) {
      "<li>❌ Troppi burst packets - Congestione di rete</li>"
    }
    if ($flowAnalysis.SpikeRatio -gt 0.06) {
      "<li>❌ Frequenti spike di latenza - Lag visibile in gioco</li>"
    }
    "</ul>"
    "<p style='color:#f85149;'>💡 <strong>Suggerimenti:</strong></p>"
    "<ul>"
    "<li>Usa connessione cablata (Ethernet) invece di Wi-Fi</li>"
    "<li>Verifica che nessun altro dispositivo stia saturando la banda</li>"
    "<li>Contatta l'ISP se il problema persiste</li>"
    "<li>Considera QoS (Quality of Service) sul router per prioritizzare gaming</li>"
    "</ul>"
    "</p>"
  })
</div>
  <h2>📉 Timeline Δt (server → client)</h2>
  <canvas id="timelineChart" height="130"></canvas>
</div>

<script>
const timelineData = $timelineJson;
const avgDelta = $($flowAnalysis.AvgDeltaMs);
const spikeThreshold = avgDelta * 2.5;

const labels = timelineData.map(p => p.t);
const deltas = timelineData.map(p => p.d);
const spikes = timelineData.map(p => p.d > spikeThreshold ? p.d : null);

const ctx = document.getElementById('timelineChart').getContext('2d');
new Chart(ctx, {
  type: 'line',
  data: {
    labels: labels,
    datasets: [
      {
        label: 'Δt (ms)',
        data: deltas,
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88, 166, 255, 0.1)',
        borderWidth: 2,
        pointRadius: 0,
        tension: 0.3,
        fill: true
      },
      {
        label: 'Spikes',
        data: spikes,
        borderColor: '#f85149',
        backgroundColor: '#f85149',
        borderWidth: 0,
        pointRadius: 3,
        pointStyle: 'triangle',
        showLine: false
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        title: { display:true, text:'Tempo (s dall\'inizio)', color:'#8b949e' },
        ticks: { color: '#8b949e' },
        grid: { color: '#21262d' }
      },
      y: {
        title: { display:true, text:'Δt server→client (ms)', color:'#8b949e' },
        ticks: { color: '#8b949e' },
        grid: { color: '#21262d' },
        beginAtZero: false
      }
    },
    plugins: {
      legend: { 
        display: true,
        labels: { color: '#e6edf3' }
      },
      annotation: {
        annotations: {
          targetLine: {
            type: 'line',
            yMin: avgDelta,
            yMax: avgDelta,
            borderColor: '#3fb950',
            borderWidth: 2,
            borderDash: [5, 5],
            label: {
              display: true,
              content: 'Target Δt: ' + avgDelta.toFixed(1) + ' ms',
              position: 'end',
              backgroundColor: 'rgba(63, 185, 80, 0.8)',
              color: '#fff',
              font: { size: 11 }
            }
          },
          spikeThreshold: {
            type: 'line',
            yMin: spikeThreshold,
            yMax: spikeThreshold,
            borderColor: '#f85149',
            borderWidth: 1,
            borderDash: [3, 3],
            label: {
              display: true,
              content: 'Spike threshold',
              position: 'start',
              backgroundColor: 'rgba(248, 81, 73, 0.6)',
              color: '#fff',
              font: { size: 10 }
            }
          }
        }
      }
    }
  }
});
</script>

</body>
</html>
"@

    # Salva HTML
    if ($PSCmdlet.ShouldProcess($htmlPath, "Salvataggio HTML report")) {
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host ">> HTML saved: $htmlPath" -ForegroundColor Yellow
    }

    # Riassunto finale
    Write-Host "`n=== 🎯 GAMING SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Server       : ${remoteIP}:${remotePort}" -ForegroundColor White
    if ($hostname) {
        Write-Host "Hostname     : $hostname" -ForegroundColor White
    }
    Write-Host "Packets      : $($flowAnalysis.PacketCount) in $($flowAnalysis.DurationSec)s (~$($flowAnalysis.PktPerSec) pkt/s)" -ForegroundColor White
    Write-Host "Jitter medio : $($flowAnalysis.AvgJitterMs) ms  → Grade: $gradeJitter" -ForegroundColor White
    Write-Host "Burst ratio  : $($flowAnalysis.BurstRatio)      → Grade: $gradeBurst" -ForegroundColor White
    Write-Host "Spike ratio  : $($flowAnalysis.SpikeRatio)      → Grade: $gradeSpike" -ForegroundColor White
    Write-Host "Overall      : $overall" -ForegroundColor Green
    Write-Host "`nReports saved in: $outputDirFull" -ForegroundColor Yellow
}

function Show-InteractiveMenu {
    <#
    .SYNOPSIS
    Shows interactive menu to simplify script usage
    #>
    
    Clear-Host
    Write-Host "`n╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Game Network Analyzer v$Global:ScriptVersion            ║" -ForegroundColor Cyan
    Write-Host "║  Interactive Menu                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
    
    Write-Host "Select an operation:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Analyze existing PCAP file" -ForegroundColor Green
    Write-Host "  [2] Live capture gaming traffic" -ForegroundColor Green
    Write-Host "  [3] Compare multiple sessions" -ForegroundColor Green
    Write-Host "  [4] Analyze PCAP with time filter (Fight Segment)" -ForegroundColor Cyan
    Write-Host "  [5] Analyze PCAP with network diagnostics" -ForegroundColor Cyan
    Write-Host "  [6] Bufferbloat Test (latency under load)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [H] Help - Show advanced commands" -ForegroundColor DarkGray
    Write-Host "  [Q] Exit" -ForegroundColor DarkGray
    Write-Host ""
    
    $choice = Read-Host "Choice"
    
    switch ($choice.ToUpper()) {
        "1" {
            # Base PCAP analysis
            Write-Host "`n>> PCAP File Analysis" -ForegroundColor Magenta
            $pcapPath = Read-Host "Enter the full path to the .pcap/.pcapng file`n  (e.g., C:\Users\Lorenzo\Desktop\New folder\fortnite_match1.pcapng)"
            
            if (-not (Test-Path $pcapPath)) {
                Write-Host "File not found: $pcapPath" -ForegroundColor Red
                Read-Host "Press ENTER to return to menu"
                return "menu"
            }
            
            Write-Host "`nGame (press ENTER for automatic detection):" -ForegroundColor Yellow
            Write-Host "  Supported: Fortnite, Valorant, CS2, Warzone, LeagueOfLegends" -ForegroundColor DarkGray
            $gameName = Read-Host "Game name"
            if (-not $gameName) { $gameName = "Auto" }
            
            return @{
                Mode = "pcap"
                PcapPath = $pcapPath
                GameName = $gameName
            }
        }
        
        "2" {
            # Live capture
            Write-Host "`n>> Live Capture" -ForegroundColor Magenta
            Write-Host "Available network interfaces:" -ForegroundColor Yellow
            Get-NetAdapter | Where-Object Status -eq 'Up' | Format-Table Name, InterfaceDescription, LinkSpeed -AutoSize
            
            $interface = Read-Host "Interface name (e.g., Ethernet, Wi-Fi)"
            if (-not $interface) {
                Write-Host "Interface required" -ForegroundColor Red
                Read-Host "Press ENTER to return to menu"
                return "menu"
            }
            
            $seconds = Read-Host "Capture duration in seconds (default: 30)"
            if (-not $seconds) { $seconds = 30 }
            
            $gameName = Read-Host "Game name (optional, press ENTER for Auto)"
            if (-not $gameName) { $gameName = "Auto" }
            
            Write-Host "`nCapture will start in 3 seconds... Get ready!" -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            
            return @{
                Mode = "live"
                Interface = $interface
                CaptureSeconds = [int]$seconds
                GameName = $gameName
            }
        }
        
        "3" {
            # Compare reports
            Write-Host "`n>> Compare Multiple Sessions" -ForegroundColor Magenta
            Write-Host "This function searches for JSON files in the game_net_reports folder" -ForegroundColor Yellow
            
            $scriptDir = Split-Path -Parent $PSCommandPath
            $reportsDir = Join-Path $scriptDir "game_net_reports\pcap_analysis"
            
            if (Test-Path $reportsDir) {
                Write-Host "`nJSON files found:" -ForegroundColor Cyan
                Get-ChildItem -Path $reportsDir -Recurse -Filter "*.json" | 
                    Select-Object -First 10 | 
                    ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor DarkGray }
            }
            
            Write-Host "`nSearch pattern (e.g., *Fortnite*.json, *.json):" -ForegroundColor Yellow
            $pattern = Read-Host "Pattern"
            if (-not $pattern) { $pattern = "*.json" }
            
            return @{
                Mode = "compare"
                ComparePattern = $pattern
            }
        }
        
        "4" {
            # Fight segment
            Write-Host "`n>> Analysis with Time Filter (Fight Segment)" -ForegroundColor Magenta
            Write-Host "Analyze only a specific time window of the PCAP" -ForegroundColor Yellow
            
            $pcapPath = Read-Host "`nPCAP file path"
            if (-not (Test-Path $pcapPath)) {
                Write-Host "File not found: $pcapPath" -ForegroundColor Red
                Read-Host "Press ENTER to return to menu"
                return "menu"
            }
            
            $startSec = Read-Host "Window start (seconds from beginning, e.g., 60)"
            $endSec = Read-Host "Window end (seconds, 0=until end, e.g., 180)"
            
            $gameName = Read-Host "Game name (optional, press ENTER for Auto)"
            if (-not $gameName) { $gameName = "Auto" }
            
            return @{
                Mode = "pcap"
                PcapPath = $pcapPath
                GameName = $gameName
                FightStartSec = [double]$startSec
                FightEndSec = [double]$endSec
            }
        }
        
        "5" {
            # Full diagnostics
            Write-Host "`n>> PCAP Analysis + Network Diagnostics" -ForegroundColor Magenta
            Write-Host "Analyze PCAP and run ping/traceroute to game server" -ForegroundColor Yellow
            
            $pcapPath = Read-Host "`nPCAP file path"
            if (-not (Test-Path $pcapPath)) {
                Write-Host "File not found: $pcapPath" -ForegroundColor Red
                Read-Host "Press ENTER to return to menu"
                return "menu"
            }
            
            $gameName = Read-Host "Game name (optional, press ENTER for Auto)"
            if (-not $gameName) { $gameName = "Auto" }
            
            return @{
                Mode = "pcap"
                PcapPath = $pcapPath
                GameName = $gameName
                EnableDiagnostics = $true
            }
        }
        
        "6" {
            # Test bufferbloat
            Write-Host "`n>> Bufferbloat Test (Latency Under Load)" -ForegroundColor Magenta
            Write-Host "This test measures latency increase when the network is under load" -ForegroundColor Yellow
            Write-Host "You must first analyze a PCAP to identify the game server" -ForegroundColor Yellow
            
            $pcapPath = Read-Host "`nPCAP file path"
            if (-not (Test-Path $pcapPath)) {
                Write-Host "File not found: $pcapPath" -ForegroundColor Red
                Read-Host "Press ENTER to return to menu"
                return "menu"
            }
            
            $gameName = Read-Host "Game name (optional, press ENTER for Auto)"
            if (-not $gameName) { $gameName = "Auto" }
            
            Write-Host "`nWARNING: The test will generate network load for ~20 seconds" -ForegroundColor Yellow
            $confirm = Read-Host "Continue? (Y/N)"
            if ($confirm -ne "Y" -and $confirm -ne "y" -and $confirm -ne "S" -and $confirm -ne "s") {
                return "menu"
            }
            
            return @{
                Mode = "pcap"
                PcapPath = $pcapPath
                GameName = $gameName
                TestBufferbloat = $true
            }
        }
        
        "H" {
            # Help
            Write-Host "`n╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
            Write-Host "║  ADVANCED COMMANDS                             ║" -ForegroundColor Cyan
            Write-Host "╚════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
            
            Write-Host "For advanced features, use command mode:" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Separate QUIC analysis:" -ForegroundColor White
            Write-Host '  .\game_net_analyzer.ps1 -Mode pcap -PcapPath "file.pcapng" -AnalyzeQUIC' -ForegroundColor Gray
            Write-Host ""
            Write-Host "Live capture with real-time HUD:" -ForegroundColor White
            Write-Host '  .\game_net_analyzer.ps1 -Mode live -Interface "Ethernet" -HudMode' -ForegroundColor Gray
            Write-Host ""
            Write-Host "Custom tshark filter:" -ForegroundColor White
            Write-Host '  .\game_net_analyzer.ps1 -Mode pcap -PcapPath "file.pcapng" -CustomFilter "udp.port==9060"' -ForegroundColor Gray
            Write-Host ""
            Write-Host "For all examples, see:" -ForegroundColor Yellow
            Write-Host "  - README.md (complete documentation)" -ForegroundColor Cyan
            Write-Host "  - EXAMPLES.ps1 (50+ practical examples)" -ForegroundColor Cyan
            Write-Host ""
            
            Read-Host "Press ENTER to return to menu"
            return "menu"
        }
        
        "Q" {
            Write-Host "`nExiting..." -ForegroundColor Yellow
            return "exit"
        }
        
        default {
            Write-Host "`nInvalid choice" -ForegroundColor Red
            Read-Host "Press ENTER to return to menu"
            return "menu"
        }
    }
}

# ===================== MAIN ======================

try {
    # Check prerequisites (unless running in WhatIf mode)
    if (-not $WhatIfPreference) {
        if (-not (Test-Prerequisites)) {
            exit 1
        }
    }
    
    # If Mode=menu or script run without parameters → show interactive menu
    if ($Mode -eq "menu") {
        do {
            $menuResult = Show-InteractiveMenu
            
            if ($menuResult -eq "exit") {
                exit 0
            }
            elseif ($menuResult -eq "menu") {
                continue
            }
            else {
                # Menu returned parameters -> execute
                $Mode = $menuResult.Mode
                if ($menuResult.ContainsKey('PcapPath')) { $PcapPath = $menuResult.PcapPath }
                if ($menuResult.ContainsKey('Interface')) { $Interface = $menuResult.Interface }
                if ($menuResult.ContainsKey('CaptureSeconds')) { $CaptureSeconds = $menuResult.CaptureSeconds }
                if ($menuResult.ContainsKey('GameName')) { $GameName = $menuResult.GameName }
                if ($menuResult.ContainsKey('ComparePattern')) { $ComparePattern = $menuResult.ComparePattern }
                if ($menuResult.ContainsKey('FightStartSec')) { $FightStartSec = $menuResult.FightStartSec }
                if ($menuResult.ContainsKey('FightEndSec')) { $FightEndSec = $menuResult.FightEndSec }
                if ($menuResult.ContainsKey('EnableDiagnostics')) { $EnableDiagnostics = $true }
                if ($menuResult.ContainsKey('TestBufferbloat')) { $TestBufferbloat = $true }
                break
            }
        } while ($true)
    }
    
    Write-Host "`n╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Game Network Analyzer v$Global:ScriptVersion            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    # Parameter validation
    if ($Mode -eq "pcap") {
        if (-not $PcapPath) {
            throw "For Mode=pcap you must specify -PcapPath"
        }
        if (-not (Test-Path $PcapPath)) {
            throw "PCAP file not found: $PcapPath"
        }
    }
    elseif ($Mode -eq "live") {
        if (-not $Interface) {
            throw "For Mode=live you must specify -Interface (e.g., 'Ethernet')"
        }
    }
    elseif ($Mode -eq "compare") {
        if (-not $ComparePattern) {
            throw "For Mode=compare you must specify -ComparePattern (e.g., '*.json' or 'reports\Fortnite_*.json')"
        }
    }

    # Verifica tshark
    $null = Get-TsharkPath

    # Determina output directory con struttura organizzata
    if ($Mode -eq "pcap") {
        $OutputDir = Get-OutputDirectory -AnalysisType "pcap" -GameName $GameName -CustomOutputDir $OutputDir
    }
    elseif ($Mode -eq "live") {
        $OutputDir = Get-OutputDirectory -AnalysisType "live" -GameName $GameName -CustomOutputDir $OutputDir
    }
    elseif ($Mode -eq "compare") {
        if (-not $OutputDir) {
            $OutputDir = Get-OutputDirectory -AnalysisType "compare"
        }
    }

    # Check/create output dir
    if (-not (Test-Path $OutputDir)) {
        Write-Verbose "Creating output directory: $OutputDir"
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    # Execution
    if ($Mode -eq "compare") {
        # For compare, search in entire game_net_reports structure if not absolute path specified
        if (-not [System.IO.Path]::IsPathRooted($ComparePattern)) {
            $scriptDir = Split-Path -Parent $PSCommandPath
            $reportsBase = Join-Path $scriptDir "game_net_reports"
            if (Test-Path $reportsBase) {
                $ComparePattern = Join-Path $reportsBase "pcap_analysis\**\$ComparePattern"
            }
        }
        
        if (-not $CompareOutHtml) {
            $CompareOutHtml = Join-Path $OutputDir "compare_reports_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        }
        
        Compare-Reports -Pattern $ComparePattern -OutHtml $CompareOutHtml
    }
    elseif ($Mode -eq "live") {
        $tsharkExe = Get-TsharkPath
        $ts = Get-Date -Format "yyyyMMdd_HHmmss"
        $capPath = Join-Path (Resolve-Path $OutputDir).Path "capture_$ts.pcapng"

        Write-Host ">> Live capture on interface '$Interface' for $CaptureSeconds seconds..." -ForegroundColor Cyan
        Write-Host "   Output PCAP: $capPath" -ForegroundColor Yellow
        
        $capArgs = @(
            "-i", $Interface,
            "-w", $capPath,
            "-f", "udp or quic",
            "-a", "duration:$CaptureSeconds"
        )
        
        if ($PSCmdlet.ShouldProcess($Interface, "Live capture for $CaptureSeconds seconds")) {
            & $tsharkExe @capArgs
            
            if ($LASTEXITCODE -ne 0) {
                throw "Error during live capture (exit code: $LASTEXITCODE)"
            }
            
            Write-Host ">> Capture completed." -ForegroundColor Green
            
            # HUD mode if requested
            if ($HudMode) {
                Show-LiveHUD -PcapFile $capPath -LocalIP (Get-LocalIPv4 | Select-Object -First 1) -RefreshSeconds 2
            }
            
            Analyze-Pcap -PcapToAnalyze $capPath -GameName $GameName -Filter $CustomFilter -RunDiagnostics $EnableDiagnostics -AnalyzeQUIC $AnalyzeQUIC -FightStartSec $FightStartSec -FightEndSec $FightEndSec -TestBufferbloat $TestBufferbloat
        }
    }
    else {
        Analyze-Pcap -PcapToAnalyze $PcapPath -GameName $GameName -Filter $CustomFilter -RunDiagnostics $EnableDiagnostics -AnalyzeQUIC $AnalyzeQUIC -FightStartSec $FightStartSec -FightEndSec $FightEndSec -TestBufferbloat $TestBufferbloat
    }
    
    Write-Host "`n✅ Analysis completed successfully!" -ForegroundColor Green
}
catch {
    Write-Host "`n❌ ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 1
}
