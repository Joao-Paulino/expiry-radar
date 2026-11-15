# Verificar se é Administrador / Check if Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[PT] Por favor, corre este script como Administrador." -ForegroundColor Red
    Write-Host "[EN] Please run this script as Administrator." -ForegroundColor Red
    exit
}

$VERSION = "v0.7.0"
$REPO = "Joao-Paulino/expiry-radar"
$BASE_URL = "https://github.com/$REPO/releases/download/$VERSION"
$DEFAULT_COL_DIR = "C:\ExpiryRadar\collector"
$DEFAULT_AGENT_DIR = "C:\ExpiryRadar\agent"

Write-Host "=== Instalador Expiry Radar / Expiry Radar Installer (Windows) ===" -ForegroundColor Green
Write-Host "1) Instalar Collector / Install Collector"
Write-Host "2) Instalar Agent / Install Agent"
Write-Host "3) Instalar Ambos / Install Both"
$OPTION = Read-Host "Escolha uma opção / Choose an option [1-3]"

# --- FUNÇÕES AUXILIARES ---

function Check-And-Clean-Install {
    param([string]$Dir, [string]$ServiceName, [string]$Name)
    
    if ((Test-Path $Dir) -or (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Host "[PT] Aviso: Já existe uma instalação do $Name em $Dir ou serviço $ServiceName." -ForegroundColor Red
        Write-Host "[EN] Warning: An installation of $Name already exists in $Dir or service $ServiceName." -ForegroundColor Red
        $confirm = Read-Host "[PT] Remover instalação existente e continuar? (s/n) / [EN] Remove existing install and continue? (y/n)"
        if ($confirm -match "^[sSyY]$") {
            if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
                Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
                # Tenta correr o uninstall-service do próprio binário, se existir
                $svcExe = Get-ChildItem -Path $Dir -Filter "*.exe" | Select-Object -First 1
                if ($svcExe) { & $svcExe.FullName uninstall-service }
            }
            Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[PT] Instalação antiga removida." -ForegroundColor Green
            Write-Host "[EN] Old installation removed." -ForegroundColor Green
        } else {
            Write-Host "[PT] Instalação cancelada." -ForegroundColor Red
            Write-Host "[EN] Installation cancelled." -ForegroundColor Red
            exit
        }
    }
}

function Download-Binary {
    param([string]$BinName, [string]$DestDir)
    $destFile = "$DestDir\$BinName.exe"
    $url = "$BASE_URL/$BinName-$VERSION-windows-amd64.exe"
    
    Write-Host "[PT] A descarregar de: $url" -ForegroundColor Yellow
    Write-Host "[EN] Downloading from: $url" -ForegroundColor Yellow
    
    if (Test-Path $destFile) { Remove-Item $destFile -Force }
    
    try {
        Invoke-WebRequest -Uri $url -OutFile $destFile -UseBasicParsing
        if (-not (Test-Path $destFile)) { throw "Ficheiro não criado" }
        Write-Host "[PT] Download verificado: $destFile" -ForegroundColor Green
        Write-Host "[EN] Download verified: $destFile" -ForegroundColor Green
    } catch {
        Write-Host "[PT] Erro: Falha ao descarregar o binário." -ForegroundColor Red
        Write-Host "[EN] Error: Failed to download binary." -ForegroundColor Red
        exit
    }
    return $destFile
}

function Generate-Certs {
    param([string]$Dir)
    Write-Host "[PT] A gerar certificados e tokens..." -ForegroundColor Yellow
    Write-Host "[EN] Generating certificates and tokens..." -ForegroundColor Yellow
    
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -ne '127.0.0.1'} | Select-Object -First 1).IPAddress
    $openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
    
    if (-Not (Test-Path $openssl)) {
        Write-Host "[PT] Erro: OpenSSL não encontrado. Instala o Git para Windows." -ForegroundColor Red
        Write-Host "[EN] Error: OpenSSL not found. Install Git for Windows." -ForegroundColor Red
        exit
    }

    & $openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 365 -nodes -keyout "$Dir\collector.key" -out "$Dir\collector.crt" -subj "/CN=expiry-radar" -addext "subjectAltName=IP:$ip" 2>$null
    
    $global:TOKEN_AGENT = (& $openssl rand -hex 32).Trim()
    $global:TOKEN_ADMIN = (& $openssl rand -hex 32).Trim()
    
    Write-Host "[PT] IP detetado: $ip" -ForegroundColor Green
    Write-Host "[EN] Detected IP: $ip" -ForegroundColor Green
}

function Define-AdminPassword {
    param([string]$Bin, [string]$Json)
    
    Write-Host "[PT] A password de administrador tem de ter no mínimo 12 caracteres." -ForegroundColor Yellow
    Write-Host "[EN] The administrator password must be at least 12 characters." -ForegroundColor Yellow
    Write-Host "[PT] O binário vai pedir a password duas vezes (confirmação). Ctrl+C para sair." -ForegroundColor Yellow
    Write-Host "[EN] The binary will ask for the password twice (confirmation). Ctrl+C to exit." -ForegroundColor Yellow
    Write-Host ""
    
    while ($true) {
        & $Bin set-admin-password $Json
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[PT] Password definida com sucesso." -ForegroundColor Green
            Write-Host "[EN] Password set successfully." -ForegroundColor Green
            break
        } else {
            Write-Host "[PT] A password não cumpre os requisitos (mínimo 12 caracteres). Tenta novamente." -ForegroundColor Red
            Write-Host "[EN] Password does not meet requirements (min 12 characters). Try again." -ForegroundColor Red
            Write-Host ""
        }
    }
}

# --- INSTALAR COLLECTOR ---
if ($OPTION -eq "1" -or $OPTION -eq "3") {
    $COL_DIR = Read-Host "[PT] Pasta do Collector [Enter para $DEFAULT_COL_DIR] / [EN] Collector directory [Enter for $DEFAULT_COL_DIR]"
    if ([string]::IsNullOrWhiteSpace($COL_DIR)) { $COL_DIR = $DEFAULT_COL_DIR }
    
    Check-And-Clean-Install -Dir $COL_DIR -ServiceName "ExpiryRadarCollector" -Name "Collector"
    New-Item -ItemType Directory -Path $COL_DIR -Force | Out-Null

    Generate-Certs -Dir $COL_DIR
    $COL_BIN = Download-Binary -BinName "expiry-radar-collector" -DestDir $COL_DIR
    
    $colDirJson = $COL_DIR -replace '\\', '\\\\'

    $json = @"
{
  "listen_addr": "0.0.0.0:8443",
  "db_path": "$colDirJson\\radar.db",
  "tls_cert_file": "$colDirJson\\collector.crt",
  "tls_key_file": "$colDirJson\\collector.key",
  "auth_tokens": ["$global:TOKEN_AGENT"],
  "admin_tokens": ["$global:TOKEN_ADMIN"],
  "alert_interval_seconds": 3000,
  "theme": "dark"
}
"@
    $json | Out-File "$COL_DIR\collector.json" -Encoding utf8

    Define-AdminPassword -Bin $COL_BIN -Json "$COL_DIR\collector.json"
    
    Write-Host "[PT] A definir TOTP do admin..." -ForegroundColor Yellow
    Write-Host "[EN] Setting admin TOTP..." -ForegroundColor Yellow
    & $COL_BIN set-admin-totp "$COL_DIR\collector.json"

    Set-Location $COL_DIR
    .\expiry-radar-collector.exe install-service collector.json
    icacls $COL_DIR /grant "NT AUTHORITY\LocalService:(OI)(CI)M" | Out-Null
    Start-Service ExpiryRadarCollector
    New-NetFirewallRule -DisplayName "Expiry Radar 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "[PT] Collector instalado e a correr em $COL_DIR" -ForegroundColor Green
    Write-Host "[EN] Collector installed and running in $COL_DIR" -ForegroundColor Green
}

# --- INSTALAR AGENT ---
if ($OPTION -eq "2" -or $OPTION -eq "3") {
    $AGENT_DIR = Read-Host "[PT] Pasta do Agent [Enter para $DEFAULT_AGENT_DIR] / [EN] Agent directory [Enter for $DEFAULT_AGENT_DIR]"
    if ([string]::IsNullOrWhiteSpace($AGENT_DIR)) { $AGENT_DIR = $DEFAULT_AGENT_DIR }
    
    Check-And-Clean-Install -Dir $AGENT_DIR -ServiceName "ExpiryRadarAgent" -Name "Agent"
    New-Item -ItemType Directory -Path $AGENT_DIR -Force | Out-Null

    $AGENT_BIN = Download-Binary -BinName "expiry-radar-agent" -DestDir $AGENT_DIR

    # DETEÇÃO AUTOMÁTICA
    $CHECK_COL_DIR = if ($COL_DIR) { $COL_DIR } else { $DEFAULT_COL_DIR }
    
    if ((Test-Path "$CHECK_COL_DIR\collector.json") -and (Test-Path "$CHECK_COL_DIR\collector.crt")) {
        Write-Host "[PT] Deteção automática: O Collector está na mesma máquina!" -ForegroundColor Green
        Write-Host "[EN] Auto-detection: Collector is on the same machine!" -ForegroundColor Green
        Write-Host "[PT] A copiar certificado e reutilizar token..." -ForegroundColor Yellow
        Write-Host "[EN] Copying certificate and reusing token..." -ForegroundColor Yellow
        
        Copy-Item -Path "$CHECK_COL_DIR\collector.crt" -Destination "$AGENT_DIR\collector.crt" -Force
        
        # Extrai o token do JSON do collector
        $colJson = Get-Content "$CHECK_COL_DIR\collector.json" | ConvertFrom-Json
        $AGENT_TOKEN = $colJson.auth_tokens[0]
        
        if (-not $AGENT_TOKEN) {
            Write-Host "[PT] Erro: Não foi possível ler o token do collector.json." -ForegroundColor Red
            Write-Host "[EN] Error: Could not read token from collector.json." -ForegroundColor Red
            exit
        }

        $COL_CRT = "$AGENT_DIR\collector.crt"
        $AGENT_ID = "win-agent-$env:COMPUTERNAME"
        $COL_IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -ne '127.0.0.1'} | Select-Object -First 1).IPAddress
    } else {
        Write-Host "[PT] O Collector não foi encontrado localmente. Assume-se máquina remota." -ForegroundColor Yellow
        Write-Host "[EN] Collector not found locally. Assuming remote machine." -ForegroundColor Yellow
        
        $COL_IP = Read-Host "[PT] IP do Collector / [EN] Collector IP"
        $AGENT_TOKEN = Read-Host "[PT] Token do Agente (auth_token) / [EN] Agent Token"
        $COL_CRT = Read-Host "[PT] Caminho do certificado do Collector / [EN] Collector certificate path"
        $AGENT_ID = Read-Host "[PT] ID do Agente / [EN] Agent ID"
    }

    $agentDirJson = $AGENT_DIR -replace '\\', '\\\\'
    $caPathJson = $COL_CRT -replace '\\', '\\\\'

    $agentJson = @"
{
  "collector_url": "https://$COL_IP`:8443",
  "collector_ca_file": "$caPathJson",
  "token": "$AGENT_TOKEN",
  "agent_id": "$AGENT_ID",
  "queue_path": "$agentDirJson\\queue.jsonl",
  "interval_seconds": 300,
  "tls_targets": [
    { "host": "www.google.com", "port": 443 },
    { "host": "github.com", "port": 443 },
    { "host": "linkedin.com", "port": 443 },
    { "host": "azure.microsoft.com", "port": 443 },
    { "host": "aws.amazon.com", "port": 443 },
    { "host": "cloud.google.com", "port": 443 },
    { "host": "vmware.com", "port": 443 }
  ]
}
"@
    $agentJson | Out-File "$AGENT_DIR\agent.json" -Encoding utf8

    Set-Location $AGENT_DIR
    .\expiry-radar-agent.exe install-service agent.json
    icacls $AGENT_DIR /grant "NT AUTHORITY\LocalService:(OI)(CI)RX" | Out-Null
    Start-Service ExpiryRadarAgent
    
    Write-Host "[PT] Agent instalado e a correr em $AGENT_DIR" -ForegroundColor Green
    Write-Host "[EN] Agent installed and running in $AGENT_DIR" -ForegroundColor Green
}
