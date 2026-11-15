# Verificar se é Administrador / Check if Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[PT] Por favor, corre este script como Administrador." -ForegroundColor Red
    Write-Host "[EN] Please run this script as Administrator." -ForegroundColor Red
    exit
}

$VERSION = "v0.8.0"
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
            if (Test-Path $Dir) {
                # Nunca apagar: a base de dados e a config ficam numa cópia / Never delete: database and config are kept in a backup
                $backup = "$Dir.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
                Move-Item -Path $Dir -Destination $backup
                Write-Host "[PT] Instalação antiga guardada em $backup" -ForegroundColor Green
                Write-Host "[EN] Old installation kept in $backup" -ForegroundColor Green
            }
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
        # Verificar a soma SHA-256 publicada no release / Verify against the release's SHA256SUMS
        # O GitHub serve o SHA256SUMS como octet-stream: .Content vem em bytes / GitHub serves it as octet-stream: .Content is bytes
        $sumsFile = "$DestDir\SHA256SUMS"
        Invoke-WebRequest -Uri "$BASE_URL/SHA256SUMS" -OutFile $sumsFile -UseBasicParsing
        $sums = [System.IO.File]::ReadAllText($sumsFile)
        $expected = ($sums -split "`n" | Where-Object { $_ -match "\s\*?$BinName-$VERSION-windows-amd64\.exe\s*$" }) -replace '\s.*$', ''
        $actual = (Get-FileHash -Algorithm SHA256 $destFile).Hash.ToLower()
        if (-not $expected -or $expected.ToLower() -ne $actual) {
            Remove-Item $destFile -Force
            throw "SHA-256 mismatch"
        }
        Write-Host "[PT] Download verificado (SHA-256): $destFile" -ForegroundColor Green
        Write-Host "[EN] Download verified (SHA-256): $destFile" -ForegroundColor Green
    } catch {
        Write-Host "[PT] Erro: Falha ao descarregar ou verificar o binário: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[EN] Error: Failed to download or verify the binary: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    return $destFile
}

function New-Token {
    # 32 bytes aleatórios em hex / 32 random bytes as hex
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Write-Utf8NoBom {
    # Out-File -Encoding utf8 escreve BOM no Windows PowerShell 5.1 e o JSON deixa de ser lido / Out-File writes a BOM on PowerShell 5.1, which breaks JSON parsing
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding $false))
}

function Generate-Certs {
    param([string]$Dir, [string]$Bin)
    Write-Host "[PT] A gerar certificado TLS e tokens..." -ForegroundColor Yellow
    Write-Host "[EN] Generating TLS certificate and tokens..." -ForegroundColor Yellow

    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { ($_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'Manual') -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
    $answer = Read-Host "[PT] IP/nome que os agentes usam [Enter para $ip] / [EN] IP/name agents will use [Enter for $ip]"
    if (-not [string]::IsNullOrWhiteSpace($answer)) { $ip = $answer.Trim() }

    # O próprio collector gera o certificado / The collector generates the certificate itself
    & $Bin gen-cert $Dir --host $ip
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[PT] Erro ao gerar o certificado." -ForegroundColor Red
        Write-Host "[EN] Error generating the certificate." -ForegroundColor Red
        exit 1
    }

    $global:TOKEN_AGENT = New-Token
    $global:TOKEN_ADMIN = New-Token
    $global:COL_HOST = $ip

    Write-Host "[PT] Certificado emitido para: $ip" -ForegroundColor Green
    Write-Host "[EN] Certificate issued for: $ip" -ForegroundColor Green
}

function Define-AdminPassword {
    param([string]$Bin, [string]$Json)
    
    Write-Host "[PT] Password de administrador: mínimo 12 caracteres, pedida duas vezes, não aparece no ecrã." -ForegroundColor Yellow
    Write-Host "[EN] Administrator password: at least 12 characters, asked twice, not shown on screen." -ForegroundColor Yellow
    Write-Host ""

    for ($try = 1; $try -le 5; $try++) {
        & $Bin set-admin-password $Json
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[PT] Password definida com sucesso." -ForegroundColor Green
            Write-Host "[EN] Password set successfully." -ForegroundColor Green
            return
        }
        # O binário já explicou o erro acima / The binary printed the reason above
        $again = Read-Host "[PT] Tentar de novo? (s/n) / [EN] Try again? (y/n)"
        if ($again -notmatch "^[sSyY]$") { break }
    }
    Write-Host "[PT] Password não definida. Podes defini-la depois com: $Bin set-admin-password $Json" -ForegroundColor Red
    Write-Host "[EN] Password not set. You can set it later with: $Bin set-admin-password $Json" -ForegroundColor Red
    exit 1
}

# --- INSTALAR COLLECTOR ---
if ($OPTION -eq "1" -or $OPTION -eq "3") {
    $COL_DIR = Read-Host "[PT] Pasta do Collector [Enter para $DEFAULT_COL_DIR] / [EN] Collector directory [Enter for $DEFAULT_COL_DIR]"
    if ([string]::IsNullOrWhiteSpace($COL_DIR)) { $COL_DIR = $DEFAULT_COL_DIR }
    
    Check-And-Clean-Install -Dir $COL_DIR -ServiceName "ExpiryRadarCollector" -Name "Collector"
    New-Item -ItemType Directory -Path $COL_DIR -Force | Out-Null

    $COL_BIN = Download-Binary -BinName "expiry-radar-collector" -DestDir $COL_DIR
    Generate-Certs -Dir $COL_DIR -Bin $COL_BIN
    
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
    Write-Utf8NoBom -Path "$COL_DIR\collector.json" -Content $json

    Define-AdminPassword -Bin $COL_BIN -Json "$COL_DIR\collector.json"
    
    Write-Host "[PT] A definir TOTP do admin..." -ForegroundColor Yellow
    Write-Host "[EN] Setting admin TOTP..." -ForegroundColor Yellow
    & $COL_BIN set-admin-totp "$COL_DIR\collector.json"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[PT] TOTP não configurado. Podes fazê-lo depois com: $COL_BIN set-admin-totp $COL_DIR\collector.json" -ForegroundColor Red
        Write-Host "[EN] TOTP not configured. You can do it later with: $COL_BIN set-admin-totp $COL_DIR\collector.json" -ForegroundColor Red
        exit 1
    }

    Set-Location $COL_DIR
    .\expiry-radar-collector.exe install-service collector.json
    icacls $COL_DIR /grant "NT AUTHORITY\LocalService:(OI)(CI)M" | Out-Null
    # Chave privada e config com tokens: só Administradores e o serviço / Private key and config with tokens: Administrators and the service only
    foreach ($f in "collector.key", "collector.json") {
        icacls "$COL_DIR\$f" /inheritance:r /grant "NT AUTHORITY\LocalService:R" /grant "BUILTIN\Administrators:F" | Out-Null
    }
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
        $COL_IP = if ($global:COL_HOST) { $global:COL_HOST } else { "localhost" }
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
  "local": { "windows_cert_stores": ["My", "WebHosting"] },
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
    Write-Utf8NoBom -Path "$AGENT_DIR\agent.json" -Content $agentJson

    Set-Location $AGENT_DIR
    .\expiry-radar-agent.exe install-service agent.json
    icacls $AGENT_DIR /grant "NT AUTHORITY\LocalService:(OI)(CI)M" | Out-Null
    icacls "$AGENT_DIR\agent.json" /inheritance:r /grant "NT AUTHORITY\LocalService:R" /grant "BUILTIN\Administrators:F" | Out-Null
    Start-Service ExpiryRadarAgent
    
    Write-Host "[PT] Agent instalado e a correr em $AGENT_DIR" -ForegroundColor Green
    Write-Host "[EN] Agent installed and running in $AGENT_DIR" -ForegroundColor Green
}
