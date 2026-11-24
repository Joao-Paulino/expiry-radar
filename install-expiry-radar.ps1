# Verificar se é Administrador / Check if Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[PT] Por favor, corre este script como Administrador." -ForegroundColor Red
    Write-Host "[EN] Please run this script as Administrator." -ForegroundColor Red
    exit
}

$VERSION = "v1.3.0"
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
    Write-Host "[PT] Certificado do Collector: / [EN] Collector certificate:"
    Write-Host "  1) Self-signed (rapido, laboratorio / quick, lab)"
    Write-Host "  2) CA interna propria (sem dominio publico / no public domain)"
    Write-Host "  3) Let's Encrypt via DNS-01 (dominio publico, sem precisar da porta 80 / public domain, no port 80 needed)"
    $certChoice = Read-Host "[1-3, Enter=2]"
    if ([string]::IsNullOrWhiteSpace($certChoice)) { $certChoice = "2" }

    if ($certChoice -eq "3") {
        Dns01-Setup -Dir $Dir
        $global:TOKEN_ADMIN = New-Token
        Write-Host "[PT] Certificado emitido para: $($global:COL_HOST)" -ForegroundColor Green
        Write-Host "[EN] Certificate issued for: $($global:COL_HOST)" -ForegroundColor Green
        return
    }

    $global:CERT_MODE = "selfsigned" # default; Dns01-Setup overrides to "acme"
    Write-Host "[PT] A gerar certificado TLS e tokens..." -ForegroundColor Yellow
    Write-Host "[EN] Generating TLS certificate and tokens..." -ForegroundColor Yellow

    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { ($_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'Manual') -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
    $answer = Read-Host "[PT] IP/nome que os agentes usam [Enter para $ip] / [EN] IP/name agents will use [Enter for $ip]"
    if (-not [string]::IsNullOrWhiteSpace($answer)) { $ip = $answer.Trim() }

    # O próprio collector gera o certificado / The collector generates the certificate itself
    if ($certChoice -eq "1") {
        & $Bin gen-cert $Dir --host $ip
    } else {
        & $Bin gen-cert $Dir --host $ip --ca "$Dir\ca"
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[PT] Erro ao gerar o certificado." -ForegroundColor Red
        Write-Host "[EN] Error generating the certificate." -ForegroundColor Red
        exit 1
    }

    $global:TOKEN_ADMIN = New-Token
    $global:COL_HOST = $ip

    Write-Host "[PT] Certificado emitido para: $ip" -ForegroundColor Green
    Write-Host "[EN] Certificate issued for: $ip" -ForegroundColor Green
}

# Dns01-Setup <collector-dir>: issues a publicly-trusted certificate via
# certbot's DNS-01 challenge (no inbound port 80/443 needed during
# validation). Never installs certbot or any plugin itself — only checks
# for them. Certbot's default layout on Windows isn't reliably documented
# (Windows support is still beta upstream), so unlike the Linux installer
# this never guesses a live-certificate path: it always asks the operator
# where certbot put fullchain.pem/privkey.pem once it's done, for every
# provider. Writes collector.crt/collector.key like every other option;
# never called when $CERT_MODE stays "selfsigned".
function Dns01-Setup {
    param([string]$Dir)

    $domain = Read-Host "[PT] Dominio publico do Collector (ex: collector.example.com) / [EN] Collector's public domain"
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Host "[PT] Dominio e obrigatorio. / [EN] Domain is required." -ForegroundColor Red
        exit 1
    }
    $leEmail = Read-Host "[PT] Email de contacto (para o Let's Encrypt/ACME) / [EN] Contact email (for Let's Encrypt/ACME)"
    if ([string]::IsNullOrWhiteSpace($leEmail)) {
        Write-Host "[PT] Email e obrigatorio. / [EN] Email is required." -ForegroundColor Red
        exit 1
    }

    Write-Host "[PT] Fornecedor de DNS: / [EN] DNS provider:"
    Write-Host "  1) Cloudflare"
    Write-Host "  2) Route53 (AWS)"
    Write-Host "  3) Google Cloud DNS"
    Write-Host "  4) DigitalOcean"
    Write-Host "  5) Azure DNS (plugin de terceiros / third-party plugin)"
    Write-Host "  6) GoDaddy (plugin de terceiros / third-party plugin)"
    Write-Host "  7) Outro / Other"
    $dnsProvider = Read-Host "[1-7]"

    if (-not (Get-Command certbot -ErrorAction SilentlyContinue)) {
        Write-Host "[PT] certbot nao esta instalado. Instala-o e volta a correr este instalador." -ForegroundColor Red
        Write-Host "[EN] certbot is not installed. Install it and re-run this installer." -ForegroundColor Red
        exit 1
    }
    $pluginsText = & certbot plugins --text 2>$null

    $certbotArgs = @("certonly", "--non-interactive", "--agree-tos", "-m", $leEmail, "-d", $domain)
    $runCertbot = $true

    switch ($dnsProvider) {
        "1" { # Cloudflare — official plugin
            if ($pluginsText -notmatch "(?i)dns-cloudflare") {
                Write-Host "[PT] Falta o plugin certbot-dns-cloudflare. Instala-o e volta a correr." -ForegroundColor Red
                Write-Host "[EN] Missing the certbot-dns-cloudflare plugin. Install it and re-run." -ForegroundColor Red
                exit 1
            }
            $cfToken = Read-Host "[PT] Cloudflare API token (com permissao DNS:Edit na zona) / [EN] Cloudflare API token (DNS:Edit on the zone)" -AsSecureString
            $credDir = "$Dir\dns01-credentials"
            New-Item -ItemType Directory -Path $credDir -Force | Out-Null
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cfToken))
            Write-Utf8NoBom -Path "$credDir\cloudflare.ini" -Content "dns_cloudflare_api_token = $plain`n"
            $certbotArgs += @("--dns-cloudflare", "--dns-cloudflare-credentials", "$credDir\cloudflare.ini")
        }
        "2" { # Route53 — official plugin, no credentials file: AWS's own chain
            if ($pluginsText -notmatch "(?i)dns-route53") {
                Write-Host "[PT] Falta o plugin certbot-dns-route53. Instala-o e volta a correr." -ForegroundColor Red
                Write-Host "[EN] Missing the certbot-dns-route53 plugin. Install it and re-run." -ForegroundColor Red
                exit 1
            }
            $awsId = Read-Host "[PT] AWS Access Key ID / [EN] AWS Access Key ID"
            $awsSecretSecure = Read-Host "[PT] AWS Secret Access Key / [EN] AWS Secret Access Key" -AsSecureString
            $awsSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($awsSecretSecure))
            $env:AWS_ACCESS_KEY_ID = $awsId
            $env:AWS_SECRET_ACCESS_KEY = $awsSecret
            Write-Host "[PT] Para as renovacoes automaticas (certbot renew) tambem funcionarem, estas credenciais tem de ficar acessiveis depois (ex: variaveis de ambiente do sistema). Esta emissao agora so as usa nesta chamada." -ForegroundColor Yellow
            Write-Host "[EN] For automatic renewals (certbot renew) to keep working, these credentials must stay available afterwards (e.g. system environment variables). This issuance only uses them for this one call." -ForegroundColor Yellow
            $certbotArgs += "--dns-route53"
        }
        "3" { # Google Cloud DNS — official plugin, existing service-account JSON
            if ($pluginsText -notmatch "(?i)dns-google") {
                Write-Host "[PT] Falta o plugin certbot-dns-google. Instala-o e volta a correr." -ForegroundColor Red
                Write-Host "[EN] Missing the certbot-dns-google plugin. Install it and re-run." -ForegroundColor Red
                exit 1
            }
            $gcpJson = Read-Host "[PT] Caminho da chave JSON da service account (com permissao dns.admin) / [EN] Path to the service account JSON key (dns.admin permission)"
            if (-not (Test-Path $gcpJson)) {
                Write-Host "[PT] Ficheiro nao encontrado: $gcpJson / [EN] File not found: $gcpJson" -ForegroundColor Red
                exit 1
            }
            $certbotArgs += @("--dns-google", "--dns-google-credentials", $gcpJson)
        }
        "4" { # DigitalOcean — official plugin
            if ($pluginsText -notmatch "(?i)dns-digitalocean") {
                Write-Host "[PT] Falta o plugin certbot-dns-digitalocean. Instala-o e volta a correr." -ForegroundColor Red
                Write-Host "[EN] Missing the certbot-dns-digitalocean plugin. Install it and re-run." -ForegroundColor Red
                exit 1
            }
            $doTokenSecure = Read-Host "[PT] DigitalOcean API token / [EN] DigitalOcean API token" -AsSecureString
            $doToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($doTokenSecure))
            $credDir = "$Dir\dns01-credentials"
            New-Item -ItemType Directory -Path $credDir -Force | Out-Null
            Write-Utf8NoBom -Path "$credDir\digitalocean.ini" -Content "dns_digitalocean_token = $doToken`n"
            $certbotArgs += @("--dns-digitalocean", "--dns-digitalocean-credentials", "$credDir\digitalocean.ini")
        }
        { $_ -in "5", "6", "7" } { # Azure/GoDaddy (third-party) / other: run certbot yourself, we just pick up the result
            $name = "outro fornecedor / other provider"
            if ($dnsProvider -eq "5") { $name = "Azure DNS (certbot-dns-azure, https://docs.certbot-dns-azure.co.uk/)" }
            if ($dnsProvider -eq "6") { $name = "GoDaddy (certbot-dns-godaddy, procura no PyPI / search PyPI)" }
            Write-Host "[PT] $name nao tem um comando automatico aqui (plugin de terceiros, ou sem suporte direto). Instala o plugin certo e corre tu mesmo, por exemplo:" -ForegroundColor Yellow
            Write-Host "  certbot certonly --agree-tos -m $leEmail -a <nome-do-plugin> -d $domain"
            Write-Host "[EN] $name has no automatic command here (third-party plugin, or not directly supported). Install the right plugin and run it yourself, for example:" -ForegroundColor Yellow
            Write-Host "  certbot certonly --agree-tos -m $leEmail -a <plugin-name> -d $domain"
            Read-Host "[PT] Prime Enter quando o certificado estiver emitido para $domain / [EN] Press Enter once the certificate is issued for $domain" | Out-Null
            $runCertbot = $false
        }
        default {
            Write-Host "[PT] Opcao invalida / [EN] Invalid option" -ForegroundColor Red
            exit 1
        }
    }

    if ($runCertbot) {
        & certbot @certbotArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[PT] certbot falhou. / [EN] certbot failed." -ForegroundColor Red
            exit 1
        }
    }

    # O layout do certbot no Windows nao esta fiavelmente documentado (suporte
    # ainda beta a montante), por isso pergunta-se sempre ao operador em vez
    # de assumir um caminho (ex: C:\Certbot\live\<dominio>).
    # Certbot's layout on Windows isn't reliably documented (upstream support
    # is still beta), so we always ask the operator instead of guessing a
    # path (e.g. C:\Certbot\live\<domain>).
    Write-Host "[PT] O certbot emitiu o certificado. Indica onde ficaram os ficheiros (normalmente debaixo de <config-dir-do-certbot>\live\$domain)." -ForegroundColor Yellow
    Write-Host "[EN] certbot issued the certificate. Tell us where the files landed (usually under <certbot-config-dir>\live\$domain)." -ForegroundColor Yellow
    $fullchainPath = Read-Host "[PT] Caminho completo de fullchain.pem / [EN] Full path to fullchain.pem"
    $privkeyPath = Read-Host "[PT] Caminho completo de privkey.pem / [EN] Full path to privkey.pem"
    if (-not (Test-Path $fullchainPath) -or -not (Test-Path $privkeyPath)) {
        Write-Host "[PT] Um dos ficheiros nao foi encontrado. / [EN] One of the files was not found." -ForegroundColor Red
        exit 1
    }
    Copy-Item -Path $fullchainPath -Destination "$Dir\collector.crt" -Force
    Copy-Item -Path $privkeyPath -Destination "$Dir\collector.key" -Force

    Write-Host "[PT] Para as renovacoes (certbot renew), copia de novo estes dois ficheiros para $Dir depois de cada renovacao (ex: com --deploy-hook ou uma Tarefa Agendada). O collector deteta a mudanca e recarrega sem reiniciar." -ForegroundColor Yellow
    Write-Host "[EN] For renewals (certbot renew), copy these two files back into $Dir after each renewal (e.g. via --deploy-hook or a Scheduled Task). The collector notices the change and reloads without restarting." -ForegroundColor Yellow

    $global:CERT_MODE = "acme"
    $global:COL_HOST = $domain
}

function Trust-Cert-For {
    # The file agents must trust: the internal CA's ca.crt when gen-cert
    # created one, otherwise the self-signed leaf. Never called when
    # $CERT_MODE is "acme" — a publicly-trusted certificate needs no trust
    # file distributed to agents at all.
    # O ficheiro em que os agentes devem confiar: ca.crt da CA interna
    # quando o gen-cert criou uma, caso contrário o certificado autoassinado.
    # Nunca chamada quando $CERT_MODE é "acme" — um certificado de confiança
    # pública não precisa de nenhum ficheiro de confiança distribuído aos agentes.
    param([string]$Dir)
    if (Test-Path "$Dir\ca\ca.crt") { return "$Dir\ca\ca.crt" }
    return "$Dir\collector.crt"
}

function Add-Agent {
    # Cria um token só para este agente (collector add-agent) / Creates a token for this agent only
    param([string]$Bin, [string]$Json, [string]$AgentId)
    $out = & $Bin add-agent $Json $AgentId
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[PT] Não foi possível criar o token do agente $AgentId." -ForegroundColor Red
        Write-Host "[EN] Could not create the token for agent $AgentId." -ForegroundColor Red
        exit 1
    }
    $tok = ($out | Where-Object { $_ -match '^\s*[0-9a-f]{64}\s*$' } | Select-Object -First 1)
    return [pscustomobject]@{ Id = $AgentId; Token = $tok.Trim() }
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
  "admin_tokens": ["$global:TOKEN_ADMIN"],
  "alert_interval_seconds": 3000,
  "theme": "dark"
}
"@
    Write-Utf8NoBom -Path "$COL_DIR\collector.json" -Content $json

    # Um token por agente: cada um só pode reportar como ele próprio / One token per agent: each may only report as itself
    $defaultId = if ($OPTION -eq "3") { "win-agent-$env:COMPUTERNAME" } else { "agent-01" }
    $firstId = Read-Host "[PT] ID do primeiro agente [Enter para $defaultId] / [EN] First agent ID [Enter for $defaultId]"
    if ([string]::IsNullOrWhiteSpace($firstId)) { $firstId = $defaultId }
    $global:FIRST_AGENT = Add-Agent -Bin $COL_BIN -Json "$COL_DIR\collector.json" -AgentId $firstId.Trim()
    if ($OPTION -eq "1") {
        Write-Host "[PT] Token do agente $($global:FIRST_AGENT.Id) (guarda-o para instalar esse agente): $($global:FIRST_AGENT.Token)" -ForegroundColor Cyan
        Write-Host "[EN] Token for agent $($global:FIRST_AGENT.Id) (keep it to install that agent): $($global:FIRST_AGENT.Token)" -ForegroundColor Cyan
        Write-Host "[PT] Mais agentes: $COL_BIN add-agent $COL_DIR\collector.json <id> e Restart-Service ExpiryRadarCollector" -ForegroundColor Cyan
    }

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

        if ($global:CERT_MODE -eq "acme") {
            # Certificado de confiança pública (Let's Encrypt/DNS-01): nenhum
            # ficheiro de confiança a distribuir ao agente.
            # Publicly-trusted certificate (Let's Encrypt/DNS-01): no trust
            # file to distribute to the agent.
            Write-Host "[PT] O Collector usa um certificado de confianca publica (Let's Encrypt); o agente nao precisa de ficheiro de confianca." -ForegroundColor Yellow
            Write-Host "[EN] The Collector uses a publicly-trusted certificate (Let's Encrypt); the agent needs no trust file." -ForegroundColor Yellow
            $COL_CRT_PAIR = ""
        } else {
            Write-Host "[PT] A copiar o certificado e a usar um token só deste agente..." -ForegroundColor Yellow
            Write-Host "[EN] Copying the certificate and using a token for this agent only..." -ForegroundColor Yellow
            Copy-Item -Path (Trust-Cert-For -Dir $CHECK_COL_DIR) -Destination "$AGENT_DIR\collector.crt" -Force
            $COL_CRT_PAIR = "$AGENT_DIR\collector.crt"
        }

        if ($global:FIRST_AGENT) {
            $AGENT_ID = $global:FIRST_AGENT.Id
            $AGENT_TOKEN = $global:FIRST_AGENT.Token
        } else {
            # Collector já instalado antes: cria um token para este agente e recarrega-o / Collector installed earlier: add a token for this agent and reload it
            $AGENT_ID = "win-agent-$env:COMPUTERNAME"
            $a = Add-Agent -Bin "$CHECK_COL_DIR\expiry-radar-collector.exe" -Json "$CHECK_COL_DIR\collector.json" -AgentId $AGENT_ID
            $AGENT_TOKEN = $a.Token
            icacls "$CHECK_COL_DIR\collector.json" /inheritance:r /grant "NT AUTHORITY\LocalService:R" /grant "BUILTIN\Administrators:F" | Out-Null
            Restart-Service ExpiryRadarCollector -ErrorAction SilentlyContinue
        }

        $COL_CRT = $COL_CRT_PAIR
        $COL_IP = if ($global:COL_HOST) { $global:COL_HOST } else { "localhost" }
    } else {
        Write-Host "[PT] O Collector não foi encontrado localmente. Assume-se máquina remota." -ForegroundColor Yellow
        Write-Host "[EN] Collector not found locally. Assuming remote machine." -ForegroundColor Yellow

        $COL_IP = Read-Host "[PT] IP do Collector / [EN] Collector IP"
        Write-Host "[PT] No collector: <collector.exe> add-agent collector.json <id> dá o token deste agente." -ForegroundColor Yellow
        Write-Host "[EN] On the collector: <collector.exe> add-agent collector.json <id> gives this agent's token." -ForegroundColor Yellow
        $AGENT_TOKEN = Read-Host "[PT] Token do Agente / [EN] Agent Token"
        $COL_CRT = Read-Host "[PT] Caminho do certificado de confianca (collector.crt, ou ca.crt se o collector usa CA interna; deixa em branco se o collector usa um certificado de confianca publica) / [EN] Trust certificate path (collector.crt, or ca.crt if the collector uses an internal CA; leave blank if the collector uses a publicly-trusted certificate)"
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
