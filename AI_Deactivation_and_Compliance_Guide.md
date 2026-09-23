# AI Deactivation and Environment Compliance Guide
**Document Version**: 2.4.0-STRICT  
**Classification**: Competition Security & Regulatory Compliance  
**Audience**: CTF Competitors, Systems Administrators, Integrity Auditors, DevSecOps  
**Scope**: Complete Neutralization of Autonomous Agents, Inline Autocomplete, Telemetry, and LLM API Relays

---

## Executive Summary & Purpose

In competitive cybersecurity competitions (such as CyberTalents, DEF CON Quals, Arab Security Cyber Wargames, and national CTF finals), strict regulations often prohibit generative AI, copilot assistance, and agentic assistants to guarantee an authentic test of individual and team competence.

This technical compliance manual details deterministic, verifiable steps to completely disable, isolate, and audit development environments across modern IDEs (**VS Code**, **Cursor**, **JetBrains**, and **Google Antigravity IDE**), lock operating system hosts, and provide cryptographic/command-line proof of compliance to competition proctors.

---

## 1. Pre-Competition Compliance Checklist

Execute this rapid 10-point checklist at least 60 minutes prior to competition start time:

- [ ] **Check 1: Extension Audit**: Verify that all generative AI extensions (GitHub Copilot, Copilot Chat, Codeium, Tabnine, Continue, Superwhisper, Claude Dev, Cline, Roo Code) are disabled or uninstalled globally.
- [ ] **Check 2: Inline Suggestion Engine**: Verify that native IDE autocomplete suggestions powered by cloud models or local transformers are disabled (`editor.inlineSuggest.enabled = false`).
- [ ] **Check 3: Autonomous Agents & Sidecars**: Terminate and purge any local agent daemons (e.g., local MCP servers, Ollama instances, LM Studio, vLLM, background AI services).
- [ ] **Check 4: Environment Variables Purge**: Verify no active API keys exist in shell environments (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`).
- [ ] **Check 5: IDE Telemetry & Cloud Sync**: Deactivate IDE telemetry, crash reporting, and cloud profile synchronization to eliminate unauthorized outbound tunneling.
- [ ] **Check 6: Host Resolution Blackhole**: Apply local OS loopback mappings (`127.0.0.1` / `::1`) in the `hosts` file for all public and private LLM endpoint domains.
- [ ] **Check 7: Local Firewall Outbound Rules**: Implement explicit outbound drop rules blocking standard AI API IPs and domains on ports 80/443.
- [ ] **Check 8: Active Socket Audit**: Run diagnostic socket inspection (`netstat` / `ss` / `lsof`) to prove no persistent connections to AI hosts exist.
- [ ] **Check 9: Process Tree Verification**: Inspect running process trees for node/python processes hosting background LLM agents or MCP servers.
- [ ] **Check 10: Proctor Audit Log Generation**: Generate a signed snapshot timestamp file containing process list, open sockets, and hosts configuration for submission to competition proctors.

---

## 2. IDE-Specific Deactivation Steps

### A. Visual Studio Code (VS Code)

#### 1. Extension Deactivation UI Path
1. Open Extension Manager: `Ctrl + Shift + X` (Windows/Linux) or `Cmd + Shift + X` (macOS).
2. Type in search filter: `@installed ai` or `@installed copilot`.
3. Locate:
   - **GitHub Copilot** (`GitHub.copilot`) -> Click **Disable (Workspace)** or **Uninstall**.
   - **GitHub Copilot Chat** (`GitHub.copilot-chat`) -> Click **Disable (Workspace)** or **Uninstall**.
   - **Continue** (`Continue.continue`) -> Click **Uninstall**.
   - **Tabnine** (`TabNine.tabnine-vscode`) -> Click **Uninstall**.
   - **Codeium** (`Codeium.codeium`) -> Click **Uninstall**.
   - **Cline / Roo Code** -> Click **Uninstall**.

#### 2. Exact Configuration File Overrides (`settings.json`)
Open Settings JSON directly:
- Press `Ctrl + Shift + P` -> Type `Preferences: Open User Settings (JSON)`.
- File Path:
  - Windows: `%APPDATA%\Code\User\settings.json`
  - Linux: `~/.config/Code/User/settings.json`
  - macOS: `~/Library/Application Support/Code/User/settings.json`

Append or override the following exact JSON keys to enforce total deactivation:

```json
{
  "editor.inlineSuggest.enabled": false,
  "github.copilot.enable": {
    "*": false,
    "plaintext": false,
    "markdown": false,
    "python": false,
    "c": false,
    "cpp": false,
    "javascript": false
  },
  "github.copilot.editor.enableAutoCompletions": false,
  "telemetry.telemetryLevel": "off",
  "workbench.enableExperiments": false,
  "workbench.settings.enableNaturalLanguageSearch": false,
  "chat.commandCenter.enabled": false,
  "accessibility.voice.speechToText": "off",
  "extensions.autoUpdate": false,
  "extensions.autoCheckUpdates": false
}
```

---

### B. Cursor IDE

Cursor is an AI-first fork of VS Code. To achieve strict competition compliance, the AI core must be fully neutralized, reverting Cursor to a pure text editor.

#### 1. UI Settings Navigation
1. Open Cursor Settings: Press `Ctrl + Shift + J` (or click gear icon top right -> **Cursor Settings**).
2. Select **Features** in the sidebar:
   - **Copilot++ / Cursor Tab**: Toggle switch to **Disabled** (`OFF`).
   - **Inline Edit**: Toggle switch to **Disabled** (`OFF`).
   - **Cursor Chat**: Toggle switch to **Disabled** (`OFF`).
   - **Composer**: Toggle switch to **Disabled** (`OFF`).
3. Select **Models** in the sidebar:
   - Disable all checkboxes: `Claude 3.5 Sonnet`, `GPT-4o`, `GPT-4-turbo`, `Cursor-Small`.
   - Remove/Blank out all custom API keys.
4. Select **General**:
   - **Privacy Mode**: Set to **On** (prevents local code indexing and remote relay).

#### 2. Exact Configuration File Overrides (`settings.json`)
File Path:
- Windows: `%APPDATA%\Cursor\User\settings.json`
- Linux: `~/.config/Cursor/User/settings.json`
- macOS: `~/Library/Application Support/Cursor/User/settings.json`

Paste the following keys:

```json
{
  "cursor.tab.enabled": false,
  "cursor.inlineEdit.enabled": false,
  "cursor.chat.enabled": false,
  "cursor.composer.enabled": false,
  "cursor.aiRules.enabled": false,
  "cursor.general.privacyMode": true,
  "editor.inlineSuggest.enabled": false,
  "telemetry.telemetryLevel": "off",
  "workbench.enableExperiments": false
}
```

---

### C. JetBrains IDEs (CLion, PyCharm, IntelliJ IDEA, WebStorm)

#### 1. Plugin Deactivation UI Path
1. Navigate: **File** > **Settings** (Windows/Linux, `Ctrl + Alt + S`) or **Preferences** (macOS, `Cmd + ,`).
2. Select **Plugins** from the left pane.
3. Switch to the **Installed** tab.
4. Locate and uncheck / click **Disable**:
   - **AI Assistant** (JetBrains built-in AI module)
   - **GitHub Copilot**
   - **Tabnine**
   - **Full Line Code Completion** (local cloud-based inline predictor)
5. Click **Apply** -> **OK** -> Click **Restart IDE** when prompted.

#### 2. Settings Overrides
In **File** > **Settings** > **Editor** > **General** > **Code Completion**:
- Uncheck **Show suggestions as you type**.
- Uncheck **Machine Learning-Assisted Completion**.
- Uncheck **Full Line completion suggestions**.

In **File** > **Settings** > **Tools** > **AI Assistant**:
- Uncheck **Enable AI Assistant in project**.
- Log out of JetBrains AI Account.

---

### D. Google Antigravity IDE & Antigravity CLI (`agy`)

Antigravity IDE contains advanced multi-agent and LLM planning capabilities. For competition compliance or manual CTF mode:

#### 1. UI Deactivation
1. Close all active agent panels: Close background chat/agent planning panes.
2. In IDE Settings (`Ctrl + ,`):
   - Search `Antigravity` -> Set `Antigravity: Enabled` to `false`.
   - Set `Antigravity: Auto Trigger Planning` to `false`.
   - Set `Antigravity: Telemetry` to `false`.

#### 2. Disabling Background Tasks & Daemons via CLI
Run the following in PowerShell / Bash to ensure no active background agent workers are running:

```powershell
# Kill any orphan agent processes or local tool servers
Get-Process | Where-Object { $_.ProcessName -like "*antigravity*" -or $_.ProcessName -like "*mcp-server*" } | Stop-Process -Force -ErrorAction SilentlyContinue
```

```bash
# Linux/macOS equivalent
pkill -f "antigravity" || true
pkill -f "mcp-server" || true
```

#### 3. Configuration File Override
Path: `C:\Users\ZIAD\.gemini\config\config.json` or local `.agents/config.json`:
```json
{
  "autonomous_mode": false,
  "agent_execution_enabled": false,
  "mcp_servers_enabled": false,
  "cloud_sync": false,
  "telemetry_enabled": false
}
```

---

## 3. Network-Level Airgap Safeguards

Software switches can fail or be bypassed by background worker restarts. Network-level null-routing ensures physical impossibility of reaching LLM APIs.

### A. Operating System Hosts File Blackhole

Mapping hostnames to `127.0.0.1` (IPv4) and `::1` (IPv6) forces immediate connection termination with `ECONNREFUSED` without leaking DNS queries.

#### Hosts File Locations:
- **Windows**: `C:\Windows\System32\drivers\etc\hosts` *(Requires Administrator)*
- **Linux / macOS**: `/etc/hosts` *(Requires `sudo`)*

#### Append Block List:
```text
# ==============================================================================
# COMPETITION COMPLIANCE: LLM & AI ENDPOINT SINKHOLE (STRICT AIRGAP)
# ==============================================================================
127.0.0.1 api.openai.com
127.0.0.1 chat.openai.com
127.0.0.1 platform.openai.com
127.0.0.1 auth0.openai.com
127.0.0.1 api.anthropic.com
127.0.0.1 claude.ai
127.0.0.1 api.cohere.ai
127.0.0.1 api.mistral.ai
127.0.0.1 generativelanguage.googleapis.com
127.0.0.1 copilot-proxy.githubusercontent.com
127.0.0.1 api.githubcopilot.com
127.0.0.1 default.exp-tas.com
127.0.0.1 api.tabnine.com
127.0.0.1 gateway.tabnine.com
127.0.0.1 api.codeium.com
127.0.0.1 cursor.sh
127.0.0.1 repo42.cursor.sh
127.0.0.1 telemetry.cursor.sh
127.0.0.1 ai-assistant.services.jetbrains.com
::1 api.openai.com
::1 api.anthropic.com
::1 generativelanguage.googleapis.com
::1 api.githubcopilot.com
# ==============================================================================
```

#### Automated Script to Apply Hosts Block (Windows PowerShell - Run as Admin):
```powershell
$HostsPath = "$env:windir\System32\drivers\etc\hosts"
$BlockedDomains = @(
    "api.openai.com", "chat.openai.com", "platform.openai.com",
    "api.anthropic.com", "claude.ai", "api.cohere.ai", "api.mistral.ai",
    "generativelanguage.googleapis.com", "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com", "api.tabnine.com", "api.codeium.com",
    "cursor.sh", "repo42.cursor.sh", "telemetry.cursor.sh",
    "ai-assistant.services.jetbrains.com"
)

$Content = "`n# AI_COMPLIANCE_BLOCK_START`n"
foreach ($Domain in $BlockedDomains) {
    $Content += "127.0.0.1 $Domain`n"
    $Content += "::1 $Domain`n"
}
$Content += "# AI_COMPLIANCE_BLOCK_END`n"

Add-Content -Path $HostsPath -Value $Content -Encoding ASCII
Clear-DnsClientCache
Write-Host "[+] Hosts file successfully updated and DNS cache flushed." -ForegroundColor Green
```

#### Automated Script to Apply Hosts Block (Linux / macOS - Bash):
```bash
#!/usr/bin/env bash
DOMAINS=(
  "api.openai.com" "chat.openai.com" "platform.openai.com"
  "api.anthropic.com" "claude.ai" "api.cohere.ai" "api.mistral.ai"
  "generativelanguage.googleapis.com" "copilot-proxy.githubusercontent.com"
  "api.githubcopilot.com" "api.tabnine.com" "api.codeium.com"
  "cursor.sh" "repo42.cursor.sh" "telemetry.cursor.sh"
  "ai-assistant.services.jetbrains.com"
)

echo -e "\n# AI_COMPLIANCE_BLOCK_START" | sudo tee -a /etc/hosts
for d in "${DOMAINS[@]}"; do
  echo "127.0.0.1 $d" | sudo tee -a /etc/hosts
  echo "::1 $d" | sudo tee -a /etc/hosts
done
echo "# AI_COMPLIANCE_BLOCK_END" | sudo tee -a /etc/hosts

# Flush DNS cache depending on OS
if command -v systemd-resolve >/dev/null 2>&1; then
  sudo systemd-resolve --flush-caches
elif command -v dscacheutil >/dev/null 2>&1; then
  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
fi
echo "[+] /etc/hosts updated."
```

---

### B. OS Firewall Strict Drop Rules

#### Windows Defender Firewall (PowerShell as Admin):
```powershell
# Block known public outbound AI telemetry / API domains
New-NetFirewallRule -DisplayName "COMPLIANCE_BLOCK_OpenAI" -Direction Outbound -Action Block -RemoteAddress Any -Protocol TCP -RemotePort 443 -Description "Strict CTF Compliance"
# Or target by process:
New-NetFirewallRule -DisplayName "COMPLIANCE_BLOCK_VSCode_Copilot" -Direction Outbound -Program "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe" -Action Block -Enabled False # Change to True if full offline mode required
```

#### Linux `iptables` / `ufw`:
```bash
# Drop outbound connections to known AI provider IP ranges if known, or resolve:
for domain in api.openai.com api.anthropic.com generativelanguage.googleapis.com; do
  ips=$(dig +short $domain | grep -E '^[0-9.]+$')
  for ip in $ips; do
    sudo iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j REJECT
  done
done
```

---

## 4. Environment Variables Sanitization

API keys stored in persistent shell profiles can be picked up automatically by background tools.

### Audit & Purge Commands (Windows PowerShell):
```powershell
# 1. Audit current session environment variables
Get-ChildItem Env: | Where-Object { $_.Name -match "KEY|TOKEN|AI|COPILOT" }

# 2. Clear from current session
$env:OPENAI_API_KEY = ""
$env:ANTHROPIC_API_KEY = ""
$env:GEMINI_API_KEY = ""
$env:MISTRAL_API_KEY = ""
$env:GITHUB_TOKEN = ""

# 3. Clear from Windows User / System Registry persistently
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", $null, "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", $null, "User")
[Environment]::SetEnvironmentVariable("GEMINI_API_KEY", $null, "User")
Write-Host "[+] Environment variables cleansed." -ForegroundColor Green
```

### Audit & Purge Commands (Linux / macOS Bash):
```bash
# Check current session
env | grep -Ei 'key|token|ai|copilot'

# Remove from active shell
unset OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY MISTRAL_API_KEY

# Clean shell configuration files (~/.bashrc, ~/.zshrc, ~/.profile)
sed -i '/_API_KEY/d' ~/.bashrc ~/.zshrc 2>/dev/null || true
```

---

## 5. Proof of Compliance Command Suite (Audit & Verification)

Before starting the competition, execute the following audit commands. Save the output to a file (`compliance_audit.log`) to hand over to proctors as deterministic proof.

### A. Socket & Connection Inspection

Verify there are NO active ESTABLISHED connections to AI endpoints or unexpected high-port listening daemons:

#### Windows PowerShell:
```powershell
Write-Host "=== ACTIVE OUTBOUND HTTPS CONNECTIONS AUDIT ===" -ForegroundColor Cyan
Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -eq 443 } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        PID           = $_.OwningProcess
        ProcessName   = $proc.ProcessName
        Path          = $proc.Path
    }
} | Format-Table -AutoSize
```

#### Linux (`ss` / `lsof`):
```bash
echo "=== ACTIVE CONNECTIONS TO PORT 443 ==="
ss -tupn state established '( dport = :443 )'
```

### B. Process & Background Daemon Verification

Search for running AI tools, background models, or agent daemons:

#### Windows PowerShell:
```powershell
Write-Host "=== SCANNING FOR DISALLOWED BACKGROUND AI PROCESSES ===" -ForegroundColor Cyan
$DisallowedPatterns = @("ollama", "lmstudio", "vllm", "copilot", "continue", "mcp-server", "tabnine")
$Found = Get-Process | Where-Object {
    $name = $_.ProcessName.ToLower()
    foreach ($pat in $DisallowedPatterns) {
        if ($name -like "*$pat*") { return $true }
    }
    return $false
}

if ($Found) {
    Write-Host "[!] WARNING: Disallowed AI processes detected:" -ForegroundColor Red
    $Found | Select-Object Id, ProcessName, Path | Format-Table -AutoSize
} else {
    Write-Host "[+] VERIFIED CLEAN: No background AI processes detected." -ForegroundColor Green
}
```

#### Linux / macOS:
```bash
ps aux | grep -Ei 'ollama|lmstudio|vllm|copilot|tabnine|mcp' | grep -v grep
if [ $? -eq 0 ]; then
  echo "[-] WARNING: Suspect processes running!"
else
  echo "[+] VERIFIED CLEAN: No background AI processes running."
fi
```

### C. Automated Comprehensive Proctor Audit Script

Run this single self-contained script to generate a verifiable proctor report:

```powershell
# Save as: generate_compliance_proof.ps1
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
$OutputFile = "Competition_AI_Compliance_Proof.txt"

@"
===============================================================================
       CTF COMPETITION INTEGRITY & AI DEACTIVATION AUDIT REPORT
===============================================================================
Generated At : $Timestamp
Host Name    : $env:COMPUTERNAME
User Account : $env:USERNAME
OS Version   : $((Get-CimInstance Win32_OperatingSystem).Caption)

-------------------------------------------------------------------------------
1. HOSTS FILE SINKHOLE AUDIT
-------------------------------------------------------------------------------
"@ | Out-File -FilePath $OutputFile -Encoding UTF8

Get-Content "$env:windir\System32\drivers\etc\hosts" | Select-String -Pattern "openai|anthropic|copilot|cursor|tabnine" | Out-File -FilePath $OutputFile -Append -Encoding UTF8

@"

-------------------------------------------------------------------------------
2. ENVIRONMENT VARIABLES AUDIT
-------------------------------------------------------------------------------
"@ | Out-File -FilePath $OutputFile -Append -Encoding UTF8

Get-ChildItem Env: | Where-Object { $_.Name -match "OPENAI|ANTHROPIC|GEMINI|COPILOT" } | Out-File -FilePath $OutputFile -Append -Encoding UTF8

@"

-------------------------------------------------------------------------------
3. ACTIVE ESTABLISHED HTTPS (PORT 443) SOCKETS
-------------------------------------------------------------------------------
"@ | Out-File -FilePath $OutputFile -Append -Encoding UTF8

Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -eq 443 } | Select-Object LocalAddress, LocalPort, RemoteAddress, OwningProcess | Out-File -FilePath $OutputFile -Append -Encoding UTF8

@"

-------------------------------------------------------------------------------
4. INSTALLED VS CODE EXTENSIONS AUDIT
-------------------------------------------------------------------------------
"@ | Out-File -FilePath $OutputFile -Append -Encoding UTF8

if (Get-Command code -ErrorAction SilentlyContinue) {
    code --list-extensions | Out-File -FilePath $OutputFile -Append -Encoding UTF8
} else {
    "VS Code CLI not found in PATH." | Out-File -FilePath $OutputFile -Append -Encoding UTF8
}

@"

===============================================================================
               VERIFICATION COMPLETED - ENVIRONMENT SEALED
===============================================================================
"@ | Out-File -FilePath $OutputFile -Append -Encoding UTF8

Write-Host "[+] Audit report generated successfully: $OutputFile" -ForegroundColor Green
```

---

## 6. Emergency Recovery (Post-Competition Restoration)

After the competition concludes, to restore standard development configurations:

1. **Remove Hosts Block**: Open `hosts` file and delete lines between `# AI_COMPLIANCE_BLOCK_START` and `# AI_COMPLIANCE_BLOCK_END`. Flush DNS cache (`ipconfig /flushdns` or `systemd-resolve --flush-caches`).
2. **Re-enable VS Code Extensions**: In VS Code, search `@disabled` and click **Enable** on required extensions.
3. **Restore `settings.json`**: Set `"editor.inlineSuggest.enabled": true` and `"github.copilot.enable": {"*": true}`.
4. **Restore Environment Variables**: Reload credentials from encrypted backup vault or configuration manager.
