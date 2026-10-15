rule gc_eicar
{
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e
}

rule gc_discord_webhook
{
    meta:
        description = "Discord webhook (common malware exfil/C2 channel)"
        severity = "high"
    strings:
        $w = /https:\/\/(discordapp\.com|discord\.com)\/api\/webhooks\/[0-9]{17,20}\/[\w-]{60,90}/ nocase
    condition:
        $w
}

rule gc_telegram_bot_token
{
    meta:
        description = "Telegram bot token (common C2 channel)"
        severity = "high"
    strings:
        $t = /[0-9]{8,10}:[A-Za-z0-9_-]{30,45}/ nocase
    condition:
        $t
}

rule gc_powershell_encoded
{
    meta:
        description = "PowerShell encoded command"
        severity = "high"
    strings:
        $a = /-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        $a
}

rule gc_keylogger_strings
{
    meta:
        description = "Keylogger API references in binary/script"
        severity = "high"
    strings:
        $a = "GetAsyncKeyState" ascii wide
        $b = "SetWindowsHookEx" ascii wide
        $c = "GetKeyState" ascii wide
    condition:
        ($a and $b) or $a or $b
}

rule gc_stealer_strings
{
    meta:
        description = "Browser credential / wallet stealer targets"
        severity = "high"
    strings:
        $a = "wallet.dat" ascii wide nocase
        $b = "Login Data" ascii wide
        $c = "cookies.sqlite" ascii wide nocase
        $d = "CryptUnprotectData" ascii wide
    condition:
        ($a or $c) or ($b and $d)
}

rule gc_injection_apis
{
    meta:
        description = "Process injection API references"
        severity = "high"
    strings:
        $a = "WriteProcessMemory" ascii wide
        $b = "CreateRemoteThread" ascii wide
        $c = "VirtualAllocEx" ascii wide
    condition:
        ($a and $b) or ($a and $c)
}

rule gc_hardcoded_c2
{
    meta:
        description = "Hardcoded IP in URL"
        severity = "medium"
    strings:
        $u = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{2,5})?/ nocase
    condition:
        $u
}

rule gc_crack_emu_info
{
    meta:
        description = "Known crack/steam emulator string (usually legitimate)"
        severity = "info"
    strings:
        $a = "Goldberg" ascii wide
        $b = "SmartSteamEmu" ascii wide
        $c = "RUNE" ascii wide
    condition:
        $a or $b or $c
}
