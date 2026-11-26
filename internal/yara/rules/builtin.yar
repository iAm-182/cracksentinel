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
        description = "Keylogger hooking API stack in binary/script"
        severity = "high"
    strings:
        $hook = "SetWindowsHookEx" ascii wide
        $async = "GetAsyncKeyState" ascii wide
        $fg = "GetForegroundWindow" ascii wide
        $next = "CallNextHookEx" ascii wide
    condition:
        $hook and ($async or ($fg and $next))
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

rule gc_infostealer_abe
{
    meta:
        description = "Chromium App-Bound Encryption bypass / IElevator stealer (Lumma/StealC/Rhadamanthys)"
        severity = "high"
    strings:
        $abe = "app_bound_encrypted_key" ascii wide
        $elev = "IElevator" ascii wide
        $ls = "Local State" ascii wide
        $login = "Login Data" ascii wide
    condition:
        $abe or ($elev and ($ls or $login))
}

rule gc_infostealer_wallets_sessions
{
    meta:
        description = "Browser crypto wallet extension IDs and Discord/Telegram session theft targets"
        severity = "high"
    strings:
        $mm = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide nocase
        $ph = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide nocase
        $ex = "exodus.wallet" ascii wide nocase
        $tg = "Telegram Desktop\\tdata" ascii wide nocase
        $dc = "discord\\Local Storage\\leveldb" ascii wide nocase
    condition:
        any of ($mm, $ph, $ex, $tg, $dc)
}

rule gc_family_lumma_stealc
{
    meta:
        description = "LummaC2 / StealC / Rhadamanthys infostealer build markers"
        severity = "high"
    strings:
        $l1 = "LummaC2" ascii wide nocase
        $l2 = "Lumma Stealer" ascii wide nocase
        $s1 = "StealC" ascii wide
        $s2 = "- HWID:" ascii
        $s3 = "Network Info:" ascii
        $r1 = "Rhadamanthys" ascii wide nocase
    condition:
        $l1 or $l2 or $r1 or ($s1 and ($s2 or $s3))
}

rule gc_family_remcos_rat
{
    meta:
        description = "Remcos RAT watchdog and mutex indicators (Elastic signature reference)"
        severity = "high"
    strings:
        $a1 = "Remcos restarted by watchdog!" ascii wide
        $a2 = "Mutex_RemWatchdog" ascii wide
        $a3 = "* Remcos v" ascii wide
        $a4 = "ServRem" ascii fullword
        $a5 = "MicRecords" ascii fullword
    condition:
        any of ($a1, $a2, $a3) or ($a4 and $a5)
}

rule gc_family_asyncrat_xworm
{
    meta:
        description = "AsyncRAT / XWorm remote access trojan markers"
        severity = "high"
    strings:
        $a1 = "AsyncRAT" ascii wide
        $x1 = "XWorm" ascii wide
        $p1 = "RunPE" ascii wide
        $p2 = "get_IsConnected" ascii wide
        $p3 = "Client.Client" ascii wide
        $p4 = "Win32_Processor" ascii wide
    condition:
        ($a1 and any of ($p1, $p2, $p3)) or ($x1 and any of ($p1, $p4))
}

rule gc_cryptominer_xmrig
{
    meta:
        description = "XMRig / Stratum silent cryptocurrency miner"
        severity = "high"
    strings:
        $s1 = "stratum+tcp://" ascii wide nocase
        $s2 = "stratum+ssl://" ascii wide nocase
        $x1 = "xmrig" ascii wide nocase
        $x2 = "donate-level" ascii wide nocase
        $x3 = "rx/0" ascii wide
        $x4 = "moneroocean" ascii wide nocase
    condition:
        any of ($s1, $s2, $x4) or ($x1 and ($x2 or $x3))
}

rule gc_defender_uac_bypass
{
    meta:
        description = "Windows Defender exclusion tamper or fodhelper/ms-settings UAC bypass"
        severity = "high"
    strings:
        $d1 = "Add-MpPreference" ascii wide nocase
        $d2 = "ExclusionPath" ascii wide nocase
        $d3 = "DisableRealtimeMonitoring" ascii wide nocase
        $u1 = "ms-settings\\Shell\\Open\\command" ascii wide nocase
        $u2 = "fodhelper.exe" ascii wide nocase
        $u3 = "DelegateExecute" ascii wide
    condition:
        ($d1 and $d2) or $d3 or $u1 or ($u2 and $u3)
}

rule gc_lsass_dumper
{
    meta:
        description = "LSASS credential memory dump indicators"
        severity = "high"
    strings:
        $a1 = "MiniDumpWriteDump" ascii wide
        $a2 = "lsass.exe" ascii wide nocase
        $b1 = "comsvcs.dll" ascii wide nocase
        $b2 = "MiniDump" ascii wide
        $c1 = "sekurlsa" ascii wide nocase
    condition:
        $c1 or ($a1 and $a2) or ($b1 and $b2)
}

rule gc_lolbin_dropper
{
    meta:
        description = "ClickFix / LOLBin remote payload download & execution"
        severity = "high"
    strings:
        $m = /mshta(\.exe)?\s+https?:\/\// nocase
        $c = /certutil(\.exe)?\s+[^\r\n]{0,80}-urlcache/ nocase
        $r = /regsvr32(\.exe)?\s+[^\r\n]{0,60}\/i:https?:\/\// nocase
        $p = /(irm|iwr|invoke-restmethod)\s+['"]?https?:\/\/[^\r\n|]{4,140}\|\s*(iex|invoke-expression)/ nocase
    condition:
        any of them
}

rule gc_crypto_clipper
{
    meta:
        description = "Cryptocurrency clipboard address-hijacking clipper"
        severity = "high"
    strings:
        $cb1 = "GetClipboardData" ascii wide
        $cb2 = "SetClipboardData" ascii wide
        $cb3 = "clipboard" ascii wide nocase
        $rx1 = "^(bc1|[13])" ascii wide
        $rx2 = "^0x[a-fA-F0-9]{40}" ascii wide
        $rx3 = "^T[A-Za-z1-9]{33}" ascii wide
        $rx4 = "^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}" ascii wide
    condition:
        any of ($cb*) and 2 of ($rx*)
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
        $d = "TENOKE" ascii wide
    condition:
        any of them
}
