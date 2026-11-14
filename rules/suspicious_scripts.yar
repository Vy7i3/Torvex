/*
 * Torvex detection content: scripted execution and loaders.
 *
 * These rules describe observable behaviour, not a malware family. Each one
 * sets severity, a MITRE ATT&CK mapping and remediation guidance so the report
 * can explain itself. They are intentionally narrow: a hit is evidence to
 * review, never a verdict.
 *
 * License: MIT OR Apache-2.0. Author: Torvex contributors.
 */

rule tvx_powershell_download_cradle : loader powershell
{
    meta:
        title = "PowerShell download cradle"
        description = "Downloads remote content and evaluates it in memory, a common first stage."
        severity = "critical"
        mitre = "T1059.001,T1105"
        compliance = "PCI DSS 6.4,NIST SI-3"
        remediation = "Block the script, identify the remote host and treat the endpoint as suspect."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $download = "DownloadString" nocase
        $download_data = "DownloadData" nocase
        $iex = "IEX" nocase
        $invoke = "Invoke-Expression" nocase

    condition:
        ($download or $download_data) and ($iex or $invoke)
}

rule tvx_encoded_powershell : obfuscation powershell
{
    meta:
        title = "Encoded PowerShell command"
        description = "A base64-encoded command hides its payload from logs and reviewers."
        severity = "high"
        mitre = "T1059.001,T1027"
        remediation = "Decode the command and review the second stage before execution."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $enc = "-EncodedCommand" nocase
        $enc_short = "-enc " nocase
        $decode = "FromBase64String" nocase

    condition:
        ($enc or $enc_short) and $decode
}

rule tvx_reverse_shell : reverse_shell
{
    meta:
        title = "Reverse shell script"
        description = "Combines an interactive shell with a socket redirect to a remote host."
        severity = "critical"
        mitre = "T1059.004,T1071"
        remediation = "Kill the process, capture its parent chain and isolate the host."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $devtcp = "/dev/tcp/"
        $bash = "bash -i" nocase
        $nc = "nc -e" nocase
        $python_socket = "import socket" nocase
        $pty = "pty.spawn" nocase

    condition:
        $devtcp and ($bash or $nc) or ($python_socket and $pty)
}

rule tvx_crypto_miner : miner resource_hijacking
{
    meta:
        title = "Crypto miner configuration"
        description = "References a mining pool or the XMRig miner."
        severity = "high"
        mitre = "T1496"
        remediation = "Remove the miner and review how it was installed and persisted."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $stratum = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $xmrig = "xmrig" nocase
        $donate = "--donate-level" nocase

    condition:
        $stratum or $stratum_ssl or ($xmrig and $donate)
}

rule tvx_ransom_note : ransomware
{
    meta:
        title = "Ransom note"
        description = "Matches text used in common ransom notes."
        severity = "critical"
        mitre = "T1486"
        compliance = "NIST IR-4"
        remediation = "Isolate the host, preserve evidence and restore from a verified backup."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $note = "your files have been encrypted" nocase
        $note_alt = "all your files are encrypted" nocase
        $decrypt = "readme_for_decrypt" nocase
        $payment = "decrypt your files" nocase

    condition:
        any of them
}

rule tvx_anti_forensics : anti_forensics
{
    meta:
        title = "History or audit trail cleared"
        description = "Clears shell history, disables SELinux at runtime or flushes the firewall."
        severity = "medium"
        mitre = "T1070,T1562"
        remediation = "Check centralised logs for the commands that ran before the clear."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $history = "history -c" nocase
        $setenforce = "setenforce 0" nocase
        $flush = "iptables -F" nocase
        $audit_stop = "service auditd stop" nocase

    condition:
        any of them
}
