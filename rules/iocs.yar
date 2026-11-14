/*
 * Torvex detection content: credential and exfiltration indicators.
 *
 * These rules match material that should not be in a working tree at all:
 * cloud keys, private keys, and chat webhooks used as data drop points. They
 * are high-signal but not proof of compromise — a key can be a redacted test
 * fixture, and a webhook can be legitimate monitoring.
 *
 * License: MIT OR Apache-2.0. Author: Torvex contributors.
 */

rule tvx_aws_access_key : credentials cloud
{
    meta:
        title = "AWS access key identifier"
        description = "A hard-coded AWS access key id leaks cloud credentials to anyone with the file."
        severity = "high"
        mitre = "T1552.001"
        compliance = "NIST IA-5"
        remediation = "Revoke the key in IAM, rotate it and move the value to a secret store."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $access_key = /AKIA[0-9A-Z]{16}/
        $secret_name = "aws_secret_access_key" nocase

    condition:
        $access_key or $secret_name
}

rule tvx_private_key_material : credentials key_material
{
    meta:
        title = "Embedded private key"
        description = "A PEM private key inside a file is an unmanaged, copyable credential."
        severity = "medium"
        mitre = "T1552.004"
        remediation = "Move the key to an agent or vault and rotate it, because the copy is exposed."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $generic = "-----BEGIN PRIVATE KEY-----"
        $placeholder = "REDACTED" nocase

    condition:
        any of ($rsa, $openssh, $ec, $generic) and not $placeholder
}

rule tvx_chat_webhook_exfil : exfiltration network
{
    meta:
        title = "Chat webhook used as a data drop"
        description = "Discord or Telegram endpoints are frequently abused for low-cost exfiltration."
        severity = "medium"
        mitre = "T1567.002,T1102"
        remediation = "Block the endpoint and review what data the surrounding code collects."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $discord = "discord.com/api/webhooks" nocase
        $telegram = "api.telegram.org" nocase
        $slack = "hooks.slack.com/services" nocase
        $scp = "scp " ascii

    condition:
        $discord or $telegram or $slack or ($scp and "id_rsa")
}

rule tvx_shell_history_upload : exfiltration
{
    meta:
        title = "Shell history uploaded"
        description = "Archives and sends shell history or credential files off the host."
        severity = "medium"
        mitre = "T1567,T1552"
        remediation = "Block outbound traffic, then rotate every credential that could be in the archive."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $history = ".bash_history" ascii
        $curl = "curl" nocase
        $post = "--data-binary" nocase
        $wget = "wget" nocase
        $upload = "--post-file" nocase

    condition:
        $history and (($curl and $post) or ($wget and $upload))
}
