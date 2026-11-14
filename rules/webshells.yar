/*
 * Torvex detection content: web shells.
 *
 * A web shell is a script an attacker uploads so they can run commands through
 * the web server. These rules require both a dangerous sink and a request
 * source, which keeps ordinary application code out of the results.
 *
 * License: MIT OR Apache-2.0. Author: Torvex contributors.
 */

rule tvx_php_webshell_eval : webshell php
{
    meta:
        title = "PHP eval web shell"
        description = "eval() applied to POST input executes arbitrary attacker-supplied PHP."
        severity = "critical"
        mitre = "T1505.003,T1059"
        compliance = "PCI DSS 6.4"
        remediation = "Remove the file, rotate application secrets and review access logs."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $eval = "eval(" ascii
        $post = "$_POST" nocase
        $request = "$_REQUEST" nocase
        $decode = "base64_decode(" ascii

    condition:
        $eval and ($post or $request) or ($decode and $eval)
}

rule tvx_php_webshell_exec : webshell php
{
    meta:
        title = "PHP command execution web shell"
        description = "A command execution function is driven directly by request input."
        severity = "high"
        mitre = "T1505.003"
        remediation = "Delete the file and determine which upload path placed it there."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $shell_exec = "shell_exec(" ascii
        $system = "system(" ascii
        $passthru = "passthru(" ascii
        $popen = "popen(" ascii
        $get = "$_GET" nocase
        $post = "$_POST" nocase

    condition:
        ($shell_exec or $system or $passthru or $popen) and ($get or $post)
}

rule tvx_jsp_webshell : webshell java
{
    meta:
        title = "JSP command execution web shell"
        description = "Executes a request parameter as a system command from a JSP page."
        severity = "high"
        mitre = "T1505.003"
        remediation = "Remove the deployed artifact, rotate credentials and review the access log."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $runtime = "Runtime.getRuntime().exec" ascii
        $request = "getParameter(" ascii
        $process = "ProcessBuilder(" ascii

    condition:
        ($runtime or $process) and $request
}

rule tvx_asp_webshell : webshell asp
{
    meta:
        title = "ASP eval web shell"
        description = "Evaluates request input as ASP code."
        severity = "high"
        mitre = "T1505.003"
        remediation = "Remove the file and review IIS logs for how it arrived."
        author = "Torvex contributors"
        license = "MIT OR Apache-2.0"

    strings:
        $eval = "eval request(" nocase
        $execute = "execute request(" nocase
        $server = "Server.CreateObject(" nocase

    condition:
        $eval or $execute or ($server and "scripting.filesystemobject")
}
