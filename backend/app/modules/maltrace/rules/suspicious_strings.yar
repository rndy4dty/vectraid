rule suspicious_powershell_encoded
{
    meta:
        author = "VECTRAID test suite"
        description = "Matches common PowerShell encoded command pattern"
        severity = "high"

    strings:
        $a = "powershell -enc" ascii nocase
        $b = "powershell.exe -enc" ascii nocase
        $c = "-EncodedCommand" ascii

    condition:
        any of them
}

rule suspicious_api_call
{
    meta:
        author = "VECTRAID test suite"
        description = "Matches Windows API commonly used in injection"
        severity = "medium"

    strings:
        $a = "CreateRemoteThread" ascii
        $b = "VirtualAllocEx" ascii

    condition:
        any of them
}
