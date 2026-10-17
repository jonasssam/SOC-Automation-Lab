# Custom Wazuh Active Response for Windows.
# Wazuh runs block-source-ip.cmd, which runs this script and passes the alert in as JSON.
# "add" blocks the attacker's IP in Windows Firewall, "delete" removes the block.

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\custom-response.log"

# IPs that should never be blocked, so a bad alert can't cut the endpoint off from the SIEM
$NeverBlock = @("127.0.0.1", "192.168.100.30")

$InputLine = [Console]::In.ReadLine()

try {
    $Message = $InputLine | ConvertFrom-Json
    $Command = $Message.command
    $Alert = $Message.parameters.alert

    # Linux-style alerts use srcip, Windows events use win.eventdata.ipAddress
    $SourceIP = $Alert.data.srcip

    if (-not $SourceIP) {
        $SourceIP = $Alert.data.win.eventdata.ipAddress
    }

    if (-not $SourceIP) {
        throw "No source IP found in alert"
    }

    # The IP comes from log data, so make sure it's actually a single IP address
    $ParsedIP = $null
    if (-not [System.Net.IPAddress]::TryParse($SourceIP, [ref]$ParsedIP)) {
        throw "Invalid source IP: $SourceIP"
    }

    if ($NeverBlock -contains $SourceIP) {
        throw "Refusing to block protected IP: $SourceIP"
    }

    $RuleName = "SOC-Automation-Block-$SourceIP"

    if ($Command -eq "add") {
        # Don't create a duplicate rule if this IP is already blocked
        if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
            Add-Content $LogFile "$(Get-Date -Format s) ALREADY BLOCKED $SourceIP"
        }
        else {
            New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block -RemoteAddress $SourceIP -Protocol Any -Profile Any -ErrorAction Stop | Out-Null
            Add-Content $LogFile "$(Get-Date -Format s) BLOCKED $SourceIP"
        }
    }
    elseif ($Command -eq "delete") {
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        Add-Content $LogFile "$(Get-Date -Format s) UNBLOCKED $SourceIP"
    }
}
catch {
    Add-Content $LogFile "$(Get-Date -Format s) ERROR $($_.Exception.Message)"
}
