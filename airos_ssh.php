<?php
/**
 * Ubiquiti AirOS SSH Helper Library
 * 
 * Shared functions for SSHing into AirOS devices, reading/writing system.cfg,
 * fetching ARP/DHCP data, and managing port forwards and static leases.
 */

/**
 * Execute a command on an AirOS device via SSH.
 * Tries two passwords (primary + fallback).
 * 
 * @param string $radioIp  IP of the AirOS radio
 * @param int    $port     SSH port
 * @param string $cmd      Command to execute
 * @param string $login    SSH username
 * @param string $pass1    Primary password
 * @param string $pass2    Fallback password (optional)
 * @return string|null     Output or null on connection failure
 */
function airos_ssh_exec(string $radioIp, int $port, string $cmd, string $login, string $pass1, string $pass2 = ''): ?string {
    $sshOpts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
        . " -o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"
        . " -o HostKeyAlgorithms=+ssh-rsa,ssh-dss"
        . " -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc";

    $escapedIp = escapeshellarg($radioIp);
    $escapedLogin = escapeshellarg($login);
    $escapedCmd = escapeshellarg($cmd);

    // Try password 1
    $escapedPass = escapeshellarg($pass1);
    $fullCmd = "sshpass -p {$escapedPass} ssh {$sshOpts} -p {$port} {$escapedLogin}@{$escapedIp} {$escapedCmd} 2>&1";
    $output = shell_exec($fullCmd) ?? '';

    if ((strpos($output, 'Permission denied') !== false || strpos($output, 'Authentication') !== false) && !empty($pass2)) {
        $escapedPass2 = escapeshellarg($pass2);
        $fullCmd = "sshpass -p {$escapedPass2} ssh {$sshOpts} -p {$port} {$escapedLogin}@{$escapedIp} {$escapedCmd} 2>&1";
        $output = shell_exec($fullCmd) ?? '';
    }

    if (strpos($output, 'Permission denied') !== false || 
        strpos($output, 'Connection refused') !== false || 
        strpos($output, 'Connection timed out') !== false) {
        return null;
    }

    return $output;
}

/**
 * Read the full system.cfg from an AirOS device.
 */
function airos_read_config(string $radioIp, int $port, string $login, string $pass1, string $pass2 = ''): ?string {
    return airos_ssh_exec($radioIp, $port, 'cat /tmp/system.cfg', $login, $pass1, $pass2);
}

/**
 * Parse port forward rules from system.cfg content.
 * Returns array keyed by index: [idx => ['host'=>..., 'dport'=>..., 'port'=>..., 'proto'=>..., 'status'=>...]]
 */
function airos_parse_port_forwards(string $configContent): array {
    preg_match_all('/^iptables\.sys\.portfw\.(\d+)\.(.+)=(.*)$/m', $configContent, $matches, PREG_SET_ORDER);
    $portForwards = [];
    foreach ($matches as $m) {
        $idx = (int)$m[1];
        $key = $m[2];
        $val = $m[3];
        if (!isset($portForwards[$idx])) $portForwards[$idx] = [];
        $portForwards[$idx][$key] = $val;
    }
    return $portForwards;
}

/**
 * Check if a static DHCP lease exists for a given MAC in system.cfg.
 */
function airos_has_static_lease(string $configContent, string $mac): bool {
    $macUpper = strtoupper($mac);
    return (bool)preg_match('/dhcpd\.\d+\.static\.\d+\.mac=' . preg_quote($macUpper, '/') . '/i', $configContent);
}

/**
 * Add a static DHCP lease to system.cfg and the running dnsmasq config.
 * Returns true on success.
 */
function airos_add_static_lease(string $radioIp, int $port, string $login, string $pass1, string $pass2, string $mac, string $leaseIp, string $configContent): bool {
    $macFormatted = strtoupper($mac);
    
    // Find next static index
    preg_match_all('/dhcpd\.(\d+)\.static\.(\d+)\./', $configContent, $staticMatches);
    $dhcpdIdx = 1;
    $maxStaticIdx = !empty($staticMatches[2]) ? max(array_map('intval', $staticMatches[2])) : 0;
    $newStaticIdx = $maxStaticIdx + 1;

    // Write to system.cfg (persists across reboots)
    $staticEntry = "dhcpd.{$dhcpdIdx}.static.{$newStaticIdx}.mac={$macFormatted}\ndhcpd.{$dhcpdIdx}.static.{$newStaticIdx}.ip={$leaseIp}\ndhcpd.{$dhcpdIdx}.static.{$newStaticIdx}.status=enabled";
    airos_ssh_exec($radioIp, $port, "echo '{$staticEntry}' >> /tmp/system.cfg", $login, $pass1, $pass2);
    
    // Save to flash
    airos_ssh_exec($radioIp, $port, "cfgmtd -w -p /etc/", $login, $pass1, $pass2);
    
    // Add to running dnsmasq and reload
    $dnsmasqEntry = "dhcp-host={$macFormatted},{$leaseIp}";
    airos_ssh_exec($radioIp, $port, "echo '{$dnsmasqEntry}' >> /etc/dnsmasq.conf", $login, $pass1, $pass2);
    airos_ssh_exec($radioIp, $port, "killall -HUP dnsmasq", $login, $pass1, $pass2);
    
    return true;
}

/**
 * Add a port forward rule to system.cfg and apply it.
 * Returns true on success.
 */
function airos_add_port_forward(string $radioIp, int $port, string $login, string $pass1, string $pass2, string $configContent, int $wanPort, string $lanHost, int $lanPort, string $proto, string $srcIp, string $comment = ''): bool {
    $portForwards = airos_parse_port_forwards($configContent);
    $maxPfIdx = !empty($portForwards) ? max(array_keys($portForwards)) : 0;
    $newPfIdx = $maxPfIdx + 1;

    // Determine WAN interface
    $wanDevname = 'ath0';
    if (preg_match('/^netconf\.(\d+)\.role=wan$/m', $configContent, $wanMatch)) {
        $wanIdx = $wanMatch[1];
        if (preg_match("/^netconf\\.{$wanIdx}\\.devname=(.+)$/m", $configContent, $devMatch)) {
            $wanDevname = trim($devMatch[1]);
        }
    }

    $srcField = ($srcIp === '0.0.0.0') ? '0.0.0.0/0' : $srcIp . '/32';
    $commentField = $comment ?: 'auto-created';

    $pfConfig = implode("\n", [
        "iptables.sys.portfw.{$newPfIdx}.comment={$commentField}",
        "iptables.sys.portfw.{$newPfIdx}.devname={$wanDevname}",
        "iptables.sys.portfw.{$newPfIdx}.dport={$wanPort}",
        "iptables.sys.portfw.{$newPfIdx}.dst=0.0.0.0/0",
        "iptables.sys.portfw.{$newPfIdx}.host={$lanHost}",
        "iptables.sys.portfw.{$newPfIdx}.port={$lanPort}",
        "iptables.sys.portfw.{$newPfIdx}.proto={$proto}",
        "iptables.sys.portfw.{$newPfIdx}.src={$srcField}",
        "iptables.sys.portfw.{$newPfIdx}.status=enabled",
    ]);

    // Backup
    airos_ssh_exec($radioIp, $port, "cp /tmp/system.cfg /tmp/system.cfg.bak", $login, $pass1, $pass2);

    // Append port forward
    $escapedPf = str_replace("'", "'\\''", $pfConfig);
    airos_ssh_exec($radioIp, $port, "echo '{$escapedPf}' >> /tmp/system.cfg", $login, $pass1, $pass2);

    // Enable portfw master switch if not already
    if (strpos($configContent, 'iptables.sys.portfw.status=enabled') === false) {
        airos_ssh_exec($radioIp, $port, "echo 'iptables.sys.portfw.status=enabled' >> /tmp/system.cfg", $login, $pass1, $pass2);
    }

    // Save and apply
    airos_ssh_exec($radioIp, $port, "cfgmtd -w -p /etc/", $login, $pass1, $pass2);
    airos_ssh_exec($radioIp, $port, "/usr/etc/rc.d/rc.softrestart save 2>/dev/null &", $login, $pass1, $pass2);

    return true;
}
