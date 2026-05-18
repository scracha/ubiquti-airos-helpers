<?php
require_once 'airos_ssh.php';

// Device Credentials
$radioIp = '110.220.33.44';
$port    = 22;
$user    = 'ubnt';
$pass1   = 'PrimarySecretPassword';
$pass2   = 'OldFallbackPassword'; // Optional fallback

// 1. Fetch current device configuration
$config = airos_read_config($radioIp, $port, $user, $pass1, $pass2);

if ($config === null) {
    die("Error: Could not connect or authenticate to the AirOS device.\n");
}

// 2. Add a Static Lease for a connected client if it doesn't exist
$targetMac = '00:15:6D:A1:B2:C3';
$targetIp  = '192.168.1.50';

if (!airos_has_static_lease($config, $targetMac)) {
    echo "Adding static lease for {$targetMac}...\n";
    airos_add_static_lease($radioIp, $port, $user, $pass1, $pass2, $targetMac, $targetIp, $config);
    
    // Refresh local config variable with new entry
    $config = airos_read_config($radioIp, $port, $user, $pass1, $pass2);
}

// 3. Forward WAN port 8080 to LAN IP port 80
echo "Adding port forward rule...\n";
$success = airos_add_port_forward(
    $radioIp, 
    $port, 
    $user, 
    $pass1, 
    $pass2, 
    $config, 
    8080,          // WAN Port
    $targetIp,     // LAN Host Destination
    80,            // LAN Port
    'tcp',         // Protocol (tcp/udp)
    '0.0.0.0',     // Source IP restriction (0.0.0.0 allows all)
    'Web Camera'   // Optional Comment
);

if ($success) {
    echo "Port forward successfully created and applied!\n";
}