# Ubiquiti AirOS SSH Helper Library

A lightweight, native PHP helper library designed to programmatically interact with Ubiquiti AirOS devices over SSH. It allows you to read system configurations, manipulate running network services, create persistent port-forwarding rules, and manage static DHCP leases without needing a bloated framework.

## Features

* **Resilient Authentication**: Attempts authentication using a primary password with automatic fallback to a secondary password if permission is denied.
* **Legacy SSH Compatibility**: Built-in compatibility flags for connecting to older AirOS devices requiring legacy key exchange algorithms, host keys, and ciphers (e.g., `diffie-hellman-group1-sha1`, `ssh-rsa`, `3des-cbc`).
* **Persistent Modifications**: Changes to `system.cfg` are properly written to flash memory (`cfgmtd`) so they survive device reboots.
* **On-the-Fly Application**: Applies DHCP leases immediately via `dnsmasq` reload, and port-forwarding rules via `rc.softrestart`.

---

## Requirements

Before using this library, ensure your host environment meets the following dependencies:

1. **PHP 7.4+** (utilizes strict typing hints)
2. **`sshpass`** installed on your host system (used to pass SSH passwords securely via the CLI)
3. **OpenSSH Client** (`ssh`) installed on your host system

To install `sshpass` on Ubuntu/Debian systems:
```bash
sudo apt-get update
sudo apt-get install sshpass