#!/bin/bash
# CloudSentinel AI: CIS Benchmark Operating System Hardening Script

echo "[+] Starting CIS OS Baseline Hardening..."

# 1. Disable Direct Root Login via SSH
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 2. Enforce Mandatory SSH Key Authentication (Disable Passwords)
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# 3. Set Restrictive Permissions on Critical Files
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /etc/ssh/sshd_config

# 4. Restart SSH Service safely
systemctl restart sshd || service ssh restart

echo "[+] CIS Hardening Completed Successfully."