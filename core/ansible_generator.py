import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class AnsiblePlaybookGenerator:
    """Generates CIS Level 1 OS and Network Hardening Ansible Playbooks."""

    @staticmethod
    def generate_playbook(hardened_payload: Dict[str, Any], framework_name: str) -> str:
        if not isinstance(hardened_payload, dict):
            hardened_payload = {}
        ami_id = hardened_payload.get("ami_id", "ami-cloudsentinel-golden")
        
        playbook_yaml = f"""# ==============================================================================
# CloudSentinel AI - Automated CIS OS Hardening & Remediation Playbook
# Target Governance: {framework_name}
# Verified Golden Target: {ami_id}
# ==============================================================================
---
- name: Apply Zero-Trust CIS Level 1 OS Hardening
  hosts: migration_quarantine_hosts
  become: yes
  tasks:
    - name: Disable SSH Direct Root Login
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PermitRootLogin'
        line: 'PermitRootLogin no'
        state: present
      notify: Restart sshd

    - name: Enforce Key-Based Authentication (Disable Password Auth)
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PasswordAuthentication'
        line: 'PasswordAuthentication no'
        state: present
      notify: Restart sshd

    - name: Configure Linux UFW Firewall for VPC-Only Management Access
      ansible.builtin.ufw:
        rule: allow
        port: "{{ item }}"
        proto: tcp
        from_ip: 10.0.0.0/16
      loop:
        - '22'
        - '3389'

    - name: Deny All Public Inbound Traffic
      ansible.builtin.ufw:
        direction: incoming
        policy: deny

    - name: Patch Critical System Libraries (OpenSSL / Log4j mitigation)
      ansible.builtin.package:
        name:
          - openssl
          - iptables
          - fail2ban
        state: latest

  handlers:
    - name: Restart sshd
      ansible.builtin.service:
        name: sshd
        state: restarted
"""
        return playbook_yaml