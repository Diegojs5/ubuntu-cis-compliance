#!/bin/bash

echo "Iniciando configurações de compliance CIS Benchmark para Ubuntu 22.04..."

# Atualizar pacotes e aplicar patches de segurança
sudo apt update && sudo apt -y upgrade

# Configurar atualizações automáticas
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Configurar política de senha complexa
sudo apt install libpam-pwquality -y
sudo sed -i 's/^#\( minlen = \).*/\116/' /etc/security/pwquality.conf
sudo sed -i 's/^#\( minclass = \).*/\12/' /etc/security/pwquality.conf

# Desabilitar login root via SSH
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Habilitar o firewall UFW
sudo ufw enable

# Configurar regras básicas de firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh

# Instalar e configurar auditd
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd

# Instalar e configurar AIDE
sudo apt install aide -y
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Desabilitar serviços não essenciais
sudo systemctl disable avahi-daemon
sudo systemctl disable cups

# Habilitar AppArmor
sudo systemctl enable apparmor
sudo systemctl start apparmor

# Configurar rotação de logs com logrotate
sudo apt install logrotate -y
sudo logrotate /etc/logrotate.conf
