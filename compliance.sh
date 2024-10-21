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

# Configurar hash SHA-512 para senhas
sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs

# Limitar tentativas de login falhas
sudo echo "auth required pam_tally2.so onerr=fail audit deny=5 unlock_time=900" >> /etc/pam.d/common-auth

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

# Desativar IPv6 (se não for necessário)
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Configurações de sysctl para segurança do kernel
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Configurar permissões de arquivos críticos
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/shadow
sudo chmod 644 /etc/group

# Desabilitar contas inativas após 30 dias
sudo useradd -D -f 30

# Proteger o GRUB com uma senha (você será solicitado a definir uma senha)
sudo grub-mkpasswd-pbkdf2

# Verificar se rsyslog está instalado
sudo apt install rsyslog -y

# Habilitar e iniciar rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog

echo "Configurações de compliance CIS Benchmark aplicadas com sucesso!"
