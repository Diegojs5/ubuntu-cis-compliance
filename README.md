
# Ubuntu CIS Compliance

Este repositório contém um script Bash que automatiza as configurações recomendadas pelo **CIS Benchmark** para o sistema operacional **Ubuntu 22.04**. O script aplica várias medidas de segurança que aumentam a proteção do sistema contra ataques e vulnerabilidades, alinhado às melhores práticas do **Center for Internet Security (CIS)**.

## Script: compliance.sh

### Como usar:

1. Clone o repositório para a sua máquina Ubuntu 22.04:
    ```bash
    git clone https://github.com/seuusuario/ubuntu-cis-compliance.git
    cd ubuntu-cis-compliance
    chmod +x compliance.sh
    sudo ./compliance.sh
    ```

2. O script vai aplicar automaticamente as configurações recomendadas para compliance com o **CIS Benchmark**.

### O que o script faz:

Abaixo está a descrição de cada seção do script **`compliance.sh`** e sua relação com o **CIS Benchmark**:

---

### 1. Atualizações e Patches Automáticos

```bash
sudo apt update && sudo apt -y upgrade
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

- **Benchmark CIS Ubuntu**: Seção 1.2.1, 1.2.2
- **Descrição**: Aplica todas as atualizações disponíveis e configura o sistema para instalar atualizações automáticas, garantindo que o sistema esteja sempre atualizado e protegido contra vulnerabilidades conhecidas.

---

### 2. Política de Senhas Fortes

```bash
sudo apt install libpam-pwquality -y
sudo sed -i 's/^#\( minlen = \).*/N/' /etc/security/pwquality.conf
sudo sed -i 's/^#\( minclass = \).*/
/' /etc/security/pwquality.conf
```

- **Benchmark CIS Ubuntu**: Seção 5.3.1
- **Descrição**: Configura o PAM (Pluggable Authentication Modules) para garantir que senhas tenham um comprimento mínimo de 16 caracteres e incluam pelo menos 2 classes de caracteres (maiúsculas, minúsculas, números, ou símbolos).

---

### 3. Configurar Hash de Senhas com SHA-512

```bash
sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
```

- **Benchmark CIS Ubuntu**: Seção 5.3.4
- **Descrição**: Configura o sistema para usar o algoritmo de hashing SHA-512 ao armazenar senhas, garantindo uma proteção mais forte contra ataques de brute-force.

---

### 4. Limitar Tentativas de Login

```bash
sudo echo "auth required pam_tally2.so onerr=fail audit deny=5 unlock_time=900" >> /etc/pam.d/common-auth
```

- **Benchmark CIS Ubuntu**: Seção 5.3.3
- **Descrição**: Configura limites para tentativas de login incorretas (até 5 tentativas falhas), evitando ataques de força bruta.

---

### 5. Desabilitar Login Root via SSH

```bash
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

- **Benchmark CIS Ubuntu**: Seção 5.2.8
- **Descrição**: Desativa o login direto como usuário `root` via SSH, forçando os administradores a se conectarem com um usuário normal e depois elevarem suas permissões com `sudo`. Isso reduz o risco de ataques ao usuário root.

---

### 6. Habilitar Firewall UFW

```bash
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
```

- **Benchmark CIS Ubuntu**: Seção 3.5.1
- **Descrição**: Habilita o firewall UFW (Uncomplicated Firewall) e aplica uma política padrão que bloqueia todo o tráfego de entrada, exceto o tráfego SSH, e permite todo o tráfego de saída. Isso restringe o acesso a serviços indesejados na máquina.

---

### 7. Auditoria do Sistema (auditd)

```bash
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

- **Benchmark CIS Ubuntu**: Seção 4.1.1.1
- **Descrição**: Instala e habilita o serviço `auditd` para registrar eventos críticos de segurança, como tentativas de login e alterações em arquivos sensíveis. Isso ajuda a monitorar e auditar o comportamento do sistema.

---

### 8. Verificação de Integridade de Arquivos (AIDE)

```bash
sudo apt install aide -y
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

- **Benchmark CIS Ubuntu**: Seção 1.3.1
- **Descrição**: Instala e inicializa o **AIDE (Advanced Intrusion Detection Environment)**, uma ferramenta que verifica a integridade de arquivos críticos no sistema. Isso permite detectar alterações não autorizadas em arquivos.

---

### 9. Desabilitar Serviços Não Necessários

```bash
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
```

- **Benchmark CIS Ubuntu**: Seção 2.2.x
- **Descrição**: Desativa serviços desnecessários, como **Avahi** (usado para descoberta de serviços em redes locais) e **CUPS** (usado para impressão), que podem introduzir vulnerabilidades se não forem usados.

---

### 10. Habilitar AppArmor

```bash
sudo systemctl enable apparmor
sudo systemctl start apparmor
```

- **Benchmark CIS Ubuntu**: Seção 1.6.1.1
- **Descrição**: Habilita o **AppArmor**, um sistema de controle de acesso que aplica políticas restritivas aos processos do sistema, limitando suas ações e aumentando a segurança geral.

---

### 11. Desativar IPv6 (se não for necessário)

```bash
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
```

- **Benchmark CIS Ubuntu**: Seção 3.2.x
- **Descrição**: Desativa o IPv6 se não for necessário, reduzindo a superfície de ataque ao desabilitar um protocolo que pode ser vulnerável se mal configurado.

---

### 12. Configuração de Segurança do Kernel (Sysctl)

```bash
# Desabilitar redirecionamento de pacotes IPv4
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0

# Desativar redirecionamento de pacotes ICMP
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

# Proteger contra ataques SYN
sudo sysctl -w net.ipv4.tcp_syncookies=1
```

- **Benchmark CIS Ubuntu**: Seção 3.3.x
- **Descrição**: Ajusta parâmetros do kernel para aumentar a segurança do sistema, como desabilitar o redirecionamento de pacotes e proteger contra ataques SYN.

---

### 13. Configuração de Permissões de Arquivos Críticos

```bash
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/shadow
sudo chmod 644 /etc/group
```

- **Benchmark CIS Ubuntu**: Seção 6.1.x
- **Descrição**: Garante que os arquivos de sistema mais críticos tenham as permissões corretas para evitar acesso não autorizado.

---

### 14. Desabilitar Contas Inativas

```bash
sudo useradd -D -f 30
```

- **Benchmark CIS Ubuntu**: Seção 5.4.2
- **Descrição**: Desabilita automaticamente contas de usuários que estão inativas por mais de 30 dias.

---

### 15. Proteger o GRUB com uma Senha

```bash
sudo grub-mkpasswd-pbkdf2
```

- **Benchmark CIS Ubuntu**: Seção 1.5.3
- **Descrição**: Protege o bootloader (GRUB) com uma senha para evitar alterações não autorizadas nas configurações do boot.

---

### 16. Configurar `rsyslog` para Logs

```bash
sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

- **Benchmark CIS Ubuntu**: Seção 4.2.x
- **Descrição**: Instala e configura o `rsyslog` para gerenciar os logs do sistema, garantindo que eles sejam capturados e armazenados corretamente.

---

## Contribuição

Contribuições são bem-vindas! Se você encontrar algum problema ou tiver sugestões de melhoria, fique à vontade para abrir um **issue** ou enviar um **pull request**.
