Ubuntu CIS Compliance
Este repositório contém um script Bash que automatiza as configurações recomendadas pelo CIS Benchmark para o sistema operacional Ubuntu 22.04. O script aplica várias medidas de segurança que aumentam a proteção do sistema contra ataques e vulnerabilidades, alinhado às melhores práticas do Center for Internet Security (CIS).

Script: compliance.sh
Como usar:
Clone o repositório para a sua máquina Ubuntu 22.04:

bash
Copiar código
git clone https://github.com/seuusuario/ubuntu-cis-compliance.git
cd ubuntu-cis-compliance
chmod +x compliance.sh
sudo ./compliance.sh
O script vai aplicar automaticamente as configurações recomendadas para compliance com o CIS Benchmark.

O que o script faz:
Abaixo está a descrição de cada seção do script compliance.sh e sua relação com o CIS Benchmark:

1. Atualizações e Patches Automáticos
bash
Copiar código
sudo apt update && sudo apt -y upgrade
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
Benchmark CIS Ubuntu: Seção 1.2.1, 1.2.2
Descrição: Aplica todas as atualizações disponíveis e configura o sistema para instalar atualizações automáticas, garantindo que o sistema esteja sempre atualizado e protegido contra vulnerabilidades conhecidas.
2. Política de Senhas Fortes
bash
Copiar código
sudo apt install libpam-pwquality -y
sudo sed -i 's/^#\( minlen = \).*/\116/' /etc/security/pwquality.conf
sudo sed -i 's/^#\( minclass = \).*/\12/' /etc/security/pwquality.conf
Benchmark CIS Ubuntu: Seção 5.3.1
Descrição: Configura o PAM (Pluggable Authentication Modules) para garantir que senhas tenham um comprimento mínimo de 16 caracteres e incluam pelo menos 2 classes de caracteres (maiúsculas, minúsculas, números, ou símbolos).
3. Desabilitar Login Root via SSH
bash
Copiar código
sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
Benchmark CIS Ubuntu: Seção 5.2.8
Descrição: Desativa o login direto como usuário root via SSH, forçando os administradores a se conectarem com um usuário normal e depois elevarem suas permissões com sudo. Isso reduz o risco de ataques ao usuário root.
4. Habilitar Firewall UFW
bash
Copiar código
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
Benchmark CIS Ubuntu: Seção 3.5.1
Descrição: Habilita o firewall UFW (Uncomplicated Firewall) e aplica uma política padrão que bloqueia todo o tráfego de entrada, exceto o tráfego SSH, e permite todo o tráfego de saída. Isso restringe o acesso a serviços indesejados na máquina.
5. Auditoria do Sistema (auditd)
bash
Copiar código
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd
Benchmark CIS Ubuntu: Seção 4.1.1.1
Descrição: Instala e habilita o serviço auditd para registrar eventos críticos de segurança, como tentativas de login e alterações em arquivos sensíveis. Isso ajuda a monitorar e auditar o comportamento do sistema.
6. Verificação de Integridade de Arquivos (AIDE)
bash
Copiar código
sudo apt install aide -y
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
Benchmark CIS Ubuntu: Seção 1.3.1
Descrição: Instala e inicializa o AIDE (Advanced Intrusion Detection Environment), uma ferramenta que verifica a integridade de arquivos críticos no sistema. Isso permite detectar alterações não autorizadas em arquivos.
7. Desabilitar Serviços Não Necessários
bash
Copiar código
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
Benchmark CIS Ubuntu: Seção 2.2.x
Descrição: Desativa serviços desnecessários, como Avahi (usado para descoberta de serviços em redes locais) e CUPS (usado para impressão), que podem introduzir vulnerabilidades se não forem usados.
8. Habilitar AppArmor
bash
Copiar código
sudo systemctl enable apparmor
sudo systemctl start apparmor
Benchmark CIS Ubuntu: Seção 1.6.1.1
Descrição: Habilita o AppArmor, um sistema de controle de acesso que aplica políticas restritivas aos processos do sistema, limitando suas ações e aumentando a segurança geral.
9. Gerenciamento de Logs (logrotate)
bash
Copiar código
sudo apt install logrotate -y
sudo logrotate /etc/logrotate.conf
Benchmark CIS Ubuntu: Seção 4.2.x
Descrição: Configura o logrotate para gerenciar o crescimento de arquivos de log, garantindo que logs antigos sejam arquivados e que o espaço no disco seja gerenciado eficientemente.
Contribuição
Contribuições são bem-vindas! Se você encontrar algum problema ou tiver sugestões de melhoria, fique à vontade para abrir um issue ou enviar um pull request.
