#!/bin/bash

# -----------------------------
#   Comprobaciones previas
# -----------------------------

# Comprobación de si Go está instalado
check_go() {
    if ! command -v go &> /dev/null; then
        echo "[!] Go no está instalado. Instalando Go..."
        sudo apt-get update && sudo apt-get install golang -y
        if ! command -v go &> /dev/null; then
            echo "[!] Error: No se pudo instalar Go. Aborte la instalación."
            exit 1
        fi
    else
        echo "[+] Go está instalado."
    fi
}

# Comprobación de si pv está instalado (para la barra de progreso)
check_pv() {
    if ! command -v pv &> /dev/null; then
        echo "[!] pv no está instalado. Instalando pv..."
        sudo apt-get install pv -y
        if ! command -v pv &> /dev/null; then
            echo "[!] Error: No se pudo instalar pv. Aborte la instalación."
            exit 1
        fi
    else
        echo "[+] pv está instalado."
    fi
}

# Comprobación de si apt está disponible (dependencias de sistema)
check_apt() {
    if ! command -v apt &> /dev/null; then
        echo "[!] apt no está disponible en tu sistema. Este script requiere apt."
        exit 1
    fi
}

# Comprobación si una herramienta ya está instalada
check_tool() {
    if command -v $1 &> /dev/null; then
        echo "[+] $1 ya está instalado."
        return 1  # Retorna 1 para indicar que no se necesita instalar
    else
        return 0  # Retorna 0 para indicar que se necesita instalar
    fi
}

# Función para mostrar barra de progreso y ejecutar la instalación
install_with_progress() {
    echo "[+] Instalando $1..."
    echo | pv -n -s 100 | while read i; do
        $2
    done
    echo "[+] $1 instalado con éxito."
}

# -----------------------------
#   Instalación de herramientas
# -----------------------------

# Comprobaciones previas
check_apt
check_go
check_pv

echo "----------------------------------------"
echo "[+] Iniciando instalación de herramientas..."
echo "----------------------------------------"

# -----------------------------
#   Instalación de herramientas
# -----------------------------

# Subdomain Enumeration
check_tool "subfinder"
if [ $? -eq 0 ]; then
    install_with_progress "Subdomain Enumeration (subfinder)" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    # Crear carpeta de listas de subdominios si no existe y colocar listas predeterminadas
    mkdir -p $HOME/.config/subfinder
    echo "[+] Instalando listas predeterminadas de subdominios en $HOME/.config/subfinder/"
    wget -q https://raw.githubusercontent.com/projectdiscovery/subfinder/master/resources/subdomains.txt -O $HOME/.config/subfinder/subdomains.txt
fi

# Alive detection + tech fingerprinting
check_tool "httpx"
if [ $? -eq 0 ]; then
    install_with_progress "Alive detection + tech fingerprinting (httpx)" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    # Descargar listas de fingerprinting o tecnologías si son necesarias
    mkdir -p $HOME/.config/httpx
    wget -q https://raw.githubusercontent.com/projectdiscovery/httpx/master/resources/fingerprints.txt -O $HOME/.config/httpx/fingerprints.txt
fi

# Fast Port Scanning
check_tool "naabu"
if [ $? -eq 0 ]; then
    install_with_progress "Fast Port Scanning (naabu)" "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    # Crear carpeta de configuración de naabu si no existe
    mkdir -p $HOME/.config/naabu
    wget -q https://raw.githubusercontent.com/projectdiscovery/naabu/master/resources/ports.txt -O $HOME/.config/naabu/ports.txt
fi

# BONUS: DNS brute resolver
check_tool "dnsx"
if [ $? -eq 0 ]; then
    install_with_progress "DNS brute resolver (dnsx)" "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    # Descargar listas de DNS para resolver subdominios
    mkdir -p $HOME/.config/dnsx
    wget -q https://raw.githubusercontent.com/projectdiscovery/dnsx/master/resources/dnsbrute.txt -O $HOME/.config/dnsx/dnsbrute.txt
fi

# BONUS: Vulnerability scanner based on templates
check_tool "nuclei"
if [ $? -eq 0 ]; then
    install_with_progress "Vulnerability scanner based on templates (nuclei)" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    # Descargar plantillas de vulnerabilidad para Nuclei
    mkdir -p $HOME/.config/nuclei-templates
    wget -q https://github.com/projectdiscovery/nuclei-templates/archive/master.zip -O $HOME/.config/nuclei-templates/master.zip
    unzip -o $HOME/.config/nuclei-templates/master.zip -d $HOME/.config/nuclei-templates
fi

# BONUS: Advanced web crawler
check_tool "katana"
if [ $? -eq 0 ]; then
    install_with_progress "Advanced web crawler (katana)" "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    # Descargar listas predeterminadas de URLs para el crawler
    mkdir -p $HOME/.config/katana
    wget -q https://raw.githubusercontent.com/projectdiscovery/katana/master/resources/urls.txt -O $HOME/.config/katana/urls.txt
fi

# -----------------------------
#   Forensics and Information Gathering Tools
# -----------------------------

# Sherlock - Find usernames across social media platforms
check_tool "sherlock"
if [ $? -eq 0 ]; then
    install_with_progress "Sherlock (find usernames)" "go install github.com/sherlock-project/sherlock@latest"
    # Descargar listas de redes sociales si es necesario
    mkdir -p $HOME/.config/sherlock
    wget -q https://raw.githubusercontent.com/sherlock-project/sherlock/master/resources/networks.txt -O $HOME/.config/sherlock/networks.txt
fi

# GitLeaks - Detect secrets in git repos
check_tool "gitleaks"
if [ $? -eq 0 ]; then
    install_with_progress "GitLeaks (detect secrets in git repos)" "go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest"
    # No se requiere lista externa, ya que GitLeaks usa los repositorios directamente.
fi

# Social-Engineer Toolkit - Exploiting social engineering vulnerabilities
check_tool "setoolkit"
if [ $? -eq 0 ]; then
    install_with_progress "Social-Engineer Toolkit (SET)" "go install github.com/trustedsec/social-engineer-toolkit/SET@latest"
    # Descargar configuraciones para ataques sociales
    mkdir -p $HOME/.config/setoolkit
    wget -q https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/resources/config.txt -O $HOME/.config/setoolkit/config.txt
fi

# -----------------------------
#   Finalización
# -----------------------------

# Mensaje de éxito
echo "----------------------------------------"
echo "[+] ¡Todo ha sido instalado con éxito!"
echo "[+] Si algún binario no funciona, asegúrate de tener esto en tu ~/.zshrc:"
echo 'export PATH=$PATH:$HOME/go/bin'
echo "----------------------------------------"
echo "[+] ¡Disfruta de tu nuevo entorno de pentesting, forensics y bug bounty!"
echo "----------------------------------------"
