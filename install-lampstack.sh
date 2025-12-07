#!/bin/bash

# Define variables
phpVersion=8.3
scriptUrl="https://r.chieldemmer.nl"
nginxInstallScript="install-nginx.sh"
mariadbInstallScript="install-mariadb.sh"

# Install nginx
#TODO: Fix wget $nginxInstallScript
apt update
apt install nginx -y

# Install php-fpm for nginx
apt install "php$phpVersion-fpm" -y

# Install mariadb
wget "$scriptUrl/$mariadbInstallScript" 
# bash install-mariadb.sh