#!/usr/bin/env bash

echo -e "\033[1;33m##### Package: Update \033[0m"
apt --assume-yes update

echo -e "\033[1;33m##### Package: Upgrade \033[0m"
apt --assume-yes upgrade

echo -e "\033[1;33m##### Package: Install \033[0m"
apt install --assume-yes curl wget vim tree net-tools zsh qemu-guest-agent

echo -e "\033[1;33m##### Package: Cleaning \033[0m"
apt --assume-yes autoremove
apt --assume-yes autoclean

echo -e "\033[1;33m##### Installing Oh-My-Zsh \033[0m"
sh -c "$(wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"

echo -e "\033[1;33m##### Customizing .zshrc \033[0m"
cat <<EOL >> ~/.zshrc
autoload -U colors && colors
PROMPT='%{\$fg_bold[green]%}%n@%m %{\$fg_bold[blue]%}%1~ %{\$reset_color%}%# '
EOL

echo -e "\033[1;33m##### Golden: Installation complete \033[0m"

echo -e "\033[1;33m##### Switching to Zsh \033[0m"
chsh -s $(which zsh)

echo -e "\033[1;33m##### Reboot \033[0m"
# shutdown -r now
