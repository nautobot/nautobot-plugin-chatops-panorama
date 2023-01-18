#!/usr/bin/env bash

if [[ ! -f "/code/development/creds.env" ]]; then
    echo "No creds.env was found in development folder!!" 1>&2
    exit 125
fi

# update packages
sudo apt-get update
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    python3-pip \
    python3-venv
export PATH="$PATH:$HOME/.local/bin"
python3 -m pip install --upgrade pip
pip install pipx

# skeleton files
cp /etc/skel/.* $HOME/

# docker
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update 
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo curl -SL https://github.com/docker/compose/releases/download/v2.15.1/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
sudo usermod -aG docker $USER
sudo chown $USER:docker /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo systemctl enable docker.service containerd.service
sudo systemctl start docker.service containerd.service
sudo chown $USER:docker /var/run/docker.sock

# install poetry
echo "Installing poetry. This may take a while."
pipx install poetry
pipx ensurepath

# source bashrc
source $HOME/.bashrc

# bash completions
poetry completions bash >> ~/.bash_completion

# install development environment
cd /code
poetry install
poetry lock
cd /code/nautobot_plugin_chatops_panorama
# activate poetry shell
source $(poetry env info --path)/bin/activate
invoke build
invoke setup-mattermost
invoke start
