#!/bin/bash

#.bashrc
sed -i  's/ls -alF/ls -hlF/g' .bashrc

cd /root

#.vimrc and .vim
rm -fr .vimrc .vim
webserver=9.111.251.179
wget http://$webserver/.vimrc
wget http://$webserver/vim.tar.gz
tar xf vim.tar.gz 

rm -fr vim.tar.gz
rm -fr /etc/apt/sources.list.d/* docker.list kubernetes.list

apt -y update
apt -y install apt-transport-https ca-certificates curl gnupg-agent software-properties-common

#docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg  | apt-key add -
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

#k8s
curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg 
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main"  > /etc/apt/sources.list.d/kubernetes.list


apt -y update
apt -y install docker-ce docker-ce-cli containerd.io kubelet kubeadm kubectl build-essential golang-1.14
