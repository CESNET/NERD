# -*- mode: ruby -*-
# vi: set ft=ruby :

###############################################################################
# This Vagrantfile creates a VM and installs and configures all dependencies
# needed to run NERD.
# It's intended for development/debugging, so there are some differences from
# produciton dpeloyment:
# - Web interface doesn't use any authentication, full access is automatically
#   granted.
# - Web interface is available only via plain HTTP.
# - NERDd must be started manually.
# - Warden data must be copied from somewhere (or warden_receiver registered 
#   and started manually)
#
###############################################################################

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.


##### Disable SELinux #####
# (Of course it would be better to configure everything correctly, but currently
# I don't have time to learn everything needed)

$selinux = <<EOF

echo "** Disabling SELinux **"
# Disable for now (until reboot)
setenforce 0
# Disable permanently
sed -i --follow-symlinks -e 's/^SELINUX=.*$/SELINUX=disabled/' /etc/sysconfig/selinux

EOF

##### Create testing users #####

$users = <<EOF

echo "=============== Create testing user accounts ==============="
cd / # to prevent "could not change directory to /home/vagrant"
sudo -u nerd psql nerd_users -c "
  INSERT INTO users (id,groups,name,email) VALUES ('devel:devel_admin','{\"admin\",\"registered\"}','Mr. Developer','test@example.org') ON CONFLICT DO NOTHING;\
  INSERT INTO users (id,groups,name,email) VALUES ('local:test','{\"registered\"}','Mr. Test','test@example.org') ON CONFLICT DO NOTHING;\
"
# Set password for local test user
htpasswd -bc /etc/nerd/htpasswd test test
chown apache:nerd /etc/nerd/htpasswd
chmod 660 /etc/nerd/htpasswd

EOF

##### Final notes #####

$notes = <<EOF
echo
echo "**********************************************************************"
echo "System is NOT FULLY PROVISIONED, yet."
echo "The following steps should be done manually now:"
echo " 1. See the logs above for potential error messages."
echo " 2. (optional, needed to receive data form Warden) Register Warden client, configure and run warden_filer (see above)."
echo " 3. Download geolocation database using /nerd/scripts/download_maxmind_geolite.sh (free registration at maxmind.com is needed)."
echo " 4. Run backend (NERDd):"
echo "      sudo systemctl start nerd-supervisor"
echo ""
echo "Backend can be managed via supervisord interface ('nerdctl' or https://localhost:9100/)"
echo ""
echo "Frontend is running at https://<this_server>/nerd/"
echo "Two user accounts for testing are available:"
echo "* Administrator/developer - use 'Devel. autologin' option"
echo "* Unprivileged local account - username/password: test/test"
echo ""

EOF

##########


Vagrant.configure(2) do |config|
  config.vm.box = "centos/7"
  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: '127.0.0.1' # Main web server (NERDweb)
  config.vm.network "forwarded_port", guest: 15672, host: 15672, host_ip: '127.0.0.1' # RabbitMQ management web interface
  config.vm.network "forwarded_port", guest: 9001, host: 9001, host_ip: '127.0.0.1' # Supervisor web interface
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end

  # Mark that this is a development Vagrant VM machine (some scripts look for this file)
  config.vm.provision "shell", inline: "touch /vagrant/vagrant_provisioning"

  # Disable SELinux
  config.vm.provision "shell", inline: $selinux
  
  # Copy installation files
  config.vm.provision "file", source: "install", destination: "/tmp/nerd_install"
  config.vm.provision "file", source: "common", destination: "/tmp/nerd_install/nerd/common"
  config.vm.provision "file", source: "NERDd", destination: "/tmp/nerd_install/nerd/NERDd"
  config.vm.provision "file", source: "NERDweb", destination: "/tmp/nerd_install/nerd/NERDweb"
  config.vm.provision "file", source: "scripts", destination: "/tmp/nerd_install/nerd/scripts"
  config.vm.provision "file", source: "etc", destination: "/tmp/nerd_install/etc"
  # Convert line-endings in files copied from windows
  config.vm.provision "shell", inline: "yum install -y -q dos2unix ; find /tmp/nerd_install/ -type f -exec dos2unix -q {} ';'"
  config.vm.provision "shell", inline: "chmod +x /tmp/nerd_install/*.sh /tmp/nerd_install/nerd/scripts/*.sh"

  # Prepare users, directories, etc.
  config.vm.provision "shell", inline: "/tmp/nerd_install/prepare_environment.sh"

  # Allow vagrant user to write into nerd directories (add it to "nerd" group)
  config.vm.provision "shell", inline: "usermod -a -G nerd vagrant"

  # Copy program files and configuration
  config.vm.provision "shell", inline: "sudo -u nerd sh -c 'cp -R /tmp/nerd_install/nerd/* /nerd/ ; chmod -R g+w /nerd/'"
  config.vm.provision "shell", inline: "sudo -u nerd sh -c 'cp -R /tmp/nerd_install/etc/* /etc/nerd/ ; chmod -R g+w /etc/nerd/'"

  # Install necessary programs, libraries and services and run them
  config.vm.provision "shell", inline: "/tmp/nerd_install/install_basic_dependencies.sh"

  # Configure various services
  config.vm.provision "shell", inline: "/tmp/nerd_install/configure_mongo.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/configure_postgres.sh --warden"
  config.vm.provision "shell", inline: "/tmp/nerd_install/configure_rabbitmq.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/install_configure_bind.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/configure_apache.sh -d /nerd" # install to /nerd, enable debug/development mode
  config.vm.provision "shell", inline: "/tmp/nerd_install/install_warden_filer.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/install_configure_munin.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/download_data_files.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/configure_cron.sh"
  config.vm.provision "shell", inline: "/tmp/nerd_install/configure_supervisor.sh open" # open mgmt port on all interfaces so it's possible to connect from host

  # Create testing users  
  config.vm.provision "shell", inline: $users

  config.vm.provision "shell", inline: "rm /vagrant/vagrant_provisioning"

  # Print final notes
  config.vm.provision "shell", inline: $notes
end