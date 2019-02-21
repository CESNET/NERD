# Creates a system user and various directories

echo "** Creating user 'nerd' **"

useradd --system --home-dir /nerd --shell /sbin/nologin nerd

echo "** Creating NERD directories and setting up permissions **"

# Code base (executables, scripts, etc.)
mkdir -p /nerd
chown nerd:nerd /nerd

# Configuration directory
mkdir -p /etc/nerd
chown nerd:nerd /etc/nerd

# Log directory
mkdir -p /var/log/nerd
chown nerd:nerd /var/log/nerd

# Data directory
mkdir -p /data
chown nerd:nerd /data

# local_bl plugin stores data into /data/local_bl  # TODO: should modules be handled in the main installation script?
mkdir -p /data/local_bl
chown -R nerd:nerd /data/local_bl




