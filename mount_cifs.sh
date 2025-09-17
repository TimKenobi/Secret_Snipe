# CIFS Mount Helper Script for SecretSnipe
# This script helps mount authenticated CIFS shares for Docker containers

#!/bin/bash

# Configuration - Update these variables
CIFS_SERVER="shsna1cifs1.stahls.net"
CIFS_SHARE="open"
MOUNT_POINT="/mnt/secretsnipe_monitor"
CREDENTIALS_FILE="/etc/samba/credentials"

# Create mount point
sudo mkdir -p $MOUNT_POINT

# Create credentials file (you'll need to provide username/password)
sudo tee $CREDENTIALS_FILE > /dev/null <<EOF
username=YOUR_DOMAIN_USERNAME
password=YOUR_PASSWORD
domain=YOUR_DOMAIN
EOF

# Set proper permissions
sudo chmod 600 $CREDENTIALS_FILE

# Mount the CIFS share
sudo mount -t cifs //$CIFS_SERVER/$CIFS_SHARE $MOUNT_POINT \
  -o credentials=$CREDENTIALS_FILE,vers=3.0,sec=ntlmssp

echo "CIFS share mounted at $MOUNT_POINT"
echo "You can now use this path in your Docker volume mounts"