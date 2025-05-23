#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Installing tallow_rust..."

# Define installation paths
SBIN_DIR="/usr/sbin"
MAN_DIR="/usr/share/man"
CONFIG_DIR="/etc/tallow"
SERVICE_DIR="/lib/systemd/system" # Common for packaged services, /etc/systemd/system for local admin overrides
PATTERNS_INSTALL_DIR="$CONFIG_DIR/patterns" # This is where the files will actually be installed
# PATTERNS_DIR_CONFIG_VAL in tallow.toml defaults to /etc/tallow/patterns, matching PATTERNS_INSTALL_DIR

# Ensure pandoc is installed
if ! command -v pandoc &> /dev/null
then
    echo "pandoc could not be found. Please install pandoc to continue."
    echo "For example, on Debian/Ubuntu: sudo apt-get install pandoc"
    exit 1
fi

# Compile the Rust project
echo "Building tallow_rust release binary..."
if ! cargo build --release; then
    echo "Cargo build failed. Exiting."
    exit 1
fi
echo "Build successful."

# Create target directories
echo "Creating target directories..."
sudo mkdir -p "$SBIN_DIR" \
             "$MAN_DIR/man1" \
             "$MAN_DIR/man5" \
             "$PATTERNS_INSTALL_DIR" \
             "$SERVICE_DIR"

# Install the binary
echo "Installing tallow_rust binary to $SBIN_DIR..."
sudo cp target/release/tallow_rust "$SBIN_DIR/tallow_rust"

# Install man pages
echo "Installing man pages to $MAN_DIR..."
if [ -f "man/tallow_rust.1.md" ]; then
    sudo pandoc -s -f markdown -t man man/tallow_rust.1.md -o "$MAN_DIR/man1/tallow_rust.1"
else
    echo "Warning: man/tallow_rust.1.md not found."
fi
if [ -f "man/tallow_rust.conf.5.md" ]; then
    sudo pandoc -s -f markdown -t man man/tallow_rust.conf.5.md -o "$MAN_DIR/man5/tallow_rust.conf.5"
else
    echo "Warning: man/tallow_rust.conf.5.md not found."
fi
if [ -f "man/tallow_rust.patterns.5.md" ]; then
    sudo pandoc -s -f markdown -t man man/tallow_rust.patterns.5.md -o "$MAN_DIR/man5/tallow_rust.patterns.5"
else
    echo "Warning: man/tallow_rust.patterns.5.md not found."
fi

# Install default config (only if it doesn't exist)
CONFIG_FILE_PATH="$CONFIG_DIR/tallow.toml"
if [ ! -f "$CONFIG_FILE_PATH" ]; then
    echo "Installing default configuration to $CONFIG_FILE_PATH..."
    if [ -f "data/default_tallow.toml" ]; then
        sudo cp data/default_tallow.toml "$CONFIG_FILE_PATH"
    else
        echo "Warning: data/default_tallow.toml not found."
    fi
else
    echo "Configuration file $CONFIG_FILE_PATH already exists. Skipping default config installation."
fi

# Install pattern files
echo "Installing pattern files to $PATTERNS_INSTALL_DIR..."
if [ -f "data/sshd.json" ]; then
    sudo cp data/sshd.json "$PATTERNS_INSTALL_DIR/sshd.json"
else
    echo "Warning: data/sshd.json not found."
fi
if [ -f "data/dovecot.json" ]; then
    sudo cp data/dovecot.json "$PATTERNS_INSTALL_DIR/dovecot.json"
else
    echo "Warning: data/dovecot.json not found."
fi

# Install systemd service file
SERVICE_FILE_PATH="$SERVICE_DIR/tallow_rust.service"
echo "Installing systemd service file to $SERVICE_FILE_PATH..."
if [ -f "data/tallow_rust.service" ]; then
    sudo cp data/tallow_rust.service "$SERVICE_FILE_PATH"
    echo "Replacing @SBINDIR@ with $SBIN_DIR in $SERVICE_FILE_PATH..."
    sudo sed -i "s|@SBINDIR@|$SBIN_DIR|g" "$SERVICE_FILE_PATH"
else
    echo "Warning: data/tallow_rust.service not found."
fi

echo "Installation complete."
echo ""
echo "Next steps:"
echo "1. Reload systemd: sudo systemctl daemon-reload"
echo "2. Enable and start the service: sudo systemctl enable --now tallow_rust"
echo "3. Check service status: sudo systemctl status tallow_rust"
echo "4. Review configuration in $CONFIG_DIR/tallow.toml and patterns in $PATTERNS_INSTALL_DIR"

# Make the script executable (though this is usually done by the user after downloading)
chmod +x install.sh
echo "install.sh is now executable."
