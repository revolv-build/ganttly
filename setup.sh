#!/bin/bash
# First-time server setup script
# Run on a fresh Ubuntu server: bash setup.sh
#
# Prerequisites: Ubuntu 22.04+, root access, domain pointing to server IP
#
# Usage:
#   bash setup.sh YOUR_APP_NAME YOUR_DOMAIN YOUR_PORT
#   Example: bash setup.sh myapp myapp.example.com 5000

set -e

APP_NAME="${1:-myapp}"
DOMAIN="${2:-example.com}"
PORT="${3:-5000}"
APP_DIR="/root/$APP_NAME"

echo "Setting up $APP_NAME at $APP_DIR"
echo "Domain: $DOMAIN, Port: $PORT"
echo ""

# System packages
echo "Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx certbot python3-certbot-nginx git

# App setup
echo "Setting up Python environment..."
cd "$APP_DIR"
python3 -m venv venv
./venv/bin/pip install -r requirements.txt -q

# Create .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/change-me-in-production/$SECRET_KEY/" .env
    sed -i "s/FLASK_ENV=development/FLASK_ENV=production/" .env
    echo "Created .env with generated secret key"
fi

# systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/$APP_NAME.service << EOF
[Unit]
Description=$APP_NAME Flask Application
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=FLASK_ENV=production
ExecStart=$APP_DIR/venv/bin/gunicorn -w 4 -b 127.0.0.1:$PORT --timeout 30 --keep-alive 5 --access-logfile /var/log/$APP_NAME.log app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $APP_NAME
systemctl start $APP_NAME

# Nginx
echo "Configuring Nginx..."
cat > /etc/nginx/sites-available/$APP_NAME << EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /uploads/ {
        alias $APP_DIR/uploads/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    location /static/ {
        alias $APP_DIR/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
        gzip_static on;
    }

    client_max_body_size 50M;
}
EOF

ln -sf /etc/nginx/sites-available/$APP_NAME /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx

echo ""
echo "Setup complete!"
echo "  App running at: http://$DOMAIN"
echo "  Service: systemctl status $APP_NAME"
echo "  Logs: journalctl -u $APP_NAME -f"
echo ""
echo "Next steps:"
echo "  1. Set up SSL: certbot --nginx -d $DOMAIN"
echo "  2. Update .env with your Resend API key"
echo "  3. Seed demo data: cd $APP_DIR && make seed"
