.PHONY: setup run seed test deploy backup migrate

# First-time setup: create venv, install deps, copy env
setup:
	python3 -m venv venv
	./venv/bin/pip install -r requirements.txt
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from .env.example — edit it with your config"; fi
	@echo "Setup complete. Run: make run"

# Run the dev server
run:
	FLASK_DEBUG=1 ./venv/bin/python app.py

# Run with gunicorn (production-like)
run-prod:
	./venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 --timeout 30 app:app

# Seed demo data
seed:
	./venv/bin/python seed.py

# Run tests
test:
	./venv/bin/pytest tests/ -v

# Run migrations (handled automatically on boot, but can be triggered manually)
migrate:
	./venv/bin/python -c "from app import init_db; init_db()"

# Backup the database
backup:
	@mkdir -p backups
	cp data/app.db "backups/app-$$(date +%Y%m%d-%H%M%S).db"
	@echo "Backup saved to backups/"

# Deploy to production (assumes SSH access configured)
deploy:
	@echo "Deploying to production..."
	ssh root@YOUR_SERVER_IP "cd /root/YOUR_APP && git pull origin main && source venv/bin/activate && pip install -r requirements.txt -q && systemctl restart YOUR_APP"
	@echo "Deployed!"
