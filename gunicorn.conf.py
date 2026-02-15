import os

workers = int(os.environ.get('GUNICORN_WORKERS', 4))
bind = f"0.0.0.0:{os.environ.get('PORT', 10000)}"
timeout = 120
