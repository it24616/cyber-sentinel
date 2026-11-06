import os
from dotenv import load_dotenv

load_dotenv()

bind = f"{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '5000')}"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", "4"))
timeout = 30
graceful_timeout = 30
preload_app = True  # Run schema initialization once in the master before workers fork.
accesslog = "-"
errorlog = "-"
