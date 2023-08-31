web: gunicorn -b 0.0.0.0:8080 app:app
celery: celery -A tasks worker --loglevel=INFO --concurrency=1 -B
