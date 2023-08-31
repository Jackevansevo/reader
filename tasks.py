from celery import Celery
from celery.schedules import crontab
from reader import make_reader
import os

app = Celery(
    "hello",
    broker=os.environ.get("REDIS_URL", "redis://"),
    beat_schedule={
        "update-feeds-every-10-minutes": {
            "task": "tasks.update_feeds",
            "schedule": crontab(minute=10),
        },
        "ping-every-minute": {
            "task": "tasks.ping",
            "schedule": crontab(),
        },
    },
)


@app.task
def ping():
    return "pong"


@app.task()
def update_feeds():
    with make_reader("db.sqlite") as reader:
        reader.update_feeds()
