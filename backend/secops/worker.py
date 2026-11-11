import os
from celery import Celery
from .events import now
from .safe_logging import configure

configure()

celery = Celery("secops", broker=os.environ.get("BROKER_URL", "redis://redis:6379/0"))
celery.conf.update(task_serializer="json", accept_content=["json"], result_serializer="json",
    task_acks_late=True, task_reject_on_worker_lost=True, worker_prefetch_multiplier=1,
    task_soft_time_limit=90, task_time_limit=120, broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 180}, task_ignore_result=True,
    beat_schedule={"drain-durable-outbox": {"task": "secops.drain", "schedule": 5.0}},
    worker_hijack_root_logger=False, worker_send_task_events=False)


@celery.task(name="secops.drain")
def drain():
    from .runtime import build
    _, db, service = build()
    with db.transaction() as tx:
        tx.execute("INSERT INTO worker_health VALUES ('scheduler',?) ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen", (now(),))
    for _ in range(100):
        if not service.process_one():
            break
