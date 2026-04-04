"""In-memory registry for tracking background asyncio tasks."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

@dataclass
class TaskInfo:
    task_id: str
    name: str
    status: str  # pending, running, completed, failed
    started_at: float
    completed_at: float | None = None
    error: str | None = None

_tasks: dict[str, TaskInfo] = {}
_MAX_HISTORY = 100  # Keep last N completed tasks
_CLEANUP_AGE_SECONDS = 3600  # Remove completed tasks older than 1 hour

def _cleanup():
    """Remove old completed/failed tasks."""
    now = time.time()
    to_remove = [
        tid for tid, info in _tasks.items()
        if info.status in ("completed", "failed")
        and info.completed_at
        and (now - info.completed_at) > _CLEANUP_AGE_SECONDS
    ]
    for tid in to_remove:
        del _tasks[tid]

def register_task(name: str) -> str:
    """Register a new task. Returns task_id."""
    _cleanup()
    task_id = str(uuid4())[:8]
    _tasks[task_id] = TaskInfo(task_id=task_id, name=name, status="running", started_at=time.time())
    return task_id

def complete_task(task_id: str):
    """Mark a task as completed."""
    if task_id in _tasks:
        _tasks[task_id].status = "completed"
        _tasks[task_id].completed_at = time.time()

def fail_task(task_id: str, error: str):
    """Mark a task as failed."""
    if task_id in _tasks:
        _tasks[task_id].status = "failed"
        _tasks[task_id].completed_at = time.time()
        _tasks[task_id].error = error[:500]

def get_active_tasks() -> list[dict]:
    """Get all tasks (active and recent completed)."""
    _cleanup()
    return [
        {
            "task_id": info.task_id,
            "name": info.name,
            "status": info.status,
            "started_at": datetime.fromtimestamp(info.started_at).isoformat(),
            "completed_at": datetime.fromtimestamp(info.completed_at).isoformat() if info.completed_at else None,
            "error": info.error,
            "duration_seconds": round((info.completed_at or time.time()) - info.started_at, 1),
        }
        for info in _tasks.values()
    ]

def get_summary() -> dict:
    """Get summary counts."""
    _cleanup()
    running = sum(1 for t in _tasks.values() if t.status == "running")
    completed = sum(1 for t in _tasks.values() if t.status == "completed")
    failed = sum(1 for t in _tasks.values() if t.status == "failed")
    return {"running": running, "completed_recent": completed, "failed_recent": failed, "total_tracked": len(_tasks)}

async def tracked_task(name: str, coro) -> asyncio.Task:
    """Create an asyncio task with tracking. Returns the asyncio.Task."""
    task_id = register_task(name)

    async def _wrapper():
        try:
            result = await coro
            complete_task(task_id)
            return result
        except Exception as e:
            fail_task(task_id, str(e))
            logger.error(f"Background task '{name}' ({task_id}) failed: {e}")
            raise

    return asyncio.create_task(_wrapper())
