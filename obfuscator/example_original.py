import asyncio
from datetime import datetime


class TaskManager:

    MAX_TASKS = 50
    VERSION = "1.0.0"

    def __init__(self, owner: str):
        self.owner = owner
        self.tasks = []
        self.completed = 0
        self._secret_key = "super_secret_api_key_12345"

    async def add_task(self, name: str, priority: int = 1) -> bool:
        if len(self.tasks) >= self.MAX_TASKS:
            print(f"Task limit reached: {self.MAX_TASKS}")
            return False

        task = {
            "name": name,
            "priority": priority,
            "created_at": datetime.now().isoformat(),
            "done": False,
        }
        self.tasks.append(task)
        print(f"[{self.owner}] Added task: {name} (priority={priority})")
        return True

    async def run_all(self):
        pending = [t for t in self.tasks if not t["done"]]
        sorted_tasks = sorted(pending, key=lambda x: x["priority"], reverse=True)

        for task in sorted_tasks:
            await self._execute(task)

    async def _execute(self, task: dict):
        await asyncio.sleep(0.01)   
        task["done"] = True
        self.completed += 1
        print(f"  ✓ Completed: {task['name']}")

    def stats(self) -> dict:
        total = len(self.tasks)
        done = sum(1 for t in self.tasks if t["done"])
        return {
            "owner": self.owner,
            "total": total,
            "done": done,
            "pending": total - done,
            "completion_rate": round(done / total * 100, 1) if total else 0.0,
        }


async def main():
    mgr = TaskManager(owner="Alice")
    await mgr.add_task("Write report", priority=3)
    await mgr.add_task("Send emails", priority=2)
    await mgr.add_task("Update docs", priority=1)
    await mgr.run_all()
    print("Stats:", mgr.stats())


if __name__ == "__main__":
    asyncio.run(main())
