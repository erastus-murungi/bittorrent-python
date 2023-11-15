import heapq
import logging
import sys
from typing import TypeVar

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s:%(levelname)s: %(message)s",
    stream=sys.stderr,
)


def log(message: str) -> None:
    # logging.info(message)
    # print(message, file=sys.stderr)
    return None


T = TypeVar("T")


class Heap(list[T]):
    def __init__(self):
        super().__init__()
        self.entry_finder = {}  # mapping of tasks to entries
        self.REMOVED = "<removed-task>"  # placeholder for a removed task
        self.counter = 0  # unique sequence count

    def enqueue(self, task: T, priority: float = 0):
        if task in self.entry_finder:
            self.delete(task)
        entry = [priority, task]
        self.entry_finder[task] = entry
        heapq.heappush(self, entry)
        self.counter += 1

    def delete(self, task: T):
        entry = self.entry_finder.pop(task)
        entry[-1] = self.REMOVED
        self.counter -= 1

    def remove(self, __value):
        raise NotImplementedError

    def dequeue(self) -> tuple[float, T]:
        while self:
            priority, task = heapq.heappop(self)
            if task is not self.REMOVED:
                del self.entry_finder[task]
                self.counter -= 1
                return priority, task
        raise KeyError("pop from an empty priority queue")

    def __len__(self):
        return self.counter


if __name__ == "__main__":
    heap = Heap()

    heap.enqueue("task1", 1)
    heap.enqueue("task2", 2)
    heap.enqueue("task3", 3)
    heap.enqueue("task4", 4)
    heap.enqueue("task5", 5)
    heap.enqueue("task6", 6)

    heap.delete("task3")
    while heap:
        print(heap.dequeue())
