"""Nonblocking, process-local inference admission."""

from threading import BoundedSemaphore


class AdmissionGate:
    def __init__(self, limit=2):
        if type(limit) is not int or not 1 <= limit <= 8:
            raise ValueError("Admission limit must be an integer from 1 to 8")
        self.limit = limit
        self._slots = BoundedSemaphore(limit)

    def try_acquire(self):
        return self._slots.acquire(blocking=False)

    def release(self):
        self._slots.release()