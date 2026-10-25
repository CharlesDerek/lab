#!/usr/bin/env python3
"""Deterministic acknowledgment ordering checks; no fanotify or host changes."""
import contextlib
import importlib.util
from pathlib import Path
import queue
import struct
import threading
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    'native_read_barrier', Path(__file__).with_name('native_read_barrier.py'))
BARRIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BARRIER)


def state():
    barrier = BARRIER.ReadBarrier.__new__(BARRIER.ReadBarrier)
    barrier.owner = (999, 1)
    barrier.denied = 0
    barrier.allowed = 0
    barrier.error = None
    barrier.changed = threading.Condition()
    barrier.finished = False
    barrier.stop = threading.Event()
    barrier.fd = 1
    barrier.thread = types.SimpleNamespace(is_alive=lambda: True)
    return barrier


@contextlib.contextmanager
def worker(barrier, write):
    delivered = False
    event = struct.pack('=IBBHQii', 24, 3, 0, 24, 0x10000, 123, 42)

    def select(*_args):
        nonlocal delivered
        if not delivered:
            delivered = True
            return [1], [], []
        barrier.stop.wait(.01)
        return [], [], []

    fake_os = types.SimpleNamespace(read=lambda *_: event, write=write, close=lambda _: None)
    fake_select = types.SimpleNamespace(select=select)
    with mock.patch.object(BARRIER, 'os', fake_os), mock.patch.object(BARRIER, 'select', fake_select):
        barrier.thread = threading.Thread(target=barrier._run)
        barrier.thread.start()
        try:
            yield
        finally:
            barrier.stop.set()
            barrier.thread.join(timeout=2)
            if barrier.thread.is_alive():
                raise AssertionError('Synthetic barrier worker did not finish')


class ReadBarrierAcknowledgmentTests(unittest.TestCase):
    def test_kernel_response_can_precede_counter_but_wait_requires_published_ack(self):
        barrier = state()
        response_sent = threading.Event()
        resume_worker = threading.Event()
        waiting = threading.Event()
        completed = queue.Queue()

        class Condition(threading.Condition):
            def wait(self, timeout=None):
                waiting.set()
                return super().wait(timeout)

        barrier.changed = Condition()

        def write(_fd, response):
            self.assertEqual(struct.unpack('=iI', response), (123, 2))
            response_sent.set()
            if not resume_worker.wait(2):
                raise AssertionError('Synthetic response release timed out')
            return len(response)

        def wait():
            try:
                barrier.wait_for_denial(0, timeout=1)
                completed.put(None)
            except BaseException as error:
                completed.put(error)

        with worker(barrier, write):
            waiter = threading.Thread(target=wait)
            try:
                self.assertTrue(response_sent.wait(1))
                self.assertEqual(barrier.denial_count(), 0)
                waiter.start()
                self.assertTrue(waiting.wait(1))
                self.assertTrue(completed.empty())
                resume_worker.set()
                waiter.join(timeout=1)
                self.assertFalse(waiter.is_alive())
                self.assertIsNone(completed.get_nowait())
                self.assertEqual(barrier.denial_count(), 1)
            finally:
                resume_worker.set()
                if waiter.ident is not None:
                    waiter.join(timeout=2)

    def test_missing_acknowledgment_still_times_out(self):
        barrier = state()
        with self.assertRaisesRegex(AssertionError, 'acknowledgment timed out'):
            barrier.wait_for_denial(0, timeout=.01)
        self.assertEqual(barrier.denied, 0)

    def test_incomplete_response_never_counts_as_denial(self):
        barrier = state()
        with worker(barrier, lambda _fd, response: len(response) - 1):
            with self.assertRaisesRegex(RuntimeError, 'Read barrier stopped'):
                barrier.wait_for_denial(0, timeout=1)
            self.assertEqual(barrier.denied, 0)

    def test_failed_response_never_counts_as_denial(self):
        barrier = state()

        def fail(*_args):
            raise OSError('Synthetic response failure')

        with worker(barrier, fail):
            with self.assertRaisesRegex(RuntimeError, 'Read barrier stopped'):
                barrier.wait_for_denial(0, timeout=1)
            self.assertEqual(barrier.denied, 0)

    def test_counter_advance_cannot_hide_barrier_failure(self):
        barrier = state()
        barrier.denied = 1
        barrier.error = RuntimeError('Synthetic barrier failure')
        with self.assertRaisesRegex(RuntimeError, 'Read barrier stopped'):
            barrier.wait_for_denial(0, timeout=.01)

    def test_finished_worker_cannot_supply_healthy_acknowledgment(self):
        barrier = state()
        barrier.denied = 1
        barrier.finished = True
        with self.assertRaisesRegex(RuntimeError, 'Read barrier stopped'):
            barrier.wait_for_denial(0, timeout=.01)


if __name__ == '__main__':
    unittest.main()
