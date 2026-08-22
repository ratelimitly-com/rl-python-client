import errno
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ratelimitly.steering import (
    STEERING_PORT_MIN,
    bind_next_steering_socket,
    next_steering_port,
)


class FakeSocket:
    def __init__(self, occupied):
        self.occupied = occupied
        self.bound = None
        self.closed = False
        self.options = []

    def setsockopt(self, *option):
        self.options.append(option)

    def setblocking(self, _enabled):
        pass

    def bind(self, address):
        if address[1] == self.occupied:
            raise OSError(errno.EADDRINUSE, "occupied")
        self.bound = address

    def close(self):
        self.closed = True


class SocketFactory:
    def __init__(self, occupied):
        self.occupied = occupied
        self.created = []

    def __call__(self, _family, _kind):
        current = FakeSocket(self.occupied)
        self.created.append(current)
        return current


class TestSteering(unittest.TestCase):
    def test_ports_advance_and_wrap(self):
        self.assertEqual(next_steering_port(STEERING_PORT_MIN), STEERING_PORT_MIN + 1)
        self.assertEqual(next_steering_port(65534), 65535)
        self.assertEqual(next_steering_port(65535), STEERING_PORT_MIN)
        self.assertEqual(next_steering_port(40000), STEERING_PORT_MIN)

    def test_occupied_candidate_is_closed_and_skipped(self):
        factory = SocketFactory(60000)
        current, selected, following = bind_next_steering_socket(
            socket.AF_INET,
            60000,
            factory,
        )
        self.assertEqual(selected, 60001)
        self.assertEqual(following, 60002)
        self.assertIs(current, factory.created[1])
        self.assertTrue(factory.created[0].closed)
        self.assertEqual(current.bound, ("0.0.0.0", 60001))

    def test_real_specific_address_candidate_is_skipped(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        occupied = None
        for candidate in range(STEERING_PORT_MIN, 65_536):
            try:
                blocker.bind(("127.0.0.1", candidate))
            except OSError as error:
                if error.errno in (errno.EADDRINUSE, errno.EACCES):
                    continue
                raise
            occupied = candidate
            break
        self.assertIsNotNone(occupied)
        try:
            current, selected, following = bind_next_steering_socket(
                socket.AF_INET,
                occupied,
            )
            try:
                self.assertNotEqual(selected, occupied)
                self.assertEqual(following, next_steering_port(selected))
                if os.name == "nt":
                    self.assertEqual(
                        current.getsockopt(
                            socket.SOL_SOCKET,
                            socket.SO_EXCLUSIVEADDRUSE,
                        ),
                        1,
                    )
            finally:
                current.close()
        finally:
            blocker.close()

    @unittest.skipUnless(os.name == "nt", "Windows bind-isolation regression")
    def test_windows_wildcard_bind_is_exclusive(self):
        current, _selected, _following = bind_next_steering_socket(
            socket.AF_INET,
            STEERING_PORT_MIN,
        )
        try:
            self.assertEqual(
                current.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE),
                1,
            )
        finally:
            current.close()


if __name__ == "__main__":
    unittest.main()
