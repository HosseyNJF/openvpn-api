import contextlib
import logging
import re
from collections import defaultdict

import select
import socket
import queue
import threading
from enum import Enum
from typing import Optional, Generator, Callable, Type, TypeVar, Dict, List

import openvpn_status
from openvpn_status.models import Status

from openvpn_api import events
from openvpn_api.events import BaseEvent
from openvpn_api.events.updown import UpDownEvent
from openvpn_api.models.state import State
from openvpn_api.models.stats import ServerStats
from openvpn_api.util import errors

logger = logging.getLogger(__name__)


T = TypeVar("T", bound=BaseEvent)

class VPNType(str, Enum):
    IP = "ip"
    UNIX_SOCKET = "socket"


class VPN:
    def __init__(self, host: str = None, port: int = None, unix_socket: str = None, timeout: float = None):
        if (unix_socket and host) or (unix_socket and port) or (not unix_socket and not host and not port):
            raise errors.VPNError("Must specify either socket or host and port")

        self._mgmt_socket: Optional[str] = unix_socket
        self._mgmt_host: Optional[str] = host
        self._mgmt_port: Optional[int] = port
        self._socket: Optional[socket.socket] = None
        self._timeout = timeout

        # Release info cache
        self._release: Optional[str] = None

        # Event system
        self._callbacks: Dict[Type[BaseEvent], List[Callable[[BaseEvent], None]]] = defaultdict(list)
        self._socket_thread: Optional[threading.Thread] = None
        self._stop_thread: threading.Event = threading.Event()
        self._try_reconnecting: threading.Event = threading.Event()
        self._recv_queue: queue.Queue = queue.Queue()
        self._send_queue: queue.Queue = queue.Queue()
        self._internal_rx: Optional[socket.socket] = None
        self._internal_tx: Optional[socket.socket] = None

        self._active_event = None

    @property
    def type(self) -> VPNType:
        """Get VPNType object for this VPN.
        """
        if self._mgmt_socket:
            return VPNType.UNIX_SOCKET
        if self._mgmt_port and self._mgmt_host:
            return VPNType.IP
        raise ValueError("Invalid connection type")

    @property
    def mgmt_address(self) -> str:
        """Get address of management interface.
        """
        if self.type == VPNType.IP:
            return f"{self._mgmt_host}:{self._mgmt_port}"
        else:
            return str(self._mgmt_socket)

    def connect(self) -> Optional[bool]:
        """Connect to management interface socket.
        """
        try:
            if self.type == VPNType.IP:
                assert self._mgmt_host is not None and self._mgmt_port is not None
                self._socket = socket.create_connection((self._mgmt_host, self._mgmt_port), timeout=None)
            elif self.type == VPNType.UNIX_SOCKET:
                assert self._mgmt_socket is not None
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.connect(self._mgmt_socket)
            else:
                raise ValueError("Invalid connection type")

            self._clear_queue(self._recv_queue)
            self._clear_queue(self._send_queue)
            self._internal_rx, self._internal_tx = socket.socketpair()
            self._socket_thread = threading.Thread(target=self._socket_thread_runner, daemon=True, name="vpn-io")
            self._socket_thread.start()

            resp = self._socket_recv()
            assert resp.startswith(">INFO"), "Did not get expected response from interface when opening socket."
            return True
        except (socket.timeout, socket.error) as e:
            raise errors.ConnectError(str(e)) from None

    def disconnect(self, _quit=True) -> None:
        """Disconnect from management interface socket.
        By default will issue the `quit` command to inform the management interface we are closing the connection
        """
        if self._socket is not None:
            if _quit:
                self._socket_send("quit\n")
            assert self._internal_tx is not None and self._internal_rx is not None
            self.stop_event_loop()
            self._clear_sockets()
        elif self._try_reconnecting.is_set():
            self._try_reconnecting.clear()

    def _clear_sockets(self):
        self._internal_rx.close()
        self._internal_tx.close()
        self._socket.close()
        self._socket = None

    @classmethod
    def _clear_queue(cls, q: queue.Queue):
        try:
            while True:
                q.get_nowait()
        except queue.Empty:
            pass

    @property
    def is_connected(self) -> bool:
        """Determine if management interface socket is connected or not.
        """
        return self._socket is not None

    @contextlib.contextmanager
    def connection(self) -> Generator:
        """Create context where management interface socket is open and close when done.
        """
        self.connect()
        try:
            yield
        finally:
            self.disconnect()

    def _socket_thread_runner(self):
        """Thread to handle socket I/O and event callbacks.
        """
        active_event_lines = []
        last_line = None
        internal_break = False
        while not self._stop_thread.is_set() and not internal_break:
            socks, _, _ = select.select((self._socket, self._internal_rx), (), (), self._timeout)

            for sock in socks:
                if sock is self._socket:
                    raw = self._socket.recv(65536).decode("utf-8")

                    # If select.select says the file is ready but there is no data, it means the connection is dropped
                    if not raw:
                        self._clear_sockets()
                        self._try_reconnecting.set()
                        self.raise_event(UpDownEvent(UpDownEvent.DOWN))
                        while self._try_reconnecting.is_set():
                            try:
                                self.connect()
                            except errors.ConnectError:
                                continue
                            self._try_reconnecting.clear()
                            self.raise_event(UpDownEvent(UpDownEvent.UP))
                        internal_break = True
                        break  # Ignore processing send queue because the old socket is disconnected

                    lines = raw.split("\n")  # Sometimes lines are sent bundled up
                    line_count = len(lines)
                    idx = -1
                    while True:
                        idx += 1
                        if idx >= line_count:
                            break

                        line = lines[idx]
                        line = line.strip()

                        if line == "":
                            continue
                        # The last line is usually empty if the data isn't chunked
                        elif idx + 1 == line_count:
                            # The last line is NOT terminated with LF and may be chunked, should append next line to it
                            last_line = line
                            continue

                        # If the new line is a notification itself, we'll know the previous line was a whole
                        if idx == 0 and last_line is not None:
                            if line.startswith('>'):
                                idx -= 1
                                line = last_line  # Process the remaining line before current line
                            else:
                                line = last_line + line
                            last_line = None

                        if self._active_event is None:
                            for event in events.get_event_types():
                                if event.has_begun(line):
                                    logger.debug("Event %s detected", type(event).__name__)
                                    active_event_lines = []
                                    if event.has_ended(line):
                                        logger.debug("Event %s received", type(event).__name__)
                                        self.raise_event(event.parse_raw([line]))
                                    else:
                                        self._active_event = event
                                        active_event_lines.append(line)
                                    break
                            else:
                                self._recv_queue.put(line)
                        else:
                            active_event_lines.append(line)
                            if self._active_event.has_ended(line):
                                logger.debug("Event %s received", type(self._active_event).__name__)
                                self.raise_event(self._active_event.parse_raw(active_event_lines))
                                active_event_lines = []
                                self._active_event = None

                elif sock is self._internal_rx:
                    status = self._internal_rx.recv(1)  # Fetch status code from internal socket
                    if status == b"\x00":  # Send data if OK
                        try:
                            data = self._send_queue.get(block=False)
                            self._socket.sendall(bytes(data, "utf-8"))
                        except queue.Empty:
                            pass

    def _socket_send(self, data) -> None:
        """Convert data to bytes and send to socket.
        """
        if self._socket is None:
            raise errors.NotConnectedError("You must be connected to the management interface to issue commands.")
        self._send_queue.put(data)
        assert self._internal_tx is not None
        self._internal_tx.sendall(b"\x00")  # Wake socket thread to send data

    def _socket_recv(self) -> str:
        """Receive bytes from socket and convert to string.
        """
        if self._socket is None:
            raise errors.NotConnectedError("You must be connected to the management interface to issue commands.")
        return self._recv_queue.get()

    def send_command(self, cmd, blocking=True) -> str:
        """Send command to management interface and fetch response.
        """
        logger.debug("Sending cmd: %r", cmd.strip())
        self._socket_send(cmd + "\n")
        if blocking:
            resp = self._socket_recv()
            if cmd.strip() not in ("load-stats", "signal SIGTERM"):
                while not (resp.strip().endswith("END") or
                           resp.strip().startswith("SUCCESS:") or
                           resp.strip().startswith("ERROR:")):
                    resp += self._socket_recv()
            logger.debug("Cmd response: %r", resp)
            return resp

    def stop_event_loop(self) -> None:
        """Halt the event loop, stops handling of socket communications"""
        self._stop_thread.set()
        self._internal_tx.sendall(b"\x01")  # Wake socket thread to allow it to close
        if self._socket_thread is not None:
            self._socket_thread.join()
            self._socket_thread = None
        self._stop_thread.clear()

    def register_callback(self, event_type: Type[T], callback: Callable[[T], None]) -> None:
        """Register a callback with the event handler for incoming messages.
        Callbacks should be kept as lightweight as possible and not perform any heavy or time consuming computation.
        NEVER send a command inside a callback. instead, add it to your own queue and process it outside the callback.
        TODO: Fix sending command inside callback
        """
        self._callbacks[event_type].append(callback)

    def raise_event(self, event: events.BaseEvent) -> None:
        """Handler for a raised event, calls all registered callables."""
        for func in self._callbacks[event.__class__]:
            try:
                func(event)
            except Exception:  # Ignore exceptions as we want to call the other handlers
                logging.exception("Exception when calling callback")

    # Interface commands and parsing

    def _get_version(self) -> str:
        """Get OpenVPN version from socket.
        """
        raw = self.send_command("version")
        for line in raw.splitlines():
            if line.startswith("OpenVPN Version"):
                return line.replace("OpenVPN Version: ", "")
        raise errors.ParseError("Unable to get OpenVPN version, no matches found in socket response.")

    @property
    def release(self) -> str:
        """OpenVPN release string.
        """
        if self._release is None:
            self._release = self._get_version()
        return self._release

    @property
    def version(self) -> Optional[str]:
        """OpenVPN version number.
        """
        if self.release is None:
            return None
        match = re.search(r"OpenVPN (?P<version>\d+.\d+.\d+)", self.release)
        if not match:
            raise errors.ParseError("Unable to parse version from release string.")
        return match.group("version")

    def get_state(self) -> State:
        """Get OpenVPN daemon state from socket.
        """
        raw = self.send_command("state")
        return State.parse_raw(raw)

    def cache_data(self) -> None:
        """Cached some metadata about the connection.
        """
        _ = self.release

    def clear_cache(self) -> None:
        """Clear cached state data about connection.
        """
        self._release = None

    def send_sigterm(self) -> None:
        """Send a SIGTERM to the OpenVPN process.
        """
        raw = self.send_command("signal SIGTERM")
        if raw.strip() != "SUCCESS: signal SIGTERM thrown":
            raise errors.ParseError("Did not get expected response after issuing SIGTERM.")
        self.disconnect(_quit=False)

    def get_stats(self) -> ServerStats:
        """Get latest VPN stats.
        """
        raw = self.send_command("load-stats")
        return ServerStats.parse_raw(raw)

    def get_status(self) -> Status:
        """Get current status from VPN.

        Uses openvpn-status library to parse status output:
        https://pypi.org/project/openvpn-status/
        """
        raw = self.send_command("status 1")
        return openvpn_status.parse_status(raw)
