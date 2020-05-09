import logging
import queue
import socket
import re
import contextlib
import threading
from typing import Optional, Generator

import openvpn_status  # type: ignore

from openvpn_api import events
from openvpn_api.util import errors
from openvpn_api.models.state import State
from openvpn_api.models.stats import ServerStats

logger = logging.getLogger(__name__)


class VPNType:
    IP = "ip"
    UNIX_SOCKET = "socket"


class VPN:
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, socket: Optional[str] = None):
        if (socket and host) or (socket and port) or (not socket and not host and not port):
            raise errors.VPNError("Must specify either socket or host and port")
        if socket:
            self._mgmt_socket = socket
            self._type = VPNType.UNIX_SOCKET
        else:
            self._mgmt_host = host
            self._mgmt_port = port
            self._type = VPNType.IP
        self._socket = None
        self._socket_file = None
        self._socket_io_lock = threading.Lock()

        self._listener_thread = None
        self._writer_thread = None

        self._recv_queue = queue.Queue()
        self._send_queue = queue.Queue()

        self._active_event = None

        self.clear_cache()  # Initialise release info and daemon state caches

    @property
    def type(self) -> Optional[str]:
        """Get VPNType object for this VPN.
        """
        return self._type

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
                self._socket = socket.create_connection((self._mgmt_host, self._mgmt_port), timeout=None)
            else:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.connect(self._mgmt_socket)

            self._socket_file = self._socket.makefile("r")

            self._listener_thread = threading.Thread(
                target=self._socket_listener_thread, daemon=True, name="mgmt-listener"
            )
            self._writer_thread = threading.Thread(target=self._socket_writer_thread, daemon=True, name="mgmt-writer")

            self._listener_thread.start()
            self._writer_thread.start()

            resp = self._socket_recv()
            assert resp.startswith(">INFO"), "Did not get expected response from interface when opening socket."
            return True
        except (socket.timeout, socket.error) as e:
            raise errors.ConnectError(str(e)) from None

    def disconnect(self, _quit=True) -> None:
        """Disconnect from management interface socket.
        """
        if self._socket is not None:
            if _quit:
                self._socket_send("quit\n")

            self._socket_file.close()
            self._socket.close()
            self._socket = None

    @property
    def is_connected(self) -> bool:
        """Determine if management interface socket is connected or not.
        """
        return self._socket != None

    @contextlib.contextmanager
    def connection(self) -> Generator:
        """Create context where management interface socket is open and close when done.
        """
        self.connect()
        try:
            yield
        finally:
            self.disconnect()

    def _socket_listener_thread(self):
        """This thread handles the socket's output and handles any events before adding the output to the receive queue.
        """
        active_event_lines = []
        while True:
            if not self.is_connected:
                break

            line = self._socket_file.readline().strip()

            if self._active_event is None:
                for event in events.event_types:
                    if event.is_input_began(line):
                        active_event_lines = []
                        if event.is_input_ended(line):
                            events.raise_event(event.parse_raw([line]))
                        else:
                            self._socket_io_lock.acquire()
                            self._active_event = event
                            active_event_lines.append(line)
                        break
                else:
                    self._recv_queue.put(line)
            else:
                active_event_lines.append(line)
                if self._active_event.is_input_ended(line):
                    events.raise_event(self._active_event.parse_raw(active_event_lines))
                    active_event_lines = []
                    self._active_event = None
                    self._socket_io_lock.release()

    def _socket_writer_thread(self):
        while True:
            if not self.is_connected:
                break

            try:
                data = self._send_queue.get()
                self._socket_io_lock.acquire()
                self._socket.send(bytes(data, "utf-8"))
            finally:
                self._socket_io_lock.release()

    def _socket_send(self, data) -> None:
        """Convert data to bytes and send to socket.
        """
        self._send_queue.put(data)

    def _socket_recv(self) -> str:
        """Receive bytes from socket and convert to string.
        """
        return self._recv_queue.get()

    def send_command(self, cmd) -> Optional[str]:
        """Send command to management interface and fetch response.
        """
        if not self.is_connected:
            raise errors.NotConnectedError("You must be connected to the management interface to issue commands.")
        logger.debug("Sending cmd: %r", cmd.strip())
        self._socket_send(cmd + "\n")
        if cmd.startswith("kill") or cmd.startswith("client-kill"):
            return
        resp = self._socket_recv()
        if cmd.strip() not in ("load-stats", "signal SIGTERM"):
            while not resp.strip().endswith("END"):
                resp += self._socket_recv()
        logger.debug("Cmd response: %r", resp)
        return resp

    # Interface commands and parsing

    @staticmethod
    def has_prefix(line) -> bool:
        return line.startswith(">INFO") or line.startswith(">CLIENT") or line.startswith(">STATE")

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

    def _get_state(self) -> State:
        """Get OpenVPN state from socket.
        """
        raw = self.send_command("state")
        return State.parse_raw(raw)

    @property
    def state(self) -> State:
        """OpenVPN daemon state.
        """
        if self._state is None:
            self._state = self._get_state()
        return self._state

    def cache_data(self) -> None:
        """Cached some metadata about the connection.
        """
        _ = self.release
        _ = self.state

    def clear_cache(self) -> None:
        """Clear cached state data about connection.
        """
        self._release = None
        self._state = None

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

    def get_status(self):
        """Get current status from VPN.

        Uses openvpn-status library to parse status output:
        https://pypi.org/project/openvpn-status/
        """
        raw = self.send_command("status 1")
        return openvpn_status.parse_status(raw)
