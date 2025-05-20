from typing import List

from openvpn_management_api import events


@events.register_event
class UpDownEvent(events.BaseEvent):
    """
    This event gets fired when the server shuts down or gets started.
    It won't be fired with usual management interface text, so no need
    to implement the text processing methods.
    """
    UP = "UP"
    DOWN = "DOWN"

    def __init__(self, event_type: str):
        if event_type not in (self.UP, self.DOWN):
            raise RuntimeError("UpDownEvent's type should be one of these: (%s, %s)" % (self.UP, self.DOWN))
        self.type = event_type

    @classmethod
    def has_begun(cls, line: str) -> bool:
        return False

    @classmethod
    def has_ended(cls, line: str) -> bool:
        return False

    @classmethod
    def parse_raw(cls, lines: List[str]):
        raise NotImplementedError
