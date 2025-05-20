import unittest


class TestNamespace(unittest.TestCase):
    def test_import(self):
        from openvpn_management_api import VPN
        from openvpn_management_api import VPNType
        from openvpn_management_api import errors
