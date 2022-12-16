"""Unit tests for Panorama utility functions."""
from unittest.mock import MagicMock
from nautobot.utilities.testing import TestCase
from nautobot_plugin_chatops_panorama.utils.panorama import get_devices_from_pano, get_devicegroups_from_pano


class TestPanoramaUtils(TestCase):
    """Test Panorama utility methods."""

    databases = ("default", "job_logs")

    def test_get_devices_from_pano(self):
        """Test the get_devices_from_pano function success."""
        mock_device = MagicMock()
        mock_device.is_active = MagicMock()
        mock_device.is_active.return_value = True
        mock_device.show_system_info = MagicMock()
        mock_device.show_system_info.return_value = {
            "system": {
                "hostname": "Test",
                "serial": 123456,
                "ip-address": "1.1.1.1/32",
                "model": "PAN-2110",
                "sw-version": "10.0.2",
            }
        }
        mock_group = MagicMock()
        mock_group.name = "Test Group"
        mock_group.children = [mock_device]
        mock_conn = MagicMock()
        mock_conn.refresh_devices = MagicMock()
        mock_conn.refresh_devices.return_value = [mock_group]
        expected = {
            "Test": {
                "hostname": "Test",
                "serial": 123456,
                "group_name": "Test Group",
                "ip_address": "1.1.1.1/32",
                "status": True,
                "model": "PAN-2110",
                "os_version": "10.0.2",
            }
        }
        result = get_devices_from_pano(connection=mock_conn)
        self.assertEqual(result, expected)

    def test_get_devicegroups_from_pano(self):
        """Test the get_devicegroups_from_pano function success."""
        mock_device = MagicMock()
        mock_device.show_system_info = MagicMock()
        mock_device.show_system_info.return_value = {
            "system": {
                "hostname": "Test",
                "serial": 123456,
                "ip-address": "1.1.1.1/32",
                "model": "PAN-2110",
                "sw-version": "10.0.2",
            }
        }
        mock_group = MagicMock()
        mock_group.name = "Test Group"
        mock_group.children = [mock_device]
        mock_empty_group = MagicMock()
        mock_empty_group.name = "Empty Group"
        mock_empty_group.children = []
        mock_conn = MagicMock()
        mock_conn.refresh_devices = MagicMock()
        mock_conn.refresh_devices.return_value = [mock_group, mock_empty_group]
        expected = {
            "Test Group": {
                "devices": [
                    {
                        "hostname": "Test",
                        "address": "1.1.1.1/32",
                        "serial": 123456,
                        "model": "PAN-2110",
                        "version": "10.0.2",
                    }
                ]
            },
            "Empty Group": {"devices": []},
        }
        result = get_devicegroups_from_pano(connection=mock_conn)
        self.assertEqual(result, expected)
