import re
import subprocess

# Target device to look for. If you are using another ZigBee USB dongle please change this.
_TARGET = "CC2531"


def _get_all_usb_devices():
    """
    Retrieve a list of all connected USB devices via lsusb.

    Returns:
        list: A list of dictionaries, each containing details of a USB device.
    """
    device_re = re.compile(b"Bus\s+(?P<bus>\d+)\s+Device\s+(?P<device>\d+).+ID\s(?P<id>\w+:\w+)\s(?P<tag>.+)$", re.I)
    df = subprocess.check_output("lsusb")
    devices = []
    for i in df.split(b'\n'):
        if i:
            info = device_re.match(i)
            if info:
                dinfo = info.groupdict()
                dinfo['device'] = '/dev/bus/usb/%s/%s' % (
                    dinfo.pop('bus').decode('utf-8'), dinfo.pop('device').decode('utf-8'))
                dinfo = {k: v.decode('utf-8') if isinstance(v, bytes) else v for k, v in dinfo.items()}
                devices.append(dinfo)
    return devices


def _extract_specific_device(devices: list, target_tag: str) -> dict or None:
    """
   Extract a specific device from the list of devices based on its tag.

   Args:
       devices (list): List of USB devices.
       target_tag (str): The target tag to search for.

   Returns:
       dict: Dictionary containing details of the matched device or None if not found.
   """
    for device in devices:
        if target_tag in device['tag']:
            return device
    return None


def _extract_interface_position(device: dict) -> str or None:
    """
    Extract the interface from the device details.

    Args:
        device (dict): Dictionary containing details of a USB device.

    Returns:
        str: Interface in the format "bus:device" or None if device is None.
    """
    if not device:
        return None
    parts = device['device'].split('/')
    interface_position = f"{int(parts[-2])}:{int(parts[-1])}"
    return interface_position


def get_zigbee_usb_interface():
    """
    Retrieve the interface position and details of the Zigbee USB device.

    Returns:
        tuple: A tuple containing the interface position (str) and device details (dict).
    """
    devices = _get_all_usb_devices()
    target_device = _extract_specific_device(devices, _TARGET)
    interface = _extract_interface_position(target_device)
    return interface, target_device
