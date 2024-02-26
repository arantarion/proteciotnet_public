import re
import subprocess
import logging

from configparser import ConfigParser, ExtendedInterpolation

logger = logging.getLogger(__name__)

try:
    config_find_cc_interface = ConfigParser(interpolation=ExtendedInterpolation())
    config_find_cc_interface.read('proteciotnet.config')

    _ZIGBEE_USB_TARGET = config_find_cc_interface.get('ZIGBEE', 'zigbee_usb_target')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def _get_all_usb_devices() -> list:
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
    logger.debug(f"Retrieved all usb devices via lsusb: {devices}")
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
            logger.debug(f"Found {target_tag}.")
            return device
    logging.warning(f"Could not find target tag for {target_tag} in {devices}")
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
        logger.warning(f"Could not find interface in {device}.")
        return None
    parts = device['device'].split('/')
    interface_position = f"{int(parts[-2])}:{int(parts[-1])}"
    logger.debug(f"Found interface position: {interface_position}")
    return interface_position


def get_zigbee_usb_interface():
    """
    Retrieve the interface position and details of the Zigbee USB device.

    Returns:
        tuple: A tuple containing the interface position (str) and device details (dict).
    """

    logger.info(f"Trying to retrieve interface and details of Zigbee USB device.")
    devices = _get_all_usb_devices()
    target_device = _extract_specific_device(devices, _ZIGBEE_USB_TARGET)
    interface = _extract_interface_position(target_device)

    logger.info(f"Found interface position: {interface}")
    logger.debug(f"devices: {devices}")
    logger.debug(f"interface: {interface}")
    logger.debug(f"target_device: {target_device}")

    return interface, target_device
