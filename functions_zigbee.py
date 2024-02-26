import os
import csv
import json
import pexpect
import logging
import tempfile
import subprocess

from time import sleep
from datetime import datetime
from collections import Counter
from django.http import HttpResponse
from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.zigbee.find_cc2531_interface import get_zigbee_usb_interface

logger = logging.getLogger(__name__)

# _TERMINATE_RECORDING_AFTER_X_PACKETS = 10
# _TERMINATE_RECORDING_AFTER_X_TIME = 25
# _ZIGBEE_JSON_BASE_DIRECTORY = "/opt/zigbee/"

try:
    config_functions_zigbee = ConfigParser(interpolation=ExtendedInterpolation())
    config_functions_zigbee.read('proteciotnet.config')
    _TERMINATE_RECORDING_AFTER_X_PACKETS = config_functions_zigbee.get('ZIGBEE', 'terminate_recording_after_x_packets')
    _TERMINATE_RECORDING_AFTER_X_TIME = config_functions_zigbee.get('ZIGBEE', 'terminate_recording_after_x_time')
    _ZIGBEE_JSON_BASE_DIRECTORY = config_functions_zigbee.get('ZIGBEE_PATHS', 'zigbee_json_base_directory')
    _ZIGBEE_PROTECIOTNET_DIRECTORY = config_functions_zigbee.get('ZIGBEE_PATHS', 'zigbee_proteciotnet_directory')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e}")
    exit(-3)


class ZigBeeDevice:
    """
    Represents a ZigBee device.

    Attributes:
        panid (str): PAN ID of the device.
        source (str): Source address of the device.
        extpanid (str): Extended PAN ID of the device.
        stackprofile (str): Stack profile of the device.
        stackversion (str): Stack version of the device.
        channel (str): Channel of the device.
    """
    def __init__(self, device):
        """
        Initialize a ZigBeeDevice object.

        Args:
            device (tuple): A tuple containing device information (panid, source, extpanid, stackprofile, stackversion, channel).
        """
        panid, source, extpanid, stackprofile, stackversion, channel = device
        self.panid = panid
        self.source = source
        self.extpanid = extpanid
        self.stackprofile = stackprofile
        self.stackversion = stackversion
        self.channel = channel
        logger.debug(f"Successfully created ZigBee Object with PANID: {self.panid}")

    def __repr__(self):
        """
        Returns a string representation of the ZigBeeDevice object.
        """
        return f"ZigBeeDevice (Source: {self.source}, PAN ID: {self.panid}, Channel: {self.channel})"

    def __str__(self):
        """
        Returns a formatted string representation of the ZigBeeDevice object.
        """
        return (f"ZigBeeDevice(panid={self.panid}, source={self.source}, "
                f"extpanid={self.extpanid}, stackprofile={self.stackprofile}, "
                f"stackversion={self.stackversion}, channel={self.channel})")


def _get_timestamp() -> str:
    """
    Get the current timestamp in the format 'YYYYMMDD_HHMMSS'.

    Returns:
        str: Current timestamp string.
    """
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def _check_file(filename: str) -> bool:
    """
    Check if a file exists and contains Zigbee traffic.

    Args:
        filename (str): The path to the file to be checked.

    Returns:
        bool: True if the file exists and contains Zigbee traffic, False otherwise.
    """
    if not os.path.exists(filename):
        logger.error(f"Error: {filename} does not exist.")
        return False

    file_size = os.path.getsize(filename)

    if file_size == 0:
        logger.error(f"{filename} is empty.")
        return False
    elif file_size == 56:
        logger.warning("no zigbee traffic found.")
        return False
    else:
        logger.info(f"{filename} exists and seems to contain zigbee traffic")
        return True


def _find_channel(sniffing_device: str = ""):
    """
    Find the Zigbee channel by running zbstumbler.

    Args:
        sniffing_device (str, optional): The device to sniff on. Defaults to "".

    Returns:
        str: The path to the output file containing channel scan results, or None if unsuccessful.
    """
    try:
        tmp_path = tempfile.mkdtemp(prefix="proteciotnet-tmp")
    except Exception as e:
        logger.error(f"Error while creating temporary directory. Error {e}")
        return None

    _FILENAME = f"zigbee_channel_scan_{_get_timestamp()}.csv"
    _OUTPUT_PATH = f"{tmp_path}/{_FILENAME}"
    logger.debug(f"Output path: {_OUTPUT_PATH}")
    logger.debug(f"Filename: {_FILENAME}")

    if sniffing_device:
        _COMMAND = ['sudo', 'zbstumbler', '-i', sniffing_device, '-w', _OUTPUT_PATH]
    else:
        _COMMAND = ['sudo', 'zbstumbler', '-w', _OUTPUT_PATH]

    logger.info(f"trying to start zbstumbler with commands: {' '.join(_COMMAND)}. Running for {_TERMINATE_RECORDING_AFTER_X_TIME} seconds.")
    try:
        child = pexpect.spawn(' '.join(_COMMAND))
        sleep(_TERMINATE_RECORDING_AFTER_X_TIME)
        child.sendcontrol('c')
        child.expect(pexpect.EOF)

    except:
        logger.error("something went wrong while executing zbstumbler. are you root?")

    logger.info(f"successfully ran zbstumbler. Output at {_OUTPUT_PATH}.")
    if _check_file(_OUTPUT_PATH):
        logger.info(f"Checked file. Seems good. Output at {_OUTPUT_PATH}.")
        return f"{_OUTPUT_PATH}"
    else:
        logger.error("File check was not successful. Something went wrong while executing _check_file().")
        return None


def _read_zbstumbler_file(filename: str) -> list:
    """
    Read the zbstumbler output file containing Zigbee device information.

    Args:
        filename (str): The path to the zbstumbler output file.

    Returns:
        list: A list of ZigBeeDevice objects.
    """
    captures_zigbee_devices = []
    with open(filename) as file:
        zigbee_devices = csv.reader(file, delimiter=",")

        logger.debug(f"Successfully read zbstumbler file {filename}.")

        for line in zigbee_devices:
            captures_zigbee_devices.append(line)

    devices = [ZigBeeDevice(elem) for elem in captures_zigbee_devices[1:]]
    logger.info("Successfully created ZigBee Objects from file content")
    logger.debug(f"Extracted devices: {devices}")

    return devices


def _determine_most_likely_channel(devices: list) -> int:
    """
    Determine the most likely Zigbee channel based on a list of ZigBeeDevice objects.

    Args:
        devices (list): A list of ZigBeeDevice objects.

    Returns:
        int: The most likely Zigbee channel.
    """
    return Counter(device.channel for device in devices).most_common(1)[0][0]


def _sniff_traffic(filename, channel, num_packages, sniffing_interface, dev_name="CC2531 USB Dongle"):

    _FILENAME = f"{filename}.pcap"
    _OUTPUT_PATH = f"{_ZIGBEE_JSON_BASE_DIRECTORY}{_FILENAME}"

    logger.info(f"Starting ZigBee sniffing with filename {_FILENAME} in path {_OUTPUT_PATH} using {dev_name}")

    _COMMAND = ['sudo', 'python3', f'{_ZIGBEE_PROTECIOTNET_DIRECTORY}/zbdumb.py', '-i', sniffing_interface,
                '-d', dev_name, '-c', channel, '-w', _OUTPUT_PATH, '-W', 'ZigBeeIsFun', '-n', f'{num_packages}']

    logger.info(f"ZigBee Sniffing command is {''.join(_COMMAND)}")

    process = subprocess.Popen(_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    logger.debug(f"ZigBee Sniffing std output: {stdout.decode()}")
    logger.debug(f"ZigBee Sniffing std error: {stderr.decode()}")

    logger.info(f"Ran sniffing successfully.")

    return _FILENAME


def _convert_pcap(in_filename: str, output_type: str) -> str:
    """
    Convert a pcap file to the specified output type using tshark.

    Args:
        in_filename (str): The input pcap filename.
        output_type (str): The desired output file type.

    Returns:
        str: The filepath of the converted file.
    """
    logger.info(f"Converting file {in_filename} to {output_type}")

    out_filepath = in_filename.split(".")[0] + f".{output_type}"
    subprocess.run(["tshark", "-r", f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{in_filename}", "-T", output_type],
                   stdout=open(f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{out_filepath}", "w"))

    logger.info(f"Successfully converted file {out_filepath} to {output_type}")

    return f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{out_filepath}"


def zigbee_postprocessing_json(file_path, scan_info, sniffing_device, sniffing_device_id, sniffing_channel):
    """
    Append additional scan information to a JSON file.

    Args:
        file_path (str): The path to the JSON file.
        scan_info (dict): Information about the scan.
        sniffing_device (str): The device used for sniffing.
        sniffing_device_id (str): The ID of the sniffing device.
        sniffing_channel (int): The channel used for sniffing.

    Returns:
        HttpResponse: JSON response indicating success or failure.
    """

    logger.info(f"Appending additional scan information to {file_path}")

    additional_scan_info = {
        "scan_info": scan_info,
        "sniffing_device": sniffing_device,
        "sniffing_device_id": sniffing_device_id,
        "sniffing_channel": sniffing_channel
    }

    logger.debug(f"additional_scan_info: {additional_scan_info}")

    with open(file_path, 'r+') as f:
        data = json.load(f)

    logger.debug(f"read file: {file_path}")

    if isinstance(data, list):
        data.insert(0, additional_scan_info)
        logger.debug(f"successfully appended additional scan information: {data}")
    else:
        logger.debug(f"Problem with appending postprocessing information to {file_path}")
        return HttpResponse(json.dumps({'error': 'Can\'t append postprocessing information to file.'}, indent=4),
                            content_type="application/json")

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

    logger.info(f"Wrote data to {file_path}")


def _convert_pdml_to_html(in_filename: str):
    """
    Convert PDML (Packet Details Markup Language) to HTML using XSL transformation.

    Args:
        in_filename (str): Input PDML file path.

    Returns:
        str: Output HTML file path if successful, otherwise None.

    Note:
        This function depends on xsltproc to be available in your systems path
    """

    logger.info(f"Converting {in_filename} to HTML using XSL transformation.")

    out_filename = in_filename.split(".")[0] + ".html"

    logger.debug(f"out_filename: {out_filename}")

    if os.path.isfile(f"{_ZIGBEE_JSON_BASE_DIRECTORY}/pdml2html.xsl"):
        logger.debug("Verified that pdml2html is available")
        subprocess.run(["xsltproc", f"{_ZIGBEE_JSON_BASE_DIRECTORY}/pdml2html.xsl", f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{in_filename}"],
                       stdout=open(f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{out_filename}", "w"))
        logger.info("Successfully converted to HTML using XSL transformation.")
        return out_filename

    logger.error(f"Could not find pdml2html in {_ZIGBEE_JSON_BASE_DIRECTORY}/pdml2html.xsl or could not convert")
    return None


def new_zigbee_scan(request) -> HttpResponse:
    """
    Initiates a new ZigBee scan based on parameters from a POST request.

    Args:
    - request (HttpRequest): The HTTP request object containing POST data.

    Returns:
    - HttpResponse: A JSON-formatted HTTP response indicating either the POST data or an error message.
    """

    if request.method == "POST":

        filename = request.POST.get("zb_filename", "")
        interface_id = request.POST.get("zb_interface", "")
        channel = request.POST.get("zb_channel", "")
        user_pcap_path = request.POST.get("zb_pcap_path", "")

        logger.info(f"Received POST. Trying to start ZigBee Scan")
        logger.debug(f"filename: {filename}")
        logger.debug(f"interface_id: {interface_id}")
        logger.debug(f"channel: {channel}")
        logger.debug(f"user_pcap_path: {user_pcap_path}")

        if not filename or filename == ".json":
            logger.error(f"Incomplete parameters to do ZigBee scan")
            return HttpResponse(json.dumps({'error': 'incomplete parameters'}, indent=4),
                                content_type="application/json")

        res = {'p': request.POST}
        sniffing_device = ""
        sniffing_channel = ""
        sniffing_scan_info = "ZigBee custom sniffing pipeline for ProtecIoTnet"
        sniffing_device_description = ""

        if channel:
            logger.info(f"Channel set by user: {channel}")
            sniffing_channel = channel
        elif user_pcap_path:
            logger.info(f"User supplied pcap file path: {user_pcap_path}. Using default channel. Performing only "
                        f"postprocessing")
            sniffing_scan_info = "User supplied ZigBee sniffing file"
            json_filename = _convert_pcap(in_filename=user_pcap_path, output_type="json")
            zigbee_postprocessing_json(file_path=json_filename,
                                       scan_info=sniffing_scan_info,
                                       sniffing_device="some ZigBee sniffer device",
                                       sniffing_device_id="?",
                                       sniffing_channel="?"
                                       )
            logger.info(f"Postprocessing complete for user supplied pcap file.")

            return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

        if not interface_id:
            logger.info("Determining ZigBee device interface")
            sniffing_device, sniffing_device_description = get_zigbee_usb_interface()
            logger.info(f"Sniffing device: {sniffing_device} / {sniffing_device_description}")
        if not channel:
            logger.info("Determining ZigBee channel")
            channel_scan_path = _find_channel()
            if channel_scan_path:
                logger.info("Scanning for ZigBee devices using zbstumbler")
                devices_in_scan = _read_zbstumbler_file(channel_scan_path)
                logger.info(f"Devices found: {devices_in_scan}")
                logger.info("Trying to determine the most likely channel")
                sniffing_channel = _determine_most_likely_channel(devices_in_scan)
                logger.info(f"Channel found: {sniffing_channel}")
            else:
                logger.error("Error while searching for ZigBee channel")
                return HttpResponse(json.dumps({'error': 'Can\'t find channel.'}, indent=4),
                                    content_type="application/json")

        logger.info("Starting ZigBee sniffing")
        pcap_path = _sniff_traffic(filename=filename,
                                   channel=sniffing_channel,
                                   num_packages=_TERMINATE_RECORDING_AFTER_X_PACKETS,
                                   sniffing_interface=sniffing_device
                                   )
        logger.info("Completed ZigBee sniffing")
        logger.info("Starting pcap to json conversion")

        json_filename = _convert_pcap(in_filename=pcap_path, output_type="json")

        logger.info("Completed pcap to json conversion")
        logger.info("Starting zigbee postprocessing")

        zigbee_postprocessing_json(file_path=json_filename,
                                   scan_info=sniffing_scan_info,
                                   sniffing_device=sniffing_device_description,
                                   sniffing_device_id=sniffing_device,
                                   sniffing_channel=sniffing_channel
                                   )
        logger.info("Completed zigbee postprocessing")
        return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
    else:
        logger.error("Error while performing ZigBee scan")
        res = {'error': 'invalid syntax'}
        return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
