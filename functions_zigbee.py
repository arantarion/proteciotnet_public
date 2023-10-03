import csv
import json
import logging
import os
import subprocess
import tempfile
from collections import Counter
from datetime import datetime
from time import sleep

import pexpect
from django.http import HttpResponse

from proteciotnet_dev.zigbee.find_cc2531_interface import get_zigbee_usb_interface

logger = logging.getLogger(__name__)

_TERMINATE_AFTER_X_PACKETS = 10
_TERMINATE_AFTER_X_TIME = 15
_FOLDER_PATH = "/opt/zigbee/"


class ZigBeeDevice:
    def __init__(self, device):
        panid, source, extpanid, stackprofile, stackversion, channel = device
        self.panid = panid
        self.source = source
        self.extpanid = extpanid
        self.stackprofile = stackprofile
        self.stackversion = stackversion
        self.channel = channel

    def __repr__(self):
        return f"ZigBeeDevice (Source: {self.source}, PAN ID: {self.panid}, Channel: {self.channel})"

    def __str__(self):
        return (f"ZigBeeDevice(panid={self.panid}, source={self.source}, "
                f"extpanid={self.extpanid}, stackprofile={self.stackprofile}, "
                f"stackversion={self.stackversion}, channel={self.channel})")


def _get_timestamp():
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def _check_file(filename):
    if not os.path.exists(filename):
        logger.error(f"Error: {filename} does not exist.")
        return

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


def _find_channel(sniffing_device=""):
    try:
        tmp_path = tempfile.mkdtemp(prefix="proteciotnet-tmp")
    except:
        logger.error("Error while creating temporary directory.")
        return None

    _FILENAME = f"zigbee_channel_scan_{_get_timestamp()}.csv"
    _OUTPUT_PATH = f"{tmp_path}/{_FILENAME}"
    if sniffing_device:
        _COMMAND = ['sudo', 'zbstumbler', '-i', sniffing_device, '-w', _OUTPUT_PATH]
    else:
        _COMMAND = ['sudo', 'zbstumbler', '-w', _OUTPUT_PATH]

    logger.info(f"trying to start zbstumbler with commands: {' '.join(_COMMAND)}")
    try:
        child = pexpect.spawn(' '.join(_COMMAND))
        sleep(_TERMINATE_AFTER_X_TIME)
        child.sendcontrol('c')
        child.expect(pexpect.EOF)

    except:
        logger.error("something went wrong while executing zbstumbler. are you root?")

    logger.info("successfully ran zbstumbler")
    if _check_file(_OUTPUT_PATH):
        return f"{_OUTPUT_PATH}/{_FILENAME}"
    else:
        return None


def _read_zbstumbler_file(filename):
    captures_zigbee_devices = []
    with open(filename) as file:
        zigbee_devices = csv.reader(file, delimiter=",")

        for line in zigbee_devices:
            captures_zigbee_devices.append(line)

    devices = [ZigBeeDevice(elem) for elem in captures_zigbee_devices[1:]]

    return devices


def _determine_most_likely_channel(devices):
    # channel_stats = []
    # for device in devices:
    #     channel_stats.append(device.channel)
    # return Counter(channel_stats).most_common(1)[0][0]
    return Counter(device.channel for device in devices).most_common(1)[0][0]


def _sniff_traffic(filename, channel, num_packages, sniffing_interface, dev_name="CC2531 USB Dongle"):
    _FILENAME = f"{filename}.pcap"
    _OUTPUT_PATH = f"{_FOLDER_PATH}{_FILENAME}"

    _COMMAND = ['sudo', 'python3', f'/opt/proteciotnet/proteciotnet_dev/zigbee/zbdumb.py', '-i', sniffing_interface,
                '-d', dev_name, '-c', channel, '-w', _OUTPUT_PATH, '-W', 'ZigBeeSucks', '-n', num_packages]

    process = subprocess.Popen(_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # print("Output:", stdout.decode())
    # print("Errors:", stderr.decode())

    # sudo zbdump -i 1:8 -d "CC2531 USB Dongle" -c 20 -w tester.pcap -n 5

    return _FILENAME


def _convert_pcap(in_filename, output_type):
    out_filepath = in_filename.split(".")[0] + f".{output_type}"
    subprocess.run(["tshark", "-r", f"{_FOLDER_PATH}{in_filename}", "-T", output_type],
                   stdout=open(f"{_FOLDER_PATH}{out_filepath}", "w"))
    return f"{_FOLDER_PATH}{out_filepath}"


def zigbee_postprocessing_json(file_path, scan_info, sniffing_device, sniffing_device_id, sniffing_channel):
    additional_scan_info = {
        "scan_info": scan_info,
        "sniffing_device": sniffing_device,
        "sniffing_device_id": sniffing_device_id,
        "sniffing_channel": sniffing_channel
    }

    with open(file_path, 'r') as f:
        data = json.load(f)

    if isinstance(data, list):
        data.insert(0, additional_scan_info)
    else:
        return HttpResponse(json.dumps({'error': 'Can\'t append postprocessing information to file.'}, indent=4),
                            content_type="application/json")

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)


def _convert_pdml_to_html(in_filename):
    out_filename = in_filename.split(".")[0] + ".html"

    if os.path.isfile(f"{_FOLDER_PATH}/pdml2html.xsl"):
        subprocess.run(["xsltproc", f"{_FOLDER_PATH}/pdml2html.xsl", f"{_FOLDER_PATH}/{in_filename}"],
                       stdout=open(f"{_FOLDER_PATH}/{out_filename}", "w"))
        return out_filename

    return None


def new_zigbee_scan(request):
    """
    Initiates a new ZigBee scan based on parameters from a POST request.

    Parameters:
    - request (HttpRequest): The HTTP request object containing POST data.

    Returns:
    - HttpResponse: A JSON-formatted HTTP response indicating either the POST data or an error message.
    """

    if request.method == "POST":

        filename = request.POST.get("zb_filename", "")
        interface_id = request.POST.get("zb_interface", "")
        channel = request.POST.get("zb_channel", "")
        user_pcap_path = request.POST.get("zb_pcap_path", "")

        if not filename or filename == ".json":
            return HttpResponse(json.dumps({'error': 'incomplete parameters'}, indent=4),
                                content_type="application/json")

        res = {'p': request.POST}
        sniffing_device = ""
        sniffing_channel = ""
        sniffing_scan_info = "ZigBee custom sniffing pipeline for ProtecIoTnet"
        sniffing_device_description = ""

        if channel:
            sniffing_channel = channel
        elif user_pcap_path:
            sniffing_scan_info = "User supplied ZigBee sniffing file"
            zigbee_postprocessing_json(file_path=user_pcap_path,
                                       scan_info=sniffing_scan_info,
                                       sniffing_device="some ZigBee sniffer device",
                                       sniffing_device_id="?",
                                       sniffing_channel="?"
                                       )
            return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

        if not interface_id:
            sniffing_device, sniffing_device_description = get_zigbee_usb_interface()
        if not channel:
            channel_scan_path = _find_channel()
            if channel_scan_path:
                devices_in_scan = _read_zbstumbler_file(channel_scan_path)
                sniffing_channel = _determine_most_likely_channel(devices_in_scan)
            else:
                return HttpResponse(json.dumps({'error': 'Can\'t find channel.'}, indent=4),
                                    content_type="application/json")

        pcap_path = _sniff_traffic(filename=filename,
                                   channel=sniffing_channel,
                                   num_packages=_TERMINATE_AFTER_X_PACKETS,
                                   sniffing_interface=sniffing_device
                                   )

        json_filename = _convert_pcap(in_filename=pcap_path, output_type="json")
        zigbee_postprocessing_json(file_path=json_filename,
                                   scan_info=sniffing_scan_info,
                                   sniffing_device=sniffing_device_description,
                                   sniffing_device_id=sniffing_device,
                                   sniffing_channel=sniffing_channel
                                   )

        return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
    else:
        res = {'error': 'invalid syntax'}
        return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
