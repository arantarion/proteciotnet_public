from find_cc2531_interface import get_zigbee_usb_interface
import os
from datetime import datetime
from time import sleep
import logging
from tqdm import tqdm
import pexpect
import csv
from collections import Counter
import subprocess

#################### Logging Setup ####################
logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.DEBUG)

# logging.debug("This is a debug message")
# logging.info("This is an info message")
# logging.warning("This is a warning message")
# logging.error("This is an error message")
# logging.critical("This is a critical message")

_TERMINATE_AFTER_X_PACKETS = 10
_TERMINATE_AFTER_X_TIME = 10
_FOLDER_PATH = "/opt/proteciotnet_zigbee"

_INTERFACE = get_zigbee_usb_interface()[0]
logging.info(f"found ZigBee hardware interface at {_INTERFACE}")


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
        print(f"Error: {filename} does not exist.")
        return

    file_size = os.path.getsize(filename)

    if file_size == 0:
        logging.error(f"{filename} is empty.")
    elif file_size == 56:
        logging.warning("no zigbee traffic found.")
    else:
        logging.info(f"{filename} exists and seems to contain zigbee traffic")


def _sleep(sleep_time):
    for _ in tqdm(range(0, sleep_time)):
        sleep(1)


#################### Finding Channel ####################

def _find_channel():
    _FILENAME = f"zigbee_channel_scan_{_get_timestamp()}.csv"
    _OUTPUT_PATH = f"{_FOLDER_PATH}/{_FILENAME}"
    _COMMAND = ['sudo', 'zbstumbler', '-i', _INTERFACE, '-w', _OUTPUT_PATH]

    if not os.path.exists(_FOLDER_PATH):
        os.makedirs(_FOLDER_PATH)
        logging.info(f"created folder {_FOLDER_PATH.split('/')[-1]}")

    logging.info(f"trying to start zbstumbler with commands: {' '.join(_COMMAND)}")
    try:
        child = pexpect.spawn(' '.join(_COMMAND))
        _sleep(_TERMINATE_AFTER_X_TIME)
        child.sendcontrol('c')
        child.expect(pexpect.EOF)

    except:
        logging.error("something went wrong while executing zbstumbler. are you root?")

    logging.info("successfully ran zbstumbler")
    _check_file(_OUTPUT_PATH)
    return f"{_FOLDER_PATH}/{_FILENAME}"


# Step 3: read csv and display info to user
def _read_file(filename):
    captures_zigbee_devices = []
    with open(filename) as file:
        zigbee_devices = csv.reader(file, delimiter=",")

        for line in zigbee_devices:
            captures_zigbee_devices.append(line)

    devices = [ZigBeeDevice(elem) for elem in captures_zigbee_devices[1:]]

    return devices


def _gen_device_channel_statistics(devices):
    channel_stats = []

    for device in devices:
        channel_stats.append(device.channel)

    return Counter(channel_stats).most_common(1)[0][0]


def _sniff_traffic(channel, num_packages, dev_name="CC2531 USB Dongle"):
    _FILENAME = f"zigbee_sniffing_{_get_timestamp()}.pcap"
    _OUTPUT_PATH = f"{_FOLDER_PATH}/{_FILENAME}"

    # -W option is neccessary, but I don't know why, and also it does not make any sense and also the value is arbitrary.
    # Just put whatever.
    _COMMAND = ['sudo', 'python3', 'zbdumb.py', '-i', _INTERFACE, '-d', dev_name, '-c', channel, '-w', _OUTPUT_PATH,
                '-W', 'ZigBeeSucks', '-n', num_packages]

    # child = pexpect.spawn(' '.join(_COMMAND))
    # child.expect(pexpect.EOF)
    process = subprocess.Popen(_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # print("Output:", stdout.decode())
    # print("Errors:", stderr.decode())

    # sudo zbdump -i 1:8 -d "CC2531 USB Dongle" -c 20 -w tester.pcap -n 5

    return _FILENAME


def _convert_pcap_to_pdml(in_filename):
    out_filename = in_filename.split(".")[0] + ".pdml"
    subprocess.run(["tshark", "-r", f"{_FOLDER_PATH}/{in_filename}", "-T", "pdml"],
                   stdout=open(f"{_FOLDER_PATH}/{out_filename}", "w"))
    return out_filename


def _convert_pdml_to_html(in_filename):
    out_filename = in_filename.split(".")[0] + ".html"

    if os.path.isfile(f"{_FOLDER_PATH}/pdml2html.xsl"):
        subprocess.run(["xsltproc", f"{_FOLDER_PATH}/pdml2html.xsl", f"{_FOLDER_PATH}/{in_filename}"],
                       stdout=open(f"{_FOLDER_PATH}/{out_filename}", "w"))
        return out_filename

    return None


if __name__ == "__main__":
    # _find_channel()
    # dev = _read_file("/opt/proteciotnet_csv/zigbee_channel_scan_20230913_121020.csv")
    # most_likely_channel = _gen_device_channel_statistics(dev)
    # _sniff_traffic('20', '20')
    filen = _convert_pcap_to_pdml("zigbee_sniffing_20230914_130123.pcap")
    print(filen)
    print(_convert_pdml_to_html(filen))
