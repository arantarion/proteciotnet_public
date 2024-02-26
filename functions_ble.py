import json
import logging
import os
import subprocess
import threading

from multiprocessing import Process
from django.http import HttpResponse
from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.bluetooth_le.ble_scan import runner, scan_continuous

is_scanning = False

logger = logging.getLogger(__name__)

try:
    config_functions_ble = ConfigParser(interpolation=ExtendedInterpolation())
    config_functions_ble.read('proteciotnet.config')
    STATIC_PATH = config_functions_ble.get('GENERAL_PATHS', 'static_directory')
    SNIFFLE_PATH = config_functions_ble.get('BLE_PATHS', 'sniffle_location')
    BLE_LOCK_FILENAME = config_functions_ble.get('BLE', 'ble_lock_filename')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e}  in file {__file__}")
    exit(-3)


def start_scan():
    """
    Starts a scan process by creating a lock file.

    If the lock file already exists, it implies that a scan is already in progress.
    """

    if not os.path.isfile(STATIC_PATH + BLE_LOCK_FILENAME):
        logger.info("Starting ble scan.")
        with open(f"{STATIC_PATH}/{BLE_LOCK_FILENAME}", "w") as f:
            f.write("")
        logger.info(f"Created lock file: {BLE_LOCK_FILENAME} in {STATIC_PATH}")
    else:
        logger.info("Scan seems to be running already")


def stop_scan():
    """
    Stops a running scan process by removing the lock file.

    If the lock file does not exist, it indicates that no scan is currently running.
    """
    if not os.path.isfile(f"{STATIC_PATH}/{BLE_LOCK_FILENAME}"):
        logger.warning("No scan is running, so can not stop it")
    else:
        try:
            os.remove(f"{STATIC_PATH}/{BLE_LOCK_FILENAME}")
            logger.info("Scan lock removed. Scan should stop soon.")
        except Exception as e:
            logger.error(f"Could not delete file - {e}")


def _convert_to_int(param: str):
    """
    Converts a parameter to an integer.

    Args:
        param (str): The parameter to be converted to an integer.

    Returns:
        int: The integer representation of the parameter if successful, otherwise an empty string.
    """
    try:
        return int(param)
    except ValueError:
        return ""


def _convert_to_bool(param: str):
    """
    Converts a parameter to a boolean value.

    Args:
        param (str): The parameter to be converted to a boolean.

    Returns:
        bool: The boolean representation of the parameter.
    """
    val = param.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return False


def new_ble_scan(request):
    """
    Initiates a new BLE scan based on parameters from a POST request.

    Parameters:
    - request (HttpRequest): The HTTP request object containing POST data.

    Returns:
    - HttpResponse: A JSON-formatted HTTP response indicating either the POST data or an error message.
    """

    if request.method == "POST":
        logger.info("Received new scanning request...")
        post_data = request.POST

        ble_filename = post_data.get("ble_filename", "")
        ble_scan_time_length = _convert_to_int(post_data.get("ble_scan_time", ""))
        ble_continuous_scan = _convert_to_bool(post_data.get("ble_cont_scan", ""))
        ble_list_only_scan = _convert_to_bool(post_data.get("ble_list_only", ""))
        ble_connectable_only = _convert_to_bool(post_data.get("ble_connectable_only", ""))
        ble_beacons_only_mode = _convert_to_bool(post_data.get("ble_beaconsOnly", ""))
        ble_bonding_test_mode = _convert_to_bool(post_data.get("ble_bondingTest", ""))
        ble_scheduled_scan = _convert_to_bool(post_data.get("ble_schedule", ""))
        ble_schedule_frequency = post_data.get("ble_frequency", "")
        ble_interface_nr = post_data.get("ble_interface_nr", "")
        ble_specific_device_addr = post_data.get("ble_specific_device", "")
        ble_sniff_filename = post_data.get("ble_sniff_filename", "")
        ble_sniff_timeout = _convert_to_int(post_data.get("ble_sniff_timeout", ""))
        ble_ltk = post_data.get("ble_ltk", "")
        ble_decrypt_packages = post_data.get("ble_decrypt_packages", "")
        ble_device_send_addr = post_data.get("ble_send_dev_addr", "")
        ble_characteristic = post_data.get("ble_chara", "")
        ble_characteristic_value = post_data.get("ble_value", "")
        ble_subscribe_to_characteristic = post_data.get("ble_subscribe_chara", "")

        ble_data = {
            "ble_filename": ble_filename,
            "ble_scan_time_length": ble_scan_time_length,
            "ble_continuous_scan": ble_continuous_scan,
            "ble_list_only_scan": ble_list_only_scan,
            "ble_connectable_only": ble_connectable_only,
            "ble_beacons_only_mode": ble_beacons_only_mode,
            "ble_bonding_test_mode": ble_bonding_test_mode,
            "ble_scheduled_scan": ble_scheduled_scan,
            "ble_schedule_frequency": ble_schedule_frequency,
            "ble_interface_nr": ble_interface_nr,
            "ble_specific_device_addr": ble_specific_device_addr,
            "ble_sniff_filename": ble_sniff_filename,
            "ble_sniff_timeout": ble_sniff_timeout,
            "ble_ltk": ble_ltk,
            "ble_decrypt_packages": ble_decrypt_packages,
            "ble_device_send_addr": ble_device_send_addr,
            "ble_characteristic": ble_characteristic,
            "ble_characteristic_value": ble_characteristic_value,
            "ble_subscribe_to_characteristic": ble_subscribe_to_characteristic
        }

        logger.debug(f"ble_data: {ble_data}")

        if ble_filename:
            if ble_continuous_scan:
                logger.info("Continuous scanning selected by user")
                start_scan()
                p = Process(target=scan_continuous(ble_filename))
                p.start()
            else:
                logger.info("Time based scanning selected")
                runner(filename=ble_filename,
                       interface=0,
                       scan_time=ble_scan_time_length,
                       list_mode=ble_list_only_scan,
                       connectable_only=ble_connectable_only,
                       beacons_only=ble_beacons_only_mode,
                       bonding_test=ble_bonding_test_mode,
                       schedule=ble_scheduled_scan,
                       schedule_frequency=ble_schedule_frequency,
                       specific_device_addr=ble_specific_device_addr
                       )

        elif ble_sniff_filename:
            logger.info("BLE sniffing selected by user")
            try:
                def target():
                    _COMMAND = f"{SNIFFLE_PATH}sniff_receiver.py -q -e -o {ble_sniff_filename}.pcap".split()
                    logger.debug(f"Sniffing command: {_COMMAND}")
                    process = subprocess.Popen(_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    logger.debug(f"stdout: {stdout}")
                    logger.debug(f"stderr: {stderr}")

                thread = threading.Thread(target=target)
                thread.start()
                thread.join(ble_sniff_timeout)
                if thread.is_alive():
                    logger.error("Thread did not end with timeout")
                    return HttpResponse(json.dumps({'error': 'TERMINATE'}, indent=4), content_type="application/json")

                _COMMAND_CRACKLE = f"crackle -i {ble_sniff_filename}.pcap -j {ble_sniff_filename}.json"

                if ble_ltk:
                    _COMMAND_CRACKLE += f" -l {ble_ltk}"

                if ble_decrypt_packages:
                    _COMMAND_CRACKLE += f" -o {ble_decrypt_packages}"

                logger.info(f"Trying Crackle with command {_COMMAND_CRACKLE}")

                process_crackle = subprocess.Popen(_COMMAND_CRACKLE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process_crackle.communicate()
                logger.debug(f"stdout: {stdout}")
                logger.debug(f"stderr: {stderr}")

                return HttpResponse(json.dumps({'p': request.POST}, indent=4), content_type="application/json")
            except Exception as e_sniff:
                logger.error(f"Could not sniff BLE traffic - {e_sniff}")
                return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

        elif ble_device_send_addr:
            logger.warning("Not implemented")
            return HttpResponse(json.dumps({'error': 'not implemented'}, indent=4), content_type="application/json")

        else:
            logger.error("Invalid syntax")
            return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

        logger.info("Script ran successfully")
        return HttpResponse(json.dumps({'p': request.POST}, indent=4), content_type="application/json")

    else:
        logger.error("Invalid syntax. You have to send a POST request")
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")
