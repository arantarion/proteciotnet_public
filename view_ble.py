import json
import logging
import os.path

_BASE_BLE_DIR = "/opt/ble/"
_BASE_STATIC_BLE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/ble_reports/"

logger = logging.getLogger(__name__)


def bluetooth_low_energy(request):
    r = {'auth': True, 'js': ""}

    ble_file_filename = request.session['scanfile'].replace(".csv", ".json")
    with open(f"{_BASE_STATIC_BLE_DIR}{ble_file_filename}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    logger.debug(f"Successfully loaded json file {ble_file_filename}")

    # scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    # addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
    file_info_header = json_input[0]

    r['bl_filename'] = ble_file_filename
    r['bl_scan_start_time'] = file_info_header['ble_scan_start_time']
    r['bl_scan_end_time'] = file_info_header['ble_scan_end_time']
    r['bl_interfaces'] = ",".join(file_info_header['ble_interface'])
    r['bl_ltk'] = file_info_header['ble_ltk']
    r['bl_nr_dev'] = file_info_header['ble_nr_devices']
    r['bl_conn_dev'] = file_info_header['ble_connectable_devices']

    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + file_info_header['ble_filename'] + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '	});' + \
               '</script>'

    logger.debug(f"Successfully created dict r with display information for the HTML page")

    return r
