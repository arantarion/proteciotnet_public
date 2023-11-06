import json
import logging
import os.path

_BASE_BLE_DIR = "/opt/ble/"
_BASE_STATIC_BLE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/ble_reports/"

logger = logging.getLogger(__name__)


def _item_generator(json_object, lookup_key):
    if isinstance(json_object, dict):
        for key, value in json_object.items():
            if key == lookup_key:
                yield value
            else:
                yield from _item_generator(value, lookup_key)
    elif isinstance(json_object, list):
        for item in json_object:
            yield from _item_generator(item, lookup_key)


def _mean(lst: list) -> int:
    return sum(lst) // len(lst)


def _construct_device_info(data):
    device_info = {}
    host_index = 1
    for device in data:
        address = device.get('address')
        device_info[address] = {
            'address': address,
            'name': device.get('device_name', ""),
            'vendor': device.get('vendor', ""),
            'mean_rssi': _mean(device.get('rssi', [])),
            'address_type': device.get('address_type', ""),
            'connectable': device.get('conn') == 'True',
            'flags': "No flags in data",
            'hostindex': host_index
        }

        for extra in device.get('extra_data', []):
            if extra.get('Type', {}).get('Description') == 'Flags':
                device_info[address]['flags'] = extra.get('Flags', "No flags in data")

        host_index += 1

    return device_info


def bluetooth_low_energy(request):
    r = {'auth': True, 'js': ""}

    ble_file_filename = request.session['scanfile'].replace(".csv", ".json")
    ble_file_filename_without_extension = ble_file_filename.replace('.json', "")
    with open(f"{_BASE_STATIC_BLE_DIR}{ble_file_filename}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    logger.debug(f"Successfully loaded json file {ble_file_filename}")

    # scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    # addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
    file_info_header = json_input[0]

    r['bl_filename'] = ble_file_filename
    r['bl_scan_start_time'] = file_info_header['ble_scan_start_time']
    r['bl_scan_end_time'] = file_info_header['ble_scan_end_time']
    r['bl_interfaces'] = f"HCI {'& '.join(file_info_header['ble_interface'])}"
    r['bl_ltk'] = file_info_header['ble_ltk'] if file_info_header['ble_ltk'] else "None found"
    r['bl_no_ltk'] = len(file_info_header['ble_ltk'])
    r['bl_nr_dev'] = file_info_header['ble_nr_devices']
    r['bl_conn_dev'] = file_info_header['ble_connectable_devices']
    r['ble_readable_dev'] = 0
    r['rssi_graph_path'] = f"{ble_file_filename_without_extension}.svg"

    r['devices'] = _construct_device_info(json_input[1:])

    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + file_info_header['ble_filename'] + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '	});' + \
               '</script>'

    logger.debug(f"Successfully created dict r with display information for the HTML page")

    return r
