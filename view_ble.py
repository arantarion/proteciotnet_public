import base64
import hashlib
import html
import json
import logging
import os.path
import re
import urllib.parse

from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.functions import label_to_color, label_to_margin

# _BASE_BLE_DIR = "/opt/ble/"
# _BASE_STATIC_BLE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/ble_reports/"

logger = logging.getLogger(__name__)

try:
    config_view_ble = ConfigParser(interpolation=ExtendedInterpolation())
    config_view_ble.read('proteciotnet.config')
    _BLE_CSV_BASE_DIRECTORY = config_view_ble.get('BLE_PATHS', 'ble_csv_base_directory')
    _BLE_REPORTS_DIRECTORY = config_view_ble.get('BLE_PATHS', 'ble_reports_directory')
    _NOTES_DIRECTORY = config_view_ble.get('GENERAL_PATHS', 'notes_directory')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e}")
    exit(-3)


def _item_generator(json_object, lookup_key: str) -> any:
    """
    Recursively iterate over a JSON object to yield values corresponding to a given key.

    Args:
        json_object (dict or list): The JSON object to iterate over.
        lookup_key (str): The key to look up in the JSON object.

    Yields:
        Any: The values corresponding to the given key in the JSON object.
    """
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
    """
    Calculate the mean of a list of numbers.

    Args:
        lst (list): A list of numbers.

    Returns:
        int: The mean of the numbers in the list.
    """
    return sum(lst) // len(lst)


def _rssi_to_distance(rssi: int) -> float:
    """
    Convert RSSI (Received Signal Strength Indication) to distance using the log-distance path loss model.

    Args:
        rssi (int): The Received Signal Strength Indication value.

    Returns:
        float: The estimated distance corresponding to the RSSI value.
    """
    # Path loss exponent
    n = 2
    # Measured power (RSSI) at reference distance
    mp = -69
    logger.debug("Calculating distance in meters based on rssi value")
    return round(10 ** ((mp - (int(rssi))) / (10 * n)), 2)


def _replace_bools_with_strings(obj):
    """
    Replace boolean values with their string representations in a nested dictionary or list.

    Args:
        obj (dict, list, bool, or other): The input object which may contain boolean values.

    Returns:
        dict, list, or other: A new object with boolean values replaced by their string representations.
    """
    logger.debug("Replacing boolean values with their string")
    if isinstance(obj, dict):
        return {k: _replace_bools_with_strings(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_replace_bools_with_strings(element) for element in obj]
    elif isinstance(obj, bool):
        return str(obj)  # Converts the boolean to a lowercase string
    else:
        return obj


def _resolve_random_addr_type(address: str) -> str:
    """
    Resolve the type of a random address based on its most significant bits.

    Args:
        address (str): The random address in hexadecimal format (e.g., "AA:BB:CC:DD:EE:FF").

    Returns:
        str: A string representing the type of the random address.
            This string includes HTML formatting for display purposes.
    """
    binary_mac = bin(int(address.replace(":", ""), 16))[2:].zfill(48)
    msb = binary_mac[-2:]
    private_addr_type = "unknown"
    if msb == '11':
        private_addr_type = "Random Address <br>&nbsp;&nbsp;&nbsp;&nbsp;&rarr; <u>Static Address</u> <br> This type of address is trackable depending on the re-randomization interval."
    elif msb == '10':
        private_addr_type = "Random Address <br>&nbsp;&nbsp;&nbsp;&nbsp;&rarr; Private Address <br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&rarr; <u>Resolvable Address</u> <br> This type of address is only minimally trackable (e.g. using device specifc data)."
    elif msb == '00':
        private_addr_type = "Random Address <br>&nbsp;&nbsp;&nbsp;&nbsp;&rarr; Private Address <br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&rarr; <u>Non-Resolvable Address</u> <br> This type of address is only minimally trackable (e.g. using device specifc data)."

    return f"""<div class="tt2">Random<sup style="font-size: 70%; position: relative; top: 0.1em; left: -0.2em;"><span class="material-icons" style="font-size: inherit;">question_mark</span></sup><span class="ttt2">{private_addr_type}</span></div>"""


def _construct_device_info(data: list, md5_sum_of_scanfile: str):
    """
    Helper function:
    Construct device information based on the provided data and MD5 sum of the scan file.

    Args:
        data (list): A list containing information about devices.
        md5_sum_of_scanfile (str): The MD5 sum of the scan file.

    Returns:
        tuple: A tuple containing device information and the total count of readable characteristics.
            - device_info (dict): A dictionary containing device information.
            - readable_characteristics_count_all (int): The total count of readable characteristics.
    """

    logger.debug("Constructing BLE device information")
    device_info = {}
    host_index = 1
    readable_characteristics_count_all = 0

    labels_of_host = {}
    label_files = os.listdir(_NOTES_DIRECTORY)
    logger.debug(f"Collecting labels in {_NOTES_DIRECTORY}")
    for lf in label_files:
        m = re.match('^(' + md5_sum_of_scanfile + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labels_of_host:
                labels_of_host[m.group(1)] = {}
            labels_of_host[m.group(1)][m.group(2)] = open('/opt/notes/' + lf, 'r').read()

    notes_of_host = {}
    notes_files = os.listdir(_NOTES_DIRECTORY)
    logger.debug(f"Collecting notes in {_NOTES_DIRECTORY}")
    for nf in notes_files:
        m = re.match('^(' + md5_sum_of_scanfile + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in notes_of_host:
                notes_of_host[m.group(1)] = {}
            notes_of_host[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()

    logger.debug(f"Generating per device information")
    for device in data:
        logger.debug(f"Current device: {device}")
        address = device.get('address')
        addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

        public_addr_tooltip_text = "<u>Public Address</u> <br> This type of address is easily trackable as it does not change."
        public_addr_tooltip_html = f"""<div class="tt2">Public<sup style="font-size: 70%; position: relative; top: 0.1em; left: -0.2em;"><span class="material-icons" style="font-size: inherit;">question_mark</span></sup><span class="ttt2">{public_addr_tooltip_text}</span></div>"""

        mean_rssi = _mean(device.get('rssi', []))
        rssi_tooltip_html = f"""<div class="tt2">{mean_rssi} dBm<sup style="font-size: 70%; position: relative; top: 0.1em; left: -0.2em;"><span class="material-icons" style="font-size: inherit;">question_mark</span></sup><span class="ttt2">Distance: about {_rssi_to_distance(mean_rssi)} meters from the USB dongle</span></div>"""

        device_info[address] = {
            'address': address,
            'address_linked': address,
            'name': device.get('device_name', ""),
            'vendor': device.get('vendor', ""),
            'mean_rssi': rssi_tooltip_html,
            'address_type': device.get('address_type', ""),
            'random_addr_resolved_type': _resolve_random_addr_type(address) if device.get('address_type',
                                                                                          "") == "random" else public_addr_tooltip_html,
            'connectable': device.get('conn') == 'True',
            'flags': dict(),
            'hostindex': host_index,
            'characteristics_count': 0
        }

        total_characteristics_count = 0
        attribute_data = device.get("attribute_data", {})
        if attribute_data:
            services = attribute_data.get("services", [])
            for service in services:
                total_characteristics_count += len(service.get("characteristics", []))

        device_info[address]['characteristics_count'] = total_characteristics_count

        for extra in device.get('extra_data', []):
            if isinstance(extra, dict):
                dev_type = extra.get('Type', {})

                if dev_type:
                    dev_desc = dev_type.get('Description', "")
                    if dev_desc == 'Flags':
                        device_info[address]['flags'] = extra.get('Flags', "")

        if not device_info[address]['flags']:
            device_info[address]['flags'] = {'LE Limited Discoverable Mode': 'False',
                                             'LE General Discoverable Mode': 'False',
                                             'BR/EDR Not Supported': 'False',
                                             'Simultaneous LE and BR/EDR to Same Device Capable (Controller)': 'False',
                                             'Simultaneous LE and BR/EDR to Same Device Capable (Host)': 'False'
                                             }

        labelout = '<span id="hostlabel' + str(host_index) + '"></span>'
        newlabelout = '<div id="hostlabel' + str(host_index) + '"></div><div id="hostlabelbb' + str(
            host_index) + '"></div>'
        if md5_sum_of_scanfile in labels_of_host:
            if addressmd5 in labels_of_host[md5_sum_of_scanfile]:
                labelcolor = label_to_color(labels_of_host[md5_sum_of_scanfile][addressmd5])
                labelmargin = label_to_margin(labels_of_host[md5_sum_of_scanfile][addressmd5])
                labelout = '<span id="hostlabel' + str(
                    host_index) + '" style="margin-left:' + labelmargin + '" class="rightlabel ' + labelcolor + '">' + html.escape(
                    labels_of_host[md5_sum_of_scanfile][addressmd5]) + '</span>'
                newlabelout = '<div id="hostlabel' + str(
                    host_index) + '" style="z-index:99;transform: rotate(-8deg);margin-top:-14px;margin-left:-40px;" class="leftlabel ' + labelcolor + '">' + html.escape(
                    labels_of_host[md5_sum_of_scanfile][addressmd5]) + '</div>' + \
                              '<div id="hostlabelbb' + str(
                    host_index) + '" class="' + labelcolor + '" style="border-radius:0px 4px 0px 4px;z-index:98;position:absolute;width:18px;height:10px;margin-left:-54px;margin-top:-3px;"></div>'

        notesout, notesb64, removenotes = '', '', ''
        if md5_sum_of_scanfile in notes_of_host:
            if addressmd5 in notes_of_host[md5_sum_of_scanfile]:
                notesb64 = notes_of_host[md5_sum_of_scanfile][addressmd5]
                notesout = '<a id="noteshost' + str(
                    host_index) + '" class="grey-text" href="#!" onclick="javascript:openNotes(\'' + hashlib.md5(
                    str(address).encode(
                        'utf-8')).hexdigest() + '\', \'' + notesb64 + '\');"><i class="fas fa-comment"></i> contains notes</a>'
                removenotes = '<li><a href="#!" class="grey-text" onclick="javascript:removeNotes(\'' + addressmd5 + '\', \'' + str(
                    host_index) + '\');">Remove notes</a></li>'

        device_info[address].update({'addressmd5': addressmd5,
                                     'removenotes': removenotes,
                                     'labelout': labelout,
                                     'newlabelout': newlabelout,
                                     'notesb64': notesb64,
                                     'notesout': notesout})

        if total_characteristics_count > 0 or device.get('extra_data', []):
            device_info[address]['address_linked'] = f'{address} '

        host_index += 1
        readable_characteristics_count_all += total_characteristics_count

    logger.info("Constructed device information successfully")
    logger.debug(f"device info: {device_info}")
    logger.debug(f"readable characteristics count: {readable_characteristics_count_all}")
    return device_info, readable_characteristics_count_all


def bluetooth_low_energy(request) -> dict:
    """
    Main function to handle BLE data and generate objects for the view.

    Args:
        request: The request object.

    Returns:
        dict: A dictionary containing information for generating the response.
    """

    logger.info(f"Generating ble device information return object.")
    r = {'auth': True, 'js': ""}

    ble_file_filename = request.session['scanfile'].replace(".csv", ".json")
    ble_file_filename_without_extension = ble_file_filename.replace('.json', "")
    with open(f"{_BLE_REPORTS_DIRECTORY}{ble_file_filename}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    logger.debug(f"Successfully loaded json file {ble_file_filename}")

    md5_sum_of_scanfile = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    r['md5_sum_of_scanfile'] = md5_sum_of_scanfile
    logger.debug(f"file hash is: {md5_sum_of_scanfile}")

    file_info_header = json_input[0]

    r['bl_filename'] = ble_file_filename
    r['bl_scan_start_time'] = file_info_header['ble_scan_start_time']
    r['bl_scan_end_time'] = file_info_header['ble_scan_end_time']
    r['bl_interfaces'] = f"HCI {'& '.join(file_info_header['ble_interface'])}"
    r['bl_ltk'] = file_info_header['ble_ltk'] if file_info_header['ble_ltk'] else "None found"
    r['bl_no_ltk'] = len(file_info_header['ble_ltk'])
    r['bl_nr_dev'] = file_info_header['ble_nr_devices']
    r['bl_conn_dev'] = file_info_header['ble_connectable_devices']
    r['rssi_graph_path'] = f"ble_reports/{ble_file_filename_without_extension}.svg"

    r['devices'], r['ble_readable_dev'] = _construct_device_info(json_input[1:], md5_sum_of_scanfile)

    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + file_info_header['ble_filename'] + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '	});' + \
               '</script>'

    r['sniff_html_output'] = ""
    html_file_filename = f"{ble_file_filename_without_extension}.html"
    if os.path.isfile(f"{_BLE_REPORTS_DIRECTORY}{html_file_filename}"):
        logger.debug(f"Fixing color in html file {html_file_filename}")
        html_file_handle = (open(f"{_BLE_REPORTS_DIRECTORY}{html_file_filename}")
                            .read()
                            .replace("#e5e5e5", "transparent"))
        html_file_handle = html_file_handle.replace(html_file_handle[html_file_handle.find("<body>")+6:html_file_handle.find("<tt>")], "")
        r['sniff_html_output'] += html_file_handle

    logger.info(f"Successfully created dict r with display information.")
    logger.debug(f"return value: {r}")
    return r


def ble_details(request) -> dict:
    """
    Function to handle device details overview in BLE files.

    Args:
        request: The request object.

    Returns:
        dict: A dictionary containing information for generating the response.
    """

    logger.info("Generating device details overview for BLE device.")

    r = {'auth': True, 'js': ""}

    addr = request.get_full_path().split("/")[-1]
    scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    r['md5_sum_of_scanfile'] = scanmd5
    logger.debug(f"md5 sum of scanfile {str(request.session['scanfile'])}: {scanmd5}")

    addressmd5 = hashlib.md5(str(addr).encode('utf-8')).hexdigest()

    logger.debug(f"Collecting all labels in {_NOTES_DIRECTORY}")
    labelhost = {}
    labelfiles = os.listdir(_NOTES_DIRECTORY)
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open(f'{_NOTES_DIRECTORY}/{lf}', 'r').read()

    logger.debug(f"Collecting all notes in {_NOTES_DIRECTORY}")
    noteshost = {}
    notesfiles = os.listdir(_NOTES_DIRECTORY)
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open(f'{_NOTES_DIRECTORY}/{nf}', 'r').read()

    ble_file_filename = request.session['scanfile'].replace(".csv", ".json")
    ble_file_filename_without_extension = ble_file_filename.replace('.json', "")

    with open(f"{_BLE_REPORTS_DIRECTORY}{ble_file_filename}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    logger.debug(f"Successfully loaded json file {ble_file_filename}")

    for elem in json_input:
        if elem.get("address", "") == addr:
            r.update({
                "extra_data": elem.get("extra_data", ""),
                "attribute_data": _replace_bools_with_strings(elem.get("attribute_data", ""))
            })

    r['scan_filename'] = f"{ble_file_filename_without_extension}.csv"
    r['address'] = addr
    r['hostname'] = f'<span class="grey-text"><b>Type:</b> Name</span><br>'
    r['json_output_attribute_data'] = ""

    r['json_output_extra_data'] = f"""
                        <script>
                            var json = {r['extra_data']}
                            $(function(){{
                                var _visualizer = new visualizer($("#output_extra_data"));
                                _visualizer.visualize(json, 'Advertisement Data');
                            }});
                        </script>
                    """

    logger.debug("Put extra data in file")

    if r['attribute_data']:
        r['json_output_attribute_data'] = f"""
                            <script>
                                var json_attr = {[r['attribute_data']]}
                                $(function(){{
                                    var _visualizer_attr = new visualizer($("#output_attribute_data"));
                                    _visualizer_attr.visualize(json_attr, 'Readable Data');
                                }});
                            </script>
                        """

    logger.debug("Put attribute data in file")

    if scanmd5 in labelhost:
        if addressmd5 in labelhost[scanmd5]:
            labelcolor = label_to_color(labelhost[scanmd5][addressmd5])
            r['label'] = html.escape(labelhost[scanmd5][addressmd5])
            r['labelcolor'] = labelcolor

    r['table'] = ''
    if scanmd5 in noteshost:
        if addressmd5 in noteshost[scanmd5]:
            notesb64 = noteshost[scanmd5][addressmd5]
            r['table'] += '<div class="card" style="background-color:#3e3e3e;">' + \
                          '	<div class="card-content"><h5>Notes</h5>' + \
                          '		' + base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii') + \
                          '	</div>' + \
                          '</div>'
            r['notes'] = base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')

    logger.info("Successfully created detail view object. Displaying now.")
    logger.debug(f"return value: {r}")

    return r
