import hashlib
import json
import os.path

from django.shortcuts import render

from .zigbee.analyse_json_zigbee_sniff import *
from .zigbee.zigbee_helper import _convert_dot_to_svg
from .zigbee.zigbee_visualize_channels import create_channel_view

_BASE_ZIGBEE_DIR = "/opt/zigbee/"
_BASE_STATIC_ZIGBEE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports/"


def zigbee(request):
    r = {'auth': True}

    with open(f"{_BASE_ZIGBEE_DIR}{request.session['scanfile']}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    # r['out'] = json.dumps(json_input, indent=4)
    # o = json.loads(r['out'])

    scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    # addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

    capture_filename = request.session['scanfile']
    capture_creation_time = get_start_time(json_input)
    capture_finish_time = get_finish_time(json_input)
    capture_nr_packets, capture_nr_zigbee_packets = count_packages_in_file(json_input)
    capture_channel = json_input[0]['sniffing_channel']

    tmp_transport_key = find_transport_keys(json_input)
    capture_nr_trust_keys = len(tmp_transport_key)
    if len(tmp_transport_key) == 1:
        capture_transport_key = tmp_transport_key[0]
    else:
        capture_transport_key = [f"{x}<br>" for x in tmp_transport_key]

    tmp_trust_key = find_trust_key(json_input)
    if len(tmp_trust_key) == 1:
        capture_trust_key = tmp_trust_key[0]
    else:
        capture_trust_key = [f"{x}<br>" for x in tmp_trust_key]

    capture_programs_used = json_input[0]['scan_info']
    capture_sniffing_device = json_input[0]["sniffing_device"]
    capture_sniffing_device_dev_id = json_input[0]["sniffing_device_id"]
    capture_devices = ""
    _, capture_nr_devices = find_unique_devices(json_input)

    if not os.path.isfile(f"{_BASE_STATIC_ZIGBEE_DIR}{capture_filename}_channel.svg"):
        capture_channel_overview_path = create_channel_view(
            "/home/henry/Documents/Masterarbeit/scans_backup/ZigBee/zbstumbler_fake_output.csv",
            "/home/henry/Downloads/channel_graph_dev/myairodump-01.csv",
            f"{capture_filename}", selected_channel=capture_channel
            )
    else:
        capture_channel_overview_path = f"{capture_filename}_channel.svg"

    create_network_graph(json_object=json_input, output_filename=f"{_BASE_STATIC_ZIGBEE_DIR}{capture_filename}.dot")
    capture_network_graph_path = f"{capture_filename}.dot"
    capture_network_graph_render_path = _convert_dot_to_svg(capture_network_graph_path)

    r['js'] = ''

    r['start_time'] = capture_creation_time
    r['filename'] = capture_filename
    r['finish_time'] = capture_finish_time
    r['nr_packets'] = capture_nr_packets
    r['nr_zigbee_packets'] = capture_nr_zigbee_packets
    r['channel'] = capture_channel
    r['transport_key'] = capture_transport_key
    r['nr_transport_key'] = capture_nr_trust_keys
    r['trust_key'] = capture_trust_key
    r['programs'] = capture_programs_used
    r['sniffing_device'] = capture_sniffing_device
    r['sn_device_id'] = capture_sniffing_device_dev_id
    r['devices'] = capture_devices
    r['nr_devices'] = capture_nr_devices
    r['channel_overview_path'] = capture_channel_overview_path
    r['network_graph_path'] = capture_network_graph_path
    r['network_graph_render_path'] = capture_network_graph_render_path.split("/")[-1]
    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + capture_filename + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '	});' + \
               '</script>'

    return r  # ender(request, 'proteciotnet_dev/zigbee_device_overview.html', r)
