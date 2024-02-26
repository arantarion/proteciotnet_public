import json
import os.path
import logging

from configparser import ConfigParser, ExtendedInterpolation

from .zigbee.zigbee_visualize_events import find_events_in_sniff
from .functions import create_file_dropdown_zigbee
from .zigbee.analyse_json_zigbee_sniff import *
from .zigbee.zigbee_visualize_channels import create_channel_view

logger = logging.getLogger(__name__)

#_BASE_ZIGBEE_DIR = "/opt/zigbee/"
#_BASE_STATIC_ZIGBEE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports/"

try:
    config_view_zigbee = ConfigParser(interpolation=ExtendedInterpolation())
    config_view_zigbee.read('proteciotnet.config')
    _ZIGBEE_JSON_BASE_DIRECTORY = config_view_zigbee.get('ZIGBEE_PATHS', 'zigbee_json_base_directory')
    _ZIGBEE_REPORTS_DIRECTORY = config_view_zigbee.get('ZIGBEE_PATHS', 'zigbee_reports_directory')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e}")
    exit(-3)


def _convert_dot_to_svg(filepath: str) -> str:
    """
    Convert a dot file to an SVG file.

    This function attempts to convert a dot file to an SVG file using the Graphviz `dot` command.
    If the SVG file already exists, it does not perform the conversion.

    Args:
        filepath (str): The path to the dot file.

    Returns:
        str: The path to the generated SVG file.

    Note:
        This function relies on the Graphviz `dot` command.
        Make sure Graphviz is installed and accessible in the system path for this function to work correctly.
    """

    logger.info("Trying to convert dot file to svg...")
    if not os.path.exists(f"{_ZIGBEE_REPORTS_DIRECTORY}/{filepath}.svg"):
        logger.debug(f"File ({filepath}) does not exist. Trying create with dot command")
        os.popen(f"sudo dot -T svg {_ZIGBEE_REPORTS_DIRECTORY}/{filepath} -o {_ZIGBEE_REPORTS_DIRECTORY}/{filepath}.svg")
        logger.debug(f"Converted {filepath} to svg file")
    logger.info(f"SVG file is in directory {_ZIGBEE_REPORTS_DIRECTORY}/{filepath}.svg")
    return f"{_ZIGBEE_REPORTS_DIRECTORY}/{filepath}.svg"


def zigbee(request) -> dict:
    """
    Process Zigbee data and generate analytics, channel overview, network graph and timeline.

    Args:
        request: The HTTP request object.

    Returns:
        dict: A dictionary containing processed data and paths to generated visualizations.
    """

    r = {'auth': True}

    with open(f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{request.session['scanfile']}", "r", encoding='utf-8') as f:
        json_input = json.load(f)
        logger.debug(f"Json input successfully set from {_ZIGBEE_JSON_BASE_DIRECTORY}/{request.session['scanfile']}")

    capture_filename = request.session['scanfile']
    logger.debug(f"capture filename is {capture_filename}")

    capture_creation_time = get_start_time(json_input)
    logger.debug(f"capture creation time is {capture_creation_time}")

    capture_finish_time = get_finish_time(json_input)
    logger.debug(f"capture_finish_time is {capture_finish_time}")

    capture_nr_packets, capture_nr_zigbee_packets = count_packages_in_file(json_input)
    logger.debug(f"number of packets is {capture_nr_packets}")

    capture_channel = json_input[0]['sniffing_channel']
    logger.debug(f"capture channel is {capture_channel}")

    tmp_transport_key = find_transport_keys(json_input)
    logger.debug(f"tmp_transport_key is {tmp_transport_key}")

    capture_nr_trust_keys = len(tmp_transport_key)
    logger.debug(f"capture_nr_trust_keys is {capture_nr_trust_keys}")

    if len(tmp_transport_key) == 1:
        capture_transport_key = tmp_transport_key[0]
    else:
        capture_transport_key = [f"{x}<br>" for x in tmp_transport_key]
    logger.debug(f"capture_transport_key is {capture_transport_key}")

    tmp_trust_key = find_trust_key(json_input)
    logger.debug(f"tmp_trust_key is {tmp_trust_key}")
    if len(tmp_trust_key) == 1:
        capture_trust_key = tmp_trust_key[0]
    else:
        capture_trust_key = [f"{x}<br>" for x in tmp_trust_key]
    logger.debug(f"capture_trust_key is {capture_trust_key}")

    capture_programs_used = json_input[0]['scan_info']
    logger.debug(f"capture_programs_used is {capture_programs_used}")

    capture_sniffing_device = json_input[0]["sniffing_device"]
    logger.debug(f"capture_sniffing_device is {capture_sniffing_device}")

    capture_sniffing_device_dev_id = json_input[0]["sniffing_device_id"]
    logger.debug(f"capture_sniffing_device_dev_id is{capture_sniffing_device_dev_id}")

    capture_devices = ""
    _, capture_nr_devices = find_unique_devices(json_input)
    logger.debug(f"capture_nr_devices is {capture_nr_devices}")

    # Check if channel overview graphic is already created
    if not os.path.isfile(f"{_ZIGBEE_REPORTS_DIRECTORY}/{capture_filename}_channel.svg"):
        logger.info(f"Channel overview does not exist. Creating channel overview.")
        capture_channel_overview_path = create_channel_view(
            zigbee_channel_capture_filename="/home/henry/Documents/Masterarbeit/scans_backup/ZigBee/zbstumbler.csv",
            wifi_channel_capture_filename=f"{_ZIGBEE_JSON_BASE_DIRECTORY}/myairodump-01.csv",
            output_filename="{capture_filename}",
            selected_channel=capture_channel
            )
        logger.info(f"successfully created channel overview.")
    else:
        logger.info(f"Channel graph already exists. Skipping creation.")
        capture_channel_overview_path = f"{capture_filename}_channel.svg"

    # Check if network overview graphic is already created
    if not os.path.isfile(f"{_ZIGBEE_REPORTS_DIRECTORY}/{capture_filename}.dot.svg"):
        logger.info(f"Network overview does not exist. Creating network overview.")
        create_network_graph(json_object=json_input,
                             output_filename=f"{_ZIGBEE_REPORTS_DIRECTORY}/{capture_filename}.dot")
        logger.info(f"successfully created network graph")
        capture_network_graph_path = f"{capture_filename}.dot"
        logger.debug(f"capture_network_graph_path: {capture_network_graph_path}")
        logger.info(f"creating svg file from dot file.")
        capture_network_graph_render_path = _convert_dot_to_svg(capture_network_graph_path)
        logger.info(f"successfully created svg from network graph render. Path is {capture_network_graph_render_path}")
    else:
        logger.info(f"Network graph already exists. Skipping creation.")
        capture_network_graph_path = f"{capture_filename}.dot"
        capture_network_graph_render_path = f"{_ZIGBEE_REPORTS_DIRECTORY}/{capture_filename}.dot.svg"
        logger.debug(f"capture_network_graph_path: {capture_network_graph_render_path} \n"
                     f"capture_network_graph_path: {capture_network_graph_path}")

    # Check if event timeline graphic is already created
    if not os.path.isfile(f"{_ZIGBEE_REPORTS_DIRECTORY}/{capture_filename}_timeline.svg"):
        logger.info(f"Timeline does not exist. Creating timeline.")
        event_timeline_path = find_events_in_sniff(pcap_sniff_filename=f'{capture_filename}')
        logger.info(f"Successfully created timeline. event_timeline_path: {event_timeline_path}")
    else:
        logger.info(f"Timeline already exists. Skipping creation.")
        event_timeline_path = f"{capture_filename}_timeline.svg"
        logger.debug(f"event_timeline_path: {event_timeline_path}")

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
    r['timeline_path'] = event_timeline_path
    r['file_dropdown'] = create_file_dropdown_zigbee(capture_filename)
    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + capture_filename + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '	});' + \
               '</script>'

    logger.debug(f"Data to send: {r}")

    return r
