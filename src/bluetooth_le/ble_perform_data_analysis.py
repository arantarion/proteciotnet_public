import csv
import json
import subprocess
import warnings
import logging

import matplotlib.lines as mlines
import matplotlib.pyplot as plt
import numpy as np

from svgpath2mpl import parse_path
from svgpathtools import svg2paths
from multiprocessing import Process
from configparser import ConfigParser, ExtendedInterpolation

warnings.filterwarnings("ignore", category=UserWarning)

logger = logging.getLogger(__name__)

try:
    config_ble_scan = ConfigParser(interpolation=ExtendedInterpolation())
    config_ble_scan.read('proteciotnet.config')

    _XSL_FILE_LOCATION = config_ble_scan.get('BLE_PATHS', 'xsl_file_location')
    _BLUETOOTH_WIRESHARK_DISPLAY_FILTER = config_ble_scan.get('BLE', 'bluetooth_wireshark_display_filter')
    _BLE_REPORTS_DIRECTORY = config_ble_scan.get('BLE_PATHS', 'ble_reports_directory')

    _STATIC_DIRECTORY = config_ble_scan.get('GENERAL_PATHS', 'static_directory')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def _create_json_info_part(ble_filename: str, scan_start_time: str, scan_end_time: str, interfaces: str, nr_devices: int, conn_devices: int) -> dict:
    """
    Create a JSON object containing BLE scan information.

    Args:
        ble_filename (str): The name of the BLE scan file.
        scan_start_time (str): The start time of the BLE scan.
        scan_end_time (str): The end time of the BLE scan.
        interfaces (str): Information about the BLE interfaces used for scanning.
        nr_devices (int): The total number of BLE devices detected.
        conn_devices (int): The number of connectable BLE devices.

    Returns:
        dict: A JSON object containing BLE scan information.
    """
    return {
        'ble_filename': ble_filename,
        'ble_scan_start_time': scan_start_time,
        'ble_scan_end_time': scan_end_time,
        'ble_interface': interfaces,
        'ble_ltk': '',
        'ble_nr_devices': nr_devices,
        'ble_connectable_devices': conn_devices,
    }


def csv_to_json(csv_file_path: str, json_file_path: str = ""):
    """
    Convert a CSV file containing BLE scan data to a JSON file.

    Args:
        csv_file_path (str): The path to the input CSV file.
        json_file_path (str, optional): The path to save the output JSON file. If not provided,
            the JSON data will be returned without saving to a file. Defaults to "".

    Returns:
        tuple: A tuple containing two elements:
            - A list of dictionaries representing the BLE scan data.
            - A list of lists containing RSSI values.
    """
    data_list = []
    rssi_values = []
    timestamps = []
    device_counter = 0
    conn_device_counter = 0
    interfaces = set()

    with open(csv_file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        logger.debug(f"Reading CSV file {csv_file_path}")

        for row in csv_reader:
            device_counter += 1
            if row['conn'] == "True":
                conn_device_counter += 1
            interfaces.add(row['interface'])
            timestamps.append(row['timestamp'])
            row['rssi'] = [int(val) for val in row['rssi'].split('>')]
            row['extra_data'] = json.loads(row['extra_data']
                                           .replace("'", '"')
                                           .replace(' True', ' "True"')
                                           .replace(' False', ' "False"'))
            if row['attribute_data']:
                row['attribute_data'] = json.loads(row['attribute_data']
                                                   .replace("'", '"')
                                                   .replace(' True', ' "True"')
                                                   .replace(' False', ' "False"'))
            data_list.append(row)
            rssi_values.append(row['rssi'])

        info_header_json = _create_json_info_part(ble_filename=csv_file_path,
                                                  scan_start_time=min(timestamps),
                                                  scan_end_time=max(timestamps),
                                                  interfaces=list(interfaces),
                                                  nr_devices=device_counter,
                                                  conn_devices=conn_device_counter)
    output_data = data_list.copy()
    output_data.insert(0, info_header_json)

    logger.debug(f"Read file {csv_file_path}")

    with open(json_file_path, 'w') as json_file:
        json.dump(output_data, json_file, indent=4)
        logger.debug(f"Successfully written json file {json_file_path}")

    logger.debug(f"data_list: {data_list}")
    logger.debug(f"rssi_values: {rssi_values}")
    return data_list, rssi_values


def create_rssi_graph(csv_file_path: str, ble_scan_results: list, output_path: str) -> None:
    """
    Create an SVG graph representing the RSSI values of BLE scan results.

    Args:
        csv_file_path (str): Path to the CSV file containing BLE scan data.
        ble_scan_results (list): List of dictionaries representing BLE scan results.
        output_path (str): Path to save the output SVG graph.

    Returns:
        None
    """
    rssi_values = []
    with open(csv_file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            row['rssi'] = [int(val) for val in row['rssi'].split('>')]
            rssi_values.append(row['rssi'])

    rssi_dict = {}
    for entry in ble_scan_results:
        address = entry.get("address", "")
        device_name = entry.get("device_name", "")
        company = entry.get('vendor', "")
        key = f"{address} ({device_name})" if device_name else f"{address} ({company})"
        rssi_dict[key] = entry["rssi"]

    fig, ax = plt.subplots(figsize=(12, 12))

    # Custom marker in the shape of a human
    user_path, attributes = svg2paths(f'{_STATIC_DIRECTORY}/img/person.svg')
    user_marker = parse_path(attributes[0]['d'])

    min_rssi, max_rssi = -100, 0
    ranges = [0.3, 0.6, 0.9]
    device_x_positions = np.linspace(0.1, 0.9, len(rssi_values))
    colors = plt.cm.viridis(np.linspace(0, 1, len(rssi_values)))

    # Generate custom markers to be displayed in the legend
    markers = []
    for idx, rssi_value in enumerate(rssi_values):
        address = next((addr for addr, rssi in rssi_dict.items() if rssi == rssi_value), None)
        circle_marker = mlines.Line2D([], [],
                                      marker='o',
                                      linestyle='None',
                                      markersize=10,
                                      label=address,
                                      color=colors[idx])
        markers.append(circle_marker)

    # place the data in the graph
    # if the rssi is more than 1 value a dot is calculated with the appropiate size to visualize the flucuation of the RSSI
    for idx, rssi_value in enumerate(rssi_values):
        if len(rssi_value) != 1:
            avg_rssi = np.mean(rssi_value)
            norm_avg_rssi = (avg_rssi - min_rssi) / (max_rssi - min_rssi)
            y_coord = norm_avg_rssi * (max(ranges) - min(ranges)) + min(ranges)
            rssi_fluctuation = np.ptp(rssi_value)
            fluctuation_scale = 0.01  # Adjust if necessary
            circle_size = rssi_fluctuation * fluctuation_scale
            circle = plt.Circle((device_x_positions[idx], y_coord), circle_size,
                                color=colors[idx],
                                alpha=0.6,
                                edgecolor='black')
            ax.annotate(avg_rssi,
                        xy=(device_x_positions[idx], y_coord),
                        fontsize=10,
                        ha="center",
                        color="white")
            ax.add_patch(circle)

        else:
            avg_rssi = np.mean(rssi_value)
            norm_avg_rssi = (avg_rssi - min_rssi) / (max_rssi - min_rssi)
            y_coord = norm_avg_rssi * (max(ranges) - min(ranges)) + min(ranges)
            ax.plot(device_x_positions[idx],
                    y_coord,
                    'o',
                    markersize=10,
                    color=colors[idx])
            ax.annotate(avg_rssi,
                        xy=(device_x_positions[idx], y_coord),
                        fontsize=10,
                        ha="center",
                        color="white")

    # Place the user circle at the bottom of the graph
    ax.plot(0.5, 0.0,
            marker=user_marker,
            markersize=100)

    # Place the dashed lines to indicate the distance (ignore the first because it is at x=0)
    linsp = np.linspace(0, max(ranges), 5)
    for val in linsp[1:]:
        ax.axhline(y=val,
                   linestyle="dashed",
                   color="gray")

    # General plot styling
    ax.set_aspect('equal')
    ax.set_xlim(0, 1)
    ax.set_ylim(0, max(ranges))
    ax.spines['left'].set_position('zero')
    ax.set_yticks(np.linspace(0, max(ranges), 5))
    ax.set_yticklabels(["Immediate", "Near", "Midrange", "Far", "Very Far"])
    ax.set_xticks([])
    ax.set_xticklabels("")
    legend = ax.legend(handles=markers,
                       loc='upper left',
                       bbox_to_anchor=(1.02, 1),
                       ncol=2,
                       fancybox=True,
                       shadow=False,
                       title="Device names",
                       labelcolor="white",
                       edgecolor='none',
                       framealpha=0)
    plt.setp(legend.get_title(), color='white')
    legend.get_frame().set_alpha(0)
    legend.get_frame().set_facecolor((0, 0, 0, 0))
    ax.spines['right'].set_visible(False)
    ax.spines['top'].set_visible(False)
    plt.ylabel("Distance to user", color='white')

    ax.tick_params(axis='x', colors='white')
    ax.tick_params(axis='y', colors='white')

    # Changing the spine colors
    for spine in ax.spines.values():
        spine.set_color('white')

    logger.debug("Created RSSI graph.")
    plt.savefig(output_path,
                format="svg",
                transparent=True,
                bbox_inches="tight")


def convert_ble_sniff_to_html(filename: str):
    """
    Convert a BLE sniffing pcap file to HTML format using tshark and XSLT transformation.

    Args:
        filename (str): Path to the input pcap file.

    Returns:
        multiprocessing.Process: Process object for the conversion task.
    """

    def conversion_process():
        """
        Convert a BLE sniffing pcap file to HTML format using tshark and XSLT transformation.

        Returns:
            None
        """
        base_filename = filename.split("/")[-2]
        pdml_filename = base_filename + '.pdml'
        html_filename = base_filename + '.html'

        # Convert pcap to pdml
        tshark_cmd = f"tshark -r {filename} -Y '{_BLUETOOTH_WIRESHARK_DISPLAY_FILTER}' -T pdml > {_BLE_REPORTS_DIRECTORY}({pdml_filename}"
        logger.debug(f"tshark_cmd: {tshark_cmd}")
        subprocess.run(tshark_cmd, shell=True)

        # Convert pdml to html
        xslt_cmd = f"xsltproc {_XSL_FILE_LOCATION} {_BLE_REPORTS_DIRECTORY}/{pdml_filename} > {_BLE_REPORTS_DIRECTORY}/{html_filename}"
        logger.debug(f"xslt_cmd: {xslt_cmd}")
        subprocess.run(xslt_cmd, shell=True)

    process = Process(target=conversion_process)
    process.start()
    return process
