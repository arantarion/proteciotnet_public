import csv
import json
import warnings

import matplotlib.lines as mlines
import matplotlib.pyplot as plt
import numpy as np
from svgpath2mpl import parse_path
from svgpathtools import svg2paths

warnings.filterwarnings("ignore", category=UserWarning)


def _create_json_info_part(ble_filename, scan_start_time, scan_end_time, interfaces, nr_devices, conn_devices):
    return {
        'ble_filename': ble_filename,
        'ble_scan_start_time': scan_start_time,
        'ble_scan_end_time': scan_end_time,
        'ble_interface': interfaces,
        'ble_ltk': '',
        'ble_nr_devices': nr_devices,
        'ble_connectable_devices': conn_devices,
    }


def csv_to_json(csv_file_path, json_file_path=""):
    data_list = []
    rssi_values = []
    timestamps = []
    device_counter = 0
    conn_device_counter = 0
    interfaces = set()

    with open(csv_file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

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

    with open(json_file_path, 'w') as json_file:
        json.dump(output_data, json_file, indent=4)

    return data_list, rssi_values


def create_rssi_graph(csv_file_path):
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
        key = f"{address} ({device_name})" if device_name else address
        rssi_dict[key] = entry["rssi"]

    fig, ax = plt.subplots(figsize=(12, 12))

    # Custom marker in the shape of a human
    user_path, attributes = svg2paths('/opt/proteciotnet/proteciotnet_dev/static/img/person.svg')
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
                        ha="center")
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
                        ha="center")

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
    ax.legend(handles=markers,
              loc='upper left',
              bbox_to_anchor=(0.5, 1.05),
              ncol=3,
              fancybox=True,
              shadow=True,
              title="Device names")
    ax.spines['right'].set_visible(False)
    ax.spines['top'].set_visible(False)
    plt.ylabel("Distance to user")
    # plt.show()
    plt.savefig("/home/henry/Downloads/my_test_graph.svg",
                format="svg",
                #transparent=True,
                bbox_inches="tight")


csv_file_path = '/home/henry/Downloads/ble_scan_test_data.csv'

ble_scan_results, rssi_values = csv_to_json(csv_file_path, f"{csv_file_path}.json")

create_rssi_graph(csv_file_path)
