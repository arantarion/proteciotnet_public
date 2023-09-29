import csv
import datetime
import os
import time
import warnings

import matplotlib.pyplot as plt
import numpy as np
from matplotlib import patches
from matplotlib.path import Path

warnings.filterwarnings('ignore')

_BASE_STATIC_ZIGBEE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports/"


def _read_csv(filename):
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        data = list(reader)
    return data


def _count_zigbee_channels(data):
    channel_counts = {}
    for row in data:
        channel = int(row[5])
        channel_counts[channel] = channel_counts.get(channel, 0) + 1
    return channel_counts


def _count_wifi_channels(data):
    channel_counts = {}
    for row in data:
        try:
            channel = int(row[3])
            channel_counts[channel] = channel_counts.get(channel, 0) + 1
        except:
            pass
    return channel_counts


def _get_wifi_channels(wifi_interface):
    os.popen(f"sudo airmon-ng start {wifi_interface}")
    time.sleep(1)
    os.popen(
        f'sudo timeout 15s airodump-ng wlan0mon --output-format csv -w {datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.airodump_wlan0mon_scan')
    time.sleep(1)
    os.popen("sudo airmon-ng stop wlan0mon")


def create_channel_view(zigbee_channel_capture_filename,
                        wifi_channel_capture_filename,
                        output_filename,
                        selected_channel=None):
    wifi_channels = _count_wifi_channels(_read_csv(wifi_channel_capture_filename))
    zigbee_channels = _count_zigbee_channels(_read_csv(zigbee_channel_capture_filename))
    zigbee_channels = dict(sorted(zigbee_channels.items()))

    # Set text color to grey tone
    params = {"ytick.color": "#9e9e9e",
              "xtick.color": "#9e9e9e",
              "axes.labelcolor": "#9e9e9e",
              "axes.edgecolor": "#9e9e9e"
              }
    plt.rcParams.update(params)

    # Create figure and axis
    fig, ax = plt.subplots(figsize=(16, 10))

    # draw invisible bar chart to later lay over arcs
    ax.bar(zigbee_channels.keys(), zigbee_channels.values(), width=0.4, label='Zigbee', color='none', linewidth=2,
           capsize=2)

    # Function to create the arcs
    def create_arc(ax_element, start, end, height, color, channel_desc, order, opacity=0.4):
        width = end - start
        center_x = (start + end) / 2
        theta = np.linspace(0, np.pi, 100)
        x = center_x + width / 2 * np.cos(theta)
        y = height * np.sin(theta)
        path = Path(np.column_stack([x, y]))
        patch = patches.PathPatch(path, edgecolor=(color, 1), facecolor=(color, opacity), zorder=order)
        ax_element.add_patch(patch)
        if channel_desc:
            ax_element.annotate(channel_desc,
                                xy=(center_x, height),
                                xytext=(center_x, height + 5),
                                color="#9e9e9e",
                                fontsize=13,
                                arrowprops=dict(arrowstyle='-', color="#9e9e9e", linestyle=':', linewidth=2),
                                )

    # Creating Zigbee arcs
    for i in range(11, 27):
        if selected_channel is not None and i == int(selected_channel):
            # Add an arrow and text for the selected channel
            ax.annotate("Your Channel",
                        xy=(i, zigbee_channels[i]),
                        xytext=(i, zigbee_channels[i] + 1),
                        color="#9e9e9e",
                        fontsize=13,
                        arrowprops=dict(arrowstyle='->', color="#9e9e9e", linestyle=':', linewidth=2),
                        zorder=3
                        )

        create_arc(ax_element=ax,
                   start=i - 0.45,
                   end=i + 0.45,
                   height=zigbee_channels[i],
                   color='#ff9800',
                   channel_desc='',
                   order=2,
                   opacity=0.6)

    # Creating Wi-Fi arcs
    create_arc(ax_element=ax,
               start=11 - 0.45,
               end=14 + 0.45,
               height=wifi_channels[1],
               color='#2196F3',
               channel_desc='WiFi Channel 1 (2421MHz)',
               order=1)
    create_arc(ax_element=ax,
               start=16 - 0.45,
               end=19 + 0.45,
               height=wifi_channels[6],
               color='#2196F3',
               channel_desc='WiFi Channel 6 (2437MHz)',
               order=1)
    create_arc(ax_element=ax,
               start=21 - 0.45,
               end=24 + 0.45,
               height=wifi_channels[11],
               color='#2196F3',
               channel_desc='WiFi Channel 11 (2462MHz)',
               order=1)

    # Set label etc
    ax.set_xlabel('Channel (MHz)', fontsize=14)
    ax.set_ylabel('Number of Devices', fontsize=14)
    ax.set_xticks(list(zigbee_channels.keys()))
    ax.set_xticklabels([f'{ch} ({2405 + 5 * (ch - 11)}MHz)' for ch in sorted(zigbee_channels.keys())],
                       rotation=90,
                       fontsize=13
                       )
    plt.yticks(fontsize=13)
    plt.tight_layout()

    ax.set_axisbelow(True)
    plt.grid(True, linestyle='--', alpha=0.7, axis='y')

    plt.savefig(f'{_BASE_STATIC_ZIGBEE_DIR}{output_filename}_channel.svg', format="svg", transparent=True)

    return f"{output_filename}_channel.svg"


# create_channel_view("/home/henry/Documents/Masterarbeit/scans_backup/ZigBee/zbstumbler_fake_output.csv",
#                     "/home/henry/Downloads/channel_graph_dev/myairodump-01.csv",
#                     "zigbee_scan_today"
#                     )
