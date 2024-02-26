import csv
import datetime
import os
import time
import logging

import matplotlib.pyplot as plt
import numpy as np

from matplotlib import patches
from matplotlib.path import Path
from configparser import ConfigParser, ExtendedInterpolation

logger = logging.getLogger(__name__)

try:
    config_zigbee_visualize = ConfigParser(interpolation=ExtendedInterpolation())
    config_zigbee_visualize.read('proteciotnet.config')

    _ZIGBEE_REPORTS_DIR = config_zigbee_visualize.get('ZIGBEE_PATHS', 'zigbee_reports_directory')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def _read_csv(filename: str) -> list:
    """
    Read data from a CSV file.

    Args:
        filename (str): The path to the CSV file.

    Returns:
        list: A list of data rows from the CSV file, excluding the header row.
    """
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        data = list(reader)
    logger.debug(f"Successfully read data from {filename}")
    return data


def _count_zigbee_channels(data: list) -> dict:
    """
    Count the occurrences of Zigbee channels in the provided data.

    Args:
        data (list): A list of data rows, where each row represents a data entry.

    Returns:
        dict: A dictionary where keys are Zigbee channel numbers and values are the corresponding counts.
    """
    channel_counts = {}
    for row in data:
        channel = int(row[5])
        channel_counts[channel] = channel_counts.get(channel, 0) + 1
    logger.debug(f"Successfully counted ZigBee channels: {channel_counts}")
    return channel_counts


def _count_wifi_channels(data: list) -> dict:
    """
    Count the occurrences of Wi-Fi channels in the provided data.

    Args:
        data (list): A list of data rows, where each row represents a data entry.

    Returns:
        dict: A dictionary where keys are Wi-Fi channel numbers and values are the corresponding counts.
    """
    channel_counts = {}
    for row in data:
        try:
            channel = int(row[3])
            channel_counts[channel] = channel_counts.get(channel, 0) + 1
        except:
            pass
    logger.debug(f"Successfully counted WiFi channels: {channel_counts}")
    return channel_counts


def _get_wifi_channels(wifi_interface):
    """
    Perform Wi-Fi channel scanning using airodump-ng.

    Args:
        wifi_interface (str): The name of the Wi-Fi interface to use for scanning.

    Note:
        This function executes shell commands and requires elevated privileges (sudo).
        airodump-ng has to be present in your system's path.

    Warning:
        Improper usage of shell commands may pose security risks.

    """
    os.popen(f"sudo airmon-ng start {wifi_interface}")
    time.sleep(1)
    os.popen(
        f'sudo timeout 15s airodump-ng wlan0mon --output-format csv -w {datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.airodump_wlan0mon_scan')
    time.sleep(1)
    os.popen("sudo airmon-ng stop wlan0mon")


def create_channel_view(zigbee_channel_capture_filename: str,
                        wifi_channel_capture_filename: str,
                        output_filename: str,
                        selected_channel=None) -> str:

    """
    Create a channel view plot comparing Zigbee and Wi-Fi channel distributions.

    Args:
        zigbee_channel_capture_filename (str): The filename of the CSV containing Zigbee channel capture data.
        wifi_channel_capture_filename (str): The filename of the CSV containing Wi-Fi channel capture data.
        output_filename (str): The base filename for the output SVG file.
        selected_channel (str, optional): The selected Wi-Fi channel to highlight in the plot. Defaults to None.

    Returns:
        str: The filename of the generated SVG plot.

    Notes:
        The function generates a plot comparing Zigbee and Wi-Fi channel distributions and saves it as an SVG file.
        Zigbee channels are plotted as arcs, and Wi-Fi channels are represented by colored blocks.
    """

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

    fig, ax = plt.subplots(figsize=(16, 10))

    # draw invisible bar chart to later lay over arcs
    ax.bar(zigbee_channels.keys(), zigbee_channels.values(), width=0.4, label='Zigbee', color='none', linewidth=2,
           capsize=2)

    def create_arc(ax_element, start, end, height, color, channel_desc, order, opacity=0.4):
        """
        Create an arc representing a channel in the channel view plot.

        Args:
            ax_element (matplotlib.axes.Axes): The Axes object where the arc will be drawn.
            start (float): The start position of the arc.
            end (float): The end position of the arc.
            height (float): The height of the arc.
            color (str): The color of the arc.
            channel_desc (str): The description of the channel.
            order (int): The z-order of the arc.
            opacity (float, optional): The opacity of the arc. Default to 0.4.

        Returns:
            None

        Notes:
            This function draws an arc representing a channel in the channel view plot.
            It adds the arc to the specified Axes object and optionally annotates it with a channel description.
        """
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

    plt.savefig(f'{_ZIGBEE_REPORTS_DIR}{output_filename}_channel.svg', format="svg", transparent=True)
    logger.info(f'Saved figure to {output_filename}_channel.svg')

    return f"{output_filename}_channel.svg"
