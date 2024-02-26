import json
import logging
import os

import matplotlib.dates as mdates

from datetime import datetime
from matplotlib import pyplot as plt
from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.zigbee.analyse_json_zigbee_sniff import _get_vendor_from_mac

logger = logging.getLogger(__name__)

try:
    config_zigbee_visualize_events = ConfigParser(interpolation=ExtendedInterpolation())
    config_zigbee_visualize_events.read('proteciotnet.config')

    _ZIGBEE_JSON_BASE_DIRECTORY = config_zigbee_visualize_events.get('ZIGBEE_PATHS', 'zigbee_json_base_directory')
    _ZIGBEE_REPORTS_DIRECTORY = config_zigbee_visualize_events.get('ZIGBEE_PATHS', 'zigbee_reports_directory')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def find_value_from_key_in_json(json_object, lookup_key: str):
    """
    Find all values associated with a given key in a JSON-like object.

    Args:
        json_object (dict or list): The JSON-like object to search.
        lookup_key (str): The key to search for.

    Yields:
        The values associated with the given key.
    """

    if isinstance(json_object, dict):
        for key, value in json_object.items():
            if key == lookup_key:
                yield value
            else:
                yield from find_value_from_key_in_json(value, lookup_key)
    elif isinstance(json_object, list):
        for item in json_object:
            yield from find_value_from_key_in_json(item, lookup_key)


def parse_datetime(date_string: str):
    """
    Parse a date-time string into its components.

    Args:
        date_string (str): The date-time string to parse.

    Returns:
        tuple: A tuple containing the date, time, and timezone components.

    Notes:
        This function extracts the date, time, and timezone components from a date-time string
        in the format "Mon dd, yyyy HH:MM:SS +/-TZ".
    """
    split_date_string = date_string.split(" ")
    date = " ".join(split_date_string[:2]).replace(",", "")
    time = split_date_string[3][:11]
    timezone = split_date_string[4]
    return date, time, timezone


def find_events_in_sniff(pcap_sniff_filename: str) -> str:
    """
    Find events in a Zigbee sniffer packet capture file.
    This function reads a JSON file containing packet capture data from a Zigbee sniffer,
    extracts relevant events, and generates a timeline plot showing device timestamps.

    Args:
        pcap_sniff_filename (str): The filename of the Zigbee sniffer packet capture file.

    Returns:
        str: The filename of the generated timeline SVG plot.

    """
    with open(f"{_ZIGBEE_JSON_BASE_DIRECTORY}/{pcap_sniff_filename}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    logger.debug(f"Successfully read JSON file {pcap_sniff_filename}")

    timeline = {}
    for device in find_value_from_key_in_json(json_input, "layers"):
        zbee_nwk_frame_type = next(find_value_from_key_in_json(device, "zbee_nwk.frame_type"), "")
        if zbee_nwk_frame_type == "0x0000":
            frame_time = next(find_value_from_key_in_json(device, "frame.time"), "")
            zbee_nwk_src64 = next(find_value_from_key_in_json(device, "zbee_nwk.src64"), "")

            if zbee_nwk_src64 in timeline:
                timeline[zbee_nwk_src64].append(frame_time)
            else:
                timeline[zbee_nwk_src64] = [frame_time]

    if "" in timeline:
        del timeline[""]

    dates = set()
    timezones = set()
    for key, value in timeline.items():
        for i in range(0, len(value)):
            curr_date, curr_time, curr_timezone = parse_datetime(value[i])
            dates.add(curr_date)
            timezones.add(curr_timezone)
            if curr_time:
                value[i] = curr_time

    for key in timeline:
        timeline[key] = [datetime.strptime(t, "%H:%M:%S.%f").time() for t in timeline[key]]

    # Plotting
    fig, ax = plt.subplots(figsize=(50, 7))
    devices = list(timeline.keys())

    params = {"ytick.color": "#9e9e9e",
              "xtick.color": "#9e9e9e",
              "axes.labelcolor": "#9e9e9e",
              "axes.edgecolor": "#9e9e9e"
              }
    plt.rcParams.update(params)

    for i, device in enumerate(devices):
        times = [datetime.combine(datetime.min, t) for t in timeline[device]]
        ax.plot(times, [i] * len(times), 'o', label=device, markersize=5)

    ax.tick_params(axis='both', colors='#9e9e9e')
    ax.xaxis.label.set_color('#9e9e9e')
    ax.yaxis.label.set_color('#9e9e9e')
    ax.title.set_color('#9e9e9e')

    for label in ax.get_xticklabels():
        label.set_color('#9e9e9e')

    for label in ax.get_yticklabels():
        label.set_color('#9e9e9e')

    for i in range(len(devices)):
        devices[i] = f"{_get_vendor_from_mac(devices[i])} /\n {devices[i]}"

    ax.set_yticks(range(len(devices)))
    ax.set_yticklabels(devices)
    ax.set_xlabel('Time')
    ax.set_title('Device Timestamps')
    ax.xaxis.set_major_locator(mdates.SecondLocator(interval=10))  # Adjust the interval as needed
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.xticks(rotation=90)
    plt.tight_layout()

    ax.set_axisbelow(True)
    plt.grid(True, linestyle='--', alpha=0.7, axis='y')

    plt.savefig(f'{_ZIGBEE_REPORTS_DIRECTORY}/{pcap_sniff_filename}_timeline.svg', format="svg", transparent=True)
    logging.debug(f"Saving timeline to {pcap_sniff_filename}_timeline.svg")
    
    return f"{pcap_sniff_filename}_timeline.svg"
