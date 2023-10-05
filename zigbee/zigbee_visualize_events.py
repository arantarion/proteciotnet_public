import json
import warnings
from datetime import datetime
import matplotlib.dates as mdates
from matplotlib import pyplot as plt
import logging

from proteciotnet_dev.zigbee.analyse_json_zigbee_sniff import _get_vendor_from_mac

logging.getLogger('matplotlib.font_manager').disabled = True
warnings.filterwarnings('ignore')

_BASE_ZIGBEE_DIR = "/opt/zigbee/"
_BASE_STATIC_ZIGBEE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports/"


def item_generator(json_object, lookup_key):
    if isinstance(json_object, dict):
        for key, value in json_object.items():
            if key == lookup_key:
                yield value
            else:
                yield from item_generator(value, lookup_key)
    elif isinstance(json_object, list):
        for item in json_object:
            yield from item_generator(item, lookup_key)


def parse_datetime(date_string):
    split_date_string = date_string.split(" ")
    date = " ".join(split_date_string[:2]).replace(",", "")
    time = split_date_string[3][:11]
    # time_obj = datetime.strptime(time, "%H:%M:%S.%f").time()
    timezone = split_date_string[4]
    return date, time, timezone


def find_events_in_sniff(pcap_sniff_filename):
    with open(f"{_BASE_ZIGBEE_DIR}{pcap_sniff_filename}", "r", encoding='utf-8') as f:
        json_input = json.load(f)

    # DATA = zbee_nwk.frame_type ==  "0x0000"
    # COMMAND = zbee_nwk.frame_type ==  "0x0001"

    timeline = {}
    for device in item_generator(json_input, "layers"):
        zbee_nwk_frame_type = next(item_generator(device, "zbee_nwk.frame_type"), "")
        if zbee_nwk_frame_type == "0x0000":
            frame_time = next(item_generator(device, "frame.time"), "")
            zbee_nwk_src64 = next(item_generator(device, "zbee_nwk.src64"), "")

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
    ax.xaxis.set_major_locator(mdates.SecondLocator(interval=10))  # Adjust interval as needed
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.xticks(rotation=90)
    plt.tight_layout()

    ax.set_axisbelow(True)
    plt.grid(True, linestyle='--', alpha=0.7, axis='y')

    plt.savefig(f'{_BASE_STATIC_ZIGBEE_DIR}{pcap_sniff_filename}_timeline.svg', format="svg", transparent=True)

    return f"{pcap_sniff_filename}_timeline.svg"
