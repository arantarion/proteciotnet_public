from collections import Counter
from zigbee.zigbee_helper import _find_reciprocal_pairs, _generate_dot_file, _convert_timezone

# path_to_file = '/home/henry/Documents/Masterarbeit/scans_backup/ZigBee/json_files/all_dev.json'
#
# with open(path_to_file, "r", encoding='utf-8') as f:
#     json_input = json.load(f)


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


def find_trust_key(json_object):
    return set([x for x in item_generator(json_object, "zbee.sec.key")]) - set(find_transport_keys(json_object))


def find_transport_keys(json_object):
    return set([x for x in item_generator(json_object, "zbee_aps.cmd.key")])


def find_unique_devices(json_object):
    devices = []
    for packet in item_generator(json_object, "wpan"):
        try:
            devices.append(packet['wpan.src64'])
        except KeyError:
            pass

    devices_counted = Counter(devices)
    return devices_counted, len(set(devices_counted))


def count_packages_in_file(json_object):
    nr_packages = len(json_object)
    nr_zigbee_packages = nr_packages - len([x for x in item_generator(json_object, "frame.len") if x == "5"])

    return nr_packages, nr_zigbee_packages


def get_start_time(json_object):
    time = next(item_generator(json_object[0], "frame.time"), None)
    return _convert_timezone(time)


def get_finish_time(json_object):
    time = next(item_generator(json_object[-1], "frame.time"), None)
    return _convert_timezone(time)


def create_network_graph(json_object, output_filename):
    source_dest = set()
    mapping_addr16_addr64 = {}
    for elem in item_generator(json_object, "wpan"):
        source = ""
        destination = ""

        skip_iteration = False
        for j in item_generator(elem, "wpan.dst16"):
            if j == "0xffff":
                skip_iteration = True
                continue
            destination = j

        if skip_iteration:
            continue

        for i in item_generator(elem, "wpan.src16"):
            source = i
            mapping_addr16_addr64.update({i: next(item_generator(elem, "wpan.src64"), None)})

        if source and destination:
            source_dest.add((source, destination))

    mapped_set = {(mapping_addr16_addr64[a], mapping_addr16_addr64[b]) for a, b in source_dest}

    reciprocal_pairs = _find_reciprocal_pairs(mapped_set)
    _generate_dot_file(mapped_set, reciprocal_pairs, output_filename)

    return mapped_set
