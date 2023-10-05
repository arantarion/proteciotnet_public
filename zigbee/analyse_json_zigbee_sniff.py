from collections import Counter
import logging
from proteciotnet_dev.static.py.vendor_macs_dict import vendor_mac_lookup_table

logging.getLogger('matplotlib.font_manager').disabled = True


def _find_reciprocal_pairs(mapped_set):
    reciprocal_pairs = set()
    for pair in mapped_set:
        if (pair[1], pair[0]) in mapped_set:
            reciprocal_pairs.add(frozenset(pair))
    return reciprocal_pairs


def _generate_dot_file(mapped_set, reciprocal_pairs, file_name):
    with open(file_name, 'w') as file:
        file.write('digraph G {\n')
        file.write('    bgcolor="transparent";\n')
        file.write('    node [color="#9e9e9e", fontcolor="#9e9e9e"];\n')
        file.write('    edge [color="#9e9e9e"];\n')
        for pair in mapped_set:
            if frozenset(pair) in reciprocal_pairs:
                if pair[0] < pair[1]:  # Avoid duplicate bidirectional edges
                    file.write(f'    "{pair[0]}" -> "{pair[1]}" [dir=both];\n')
            else:
                file.write(f'    "{pair[0]}" -> "{pair[1]}";\n')
        file.write('}\n')


def _convert_timezone(timestamp_str):
    formatted_timestamp = timestamp_str.split(".")[0]
    return formatted_timestamp


def _get_vendor_from_mac(mac_address):
    mac_prefix = mac_address[:8].upper()
    vendor = vendor_mac_lookup_table.get(mac_prefix, "")
    return vendor


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
    return list(set([x for x in item_generator(json_object, "zbee.sec.key")]) - set(find_transport_keys(json_object)))


def find_transport_keys(json_object):
    return list(set([x for x in item_generator(json_object, "zbee_aps.cmd.key")]))


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
    # Index 1 because 0 is the custom info about scan
    time = next(item_generator(json_object[1], "frame.time"), None)
    if time:
        return _convert_timezone(time)
    else:
        return "01.01.1970 - 00:00:00"


def get_finish_time(json_object):
    time = next(item_generator(json_object[-1], "frame.time"), None)
    if time:
        return _convert_timezone(time)
    else:
        return "01.01.1970 - 00:00:00"


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
            source64 = next(item_generator(elem, "wpan.src64"), None)
            mapping_addr16_addr64.update({i: source64})

        if source and destination:
            source_dest.add((source, destination))

    for k, v in mapping_addr16_addr64.items():
        source64_vendor = _get_vendor_from_mac(v)
        if source64_vendor:
            mapping_addr16_addr64[k] = f"{v} /\n {source64_vendor}"

    mapped_set = {(mapping_addr16_addr64[a], mapping_addr16_addr64[b]) for a, b in source_dest}
    reciprocal_pairs = _find_reciprocal_pairs(mapped_set)
    _generate_dot_file(mapped_set, reciprocal_pairs, output_filename)
