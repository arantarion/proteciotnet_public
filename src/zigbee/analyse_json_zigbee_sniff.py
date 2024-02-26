import logging
from datetime import datetime
from collections import Counter

from proteciotnet_dev.static.py.vendor_macs_dict import vendor_mac_lookup_table

logger = logging.getLogger(__name__)


def _find_reciprocal_pairs(mapped_set: set) -> set:
    """
    Find reciprocal pairs in a mapped set.

    Args:
        mapped_set (set): A set of pairs.

    Returns:
        set: A set containing the reciprocal pairs.

    """

    reciprocal_pairs = set()
    for pair in mapped_set:
        if (pair[1], pair[0]) in mapped_set:
            reciprocal_pairs.add(frozenset(pair))

    logger.debug(f"Reciprocal pairs: {reciprocal_pairs}")

    return reciprocal_pairs


def _generate_dot_file(mapped_set: set, reciprocal_pairs: set, file_name: str) -> None:
    """
    Generate a DOT file based on the mapped set and reciprocal pairs.

    Args:
        mapped_set (set): A set of pairs.
        reciprocal_pairs (set): A set containing reciprocal pairs.
        file_name (str): The name of the DOT file to generate.

    Returns:
        None

    Raises:
        None
    """

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

    logger.info(f"Successfully wrote dot file to {file_name}")


def _convert_timezone(timestamp_str: str) -> str:
    """
    Convert timestamp from one format to another.
    This is done to have the same format as everywhere else.

    Args:
        timestamp_str (str): The timestamp string to be converted.

    Returns:
        str: The converted timestamp string.

    """

    logger.debug(f"Converting {timestamp_str}")

    formatted_timestamp = timestamp_str.split(".")[0]
    dt_object = datetime.strptime(formatted_timestamp, '%b %d, %Y %H:%M:%S')
    output_formatted_timestamp = dt_object.strftime("%A, %d. %B %Y - %H:%M:%S")

    logger.debug(f"Converted timestamp: {output_formatted_timestamp}")

    return output_formatted_timestamp


def _get_vendor_from_mac(mac_address: str) -> str:
    """
    Get the vendor name from the MAC address prefix.

    Args:
        mac_address (str): The MAC address.

    Returns:
        str: The vendor name corresponding to the MAC address prefix, or an empty string if not found.
    """
    try:
        mac_prefix = mac_address[:8].upper()
        vendor = vendor_mac_lookup_table.get(mac_prefix, "")
        logger.debug(f"Vendor name: {vendor}")
        return vendor
    except Exception:
        logger.warning(f"Could not find vendor name from: {mac_address}")
        return ""


def item_generator(json_object, lookup_key: str):
    """
    A generator function to extract values from a ZigBee recording (json) based on a specified lookup key.

    Args:
        json_object (dict or list): The ZigBee recording (json) to search.
        lookup_key (str): The key to search for in the ZigBee recording (json).

    Yields:
        object: The values corresponding to the lookup key found in the ZigBee recording (json).
    """
    if isinstance(json_object, dict):
        for key, value in json_object.items():
            if key == lookup_key:
                yield value
            else:
                yield from item_generator(value, lookup_key)
    elif isinstance(json_object, list):
        for item in json_object:
            yield from item_generator(item, lookup_key)


def find_trust_key(json_object: dict) -> list:
    """
    Find trust keys in the ZigBee recording (json).

    Args:
        json_object (dict): The ZigBee recording (json) to search.

    Returns:
        list: List of trust keys found.
    """
    trust_keys = list(set([x for x in item_generator(json_object, "zbee.sec.key")]) - set(find_transport_keys(json_object)))
    logging.debug(f"found trust keys: {trust_keys}")
    return trust_keys


def find_transport_keys(json_object: dict) -> list:
    """
    Find transport keys in the ZigBee recording (json).

    Args:
        json_object (dict): The ZigBee recording (json) to search.

    Returns:
        list: List of transport keys found.
    """
    transport_keys = list(set([x for x in item_generator(json_object, "zbee_aps.cmd.key")]))
    logging.debug(f"found transport keys: {transport_keys}")
    return transport_keys


def find_unique_devices(json_object: dict) -> tuple:
    """
    Find unique devices in the ZigBee recording (json).

    Args:
        json_object (dict): The ZigBee recording (json) to search.

    Returns:
        tuple: A tuple containing a Counter object of devices and the count of unique devices.
    """
    devices = []
    for packet in item_generator(json_object, "wpan"):
        try:
            devices.append(packet['wpan.src64'])
        except KeyError:
            pass

    devices_counted = Counter(devices)
    logger.debug(f"found {devices_counted}")
    return devices_counted, len(set(devices_counted))


def count_packages_in_file(json_object: dict) -> tuple:
    """
    Count the number of packages in the ZigBee recording (json).

    Args:
        json_object (dict): The ZigBee recording (json) to count packages in.

    Returns:
        tuple: A tuple containing the total number of packages and the number of Zigbee packages.
    """
    nr_packages = len(json_object)
    nr_zigbee_packages = nr_packages - len([x for x in item_generator(json_object, "frame.len") if x == "5"])

    logger.debug(f"Found {nr_packages} packages")
    logger.debug(f"Found {nr_zigbee_packages} zigbee packages")

    return nr_packages, nr_zigbee_packages


def get_start_time(json_object: dict) -> str:
    """
    Get the start time from the ZigBee recording (json).

    Args:
        json_object (dict): The ZigBee recording (json) containing time information.

    Returns:
        str: The formatted start time.
    """
    # Index 1 because 0 is the custom info about scan
    time = next(item_generator(json_object[1], "frame.time"), None)
    if time:
        logger.debug(f"Found {time}")
        return _convert_timezone(time)
    else:
        logger.warning(f"Did not find time")
        return "01.01.1970 - 00:00:00"


def get_finish_time(json_object: dict) -> str:
    """
    Get the finish time from the ZigBee recording (json).

    Args:
        json_object (dict): The ZigBee recording (json) containing time information.

    Returns:
        str: The formatted finish time.
    """
    time = next(item_generator(json_object[-1], "frame.time"), None)
    if time:
        logger.debug(f"Found {time}")
        return _convert_timezone(time)
    else:
        logger.warning(f"Did not find time")
        return "01.01.1970 - 00:00:00"


def create_network_graph(json_object: dict, output_filename: str) -> None:
    """
    Create a network graph from the given a ZigBee recording (json) and write it to a DOT file.

    Args:
        json_object (dict): The ZigBee recording (json) containing network packet data.
        output_filename (str): The name of the output DOT file.

    Returns:
        None
    """

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
            source64 = next(item_generator(elem, "wpan.src64"), "")
            mapping_addr16_addr64.update({i: source64})

        if source and destination:
            source_dest.add((source, destination))

    for k, v in mapping_addr16_addr64.items():
        source64_vendor = _get_vendor_from_mac(v)
        if source64_vendor:
            mapping_addr16_addr64[k] = f"{v} /\n {source64_vendor}"

    addr16_list = []
    for tpl in source_dest:
        addr16_list.extend(tpl)
    addr16_list = list(set(addr16_list))

    mapping_addr16_addr64_keys = mapping_addr16_addr64.keys()
    for key in addr16_list:
        if key not in mapping_addr16_addr64_keys:
            mapping_addr16_addr64.update({key: ""})

    mapped_set = {(mapping_addr16_addr64[a], mapping_addr16_addr64[b]) for a, b in source_dest}
    logging.debug(f"mapped set: {mapped_set}")

    reciprocal_pairs = _find_reciprocal_pairs(mapped_set)
    logging.debug(f"reciprocal_pairs: {reciprocal_pairs}")

    _generate_dot_file(mapped_set, reciprocal_pairs, output_filename)
    logging.debug(f"Successfully generated dot file.")
