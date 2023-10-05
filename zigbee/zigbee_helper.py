import os
from datetime import datetime

_BASE_STATIC_ZIGBEE_DIR = "/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports/"


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


def _convert_dot_to_svg(filepath):
    if not os.path.exists(f"{_BASE_STATIC_ZIGBEE_DIR}{filepath}.svg"):
        os.popen(f"sudo dot -Tsvg {_BASE_STATIC_ZIGBEE_DIR}{filepath} -o {_BASE_STATIC_ZIGBEE_DIR}{filepath}.svg")
    return f"{_BASE_STATIC_ZIGBEE_DIR}{filepath}.svg"
