from datetime import datetime


def _find_reciprocal_pairs(mapped_set):
    reciprocal_pairs = set()
    for pair in mapped_set:
        if (pair[1], pair[0]) in mapped_set:
            reciprocal_pairs.add(frozenset(pair))
    return reciprocal_pairs


def _generate_dot_file(mapped_set, reciprocal_pairs, file_name):
    with open(file_name, 'w') as file:
        file.write('digraph G {\n')
        for pair in mapped_set:
            if frozenset(pair) in reciprocal_pairs:
                if pair[0] < pair[1]:  # Avoid duplicate bidirectional edges
                    file.write(f'    "{pair[0]}" -> "{pair[1]}" [dir=both];\n')
            else:
                file.write(f'    "{pair[0]}" -> "{pair[1]}";\n')
        file.write('}\n')


def _convert_timezone(timestamp_str):
    dt = datetime.strptime(timestamp_str, '%b %d, %Y %H:%M:%S.%f000 %Z')
    formatted_timestamp = dt.strftime('%d.%m.%Y - %H:%M:%S')
    return formatted_timestamp
