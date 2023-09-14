import xmltodict


class Device:
    def __init__(self, dev=None, src=None) -> None:
        self.src = src if src else ""
        self.manufacturer = dev['manufacturer'] if dev else ""
        self.model = dev['model'] if dev else ""
        self.build = dev['build'] if dev else ""

    def _set_manufacturer(self, manu):
        self.manufacturer = manu

    def _set_model(self, model):
        self.model = model

    def _set_build(self, build):
        self.build = build

    def __repr__(self) -> str:
        if self.model and self.build and self.manufacturer:
            return f"Device(src='{self.src}', manufacturer='{self.manufacturer}', model='{self.model}', build='{self.build}')"
        return ""

    def __str__(self) -> str:
        if self.model and self.build and self.manufacturer:
            return f"Device Info ({self.src}):\nManufacturer: {self.manufacturer}\nModel: {self.model}\nBuild: {self.build}"
        return ""

    def __hash__(self) -> int:
        return hash((self.manufacturer, self.model, self.build))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Device):
            return NotImplemented
        return (self.manufacturer, self.model, self.build) == (other.manufacturer, other.model, other.build)


def _parse_pdml(filename):
    return xmltodict.parse(open(filename, 'r').read())


def _hex_to_ascii(hex_string):
    try:
        ascii_string = bytes.fromhex(hex_string).decode('utf-8')
        return ascii_string
    except ValueError:
        return "Invalid hexadecimal input"


def print_formatted(title, values, optional_function=None):
    max_word_length = len(title) + 2
    line_length = max_word_length + 70

    centered_word = f"#{title.center(max_word_length, ' ')}#"
    print(centered_word.center(line_length, '#'))

    for count, value in enumerate(values, 1):
        print(f"{title[:-1]} {count}:  {value}")

        if optional_function:
            print(optional_function(value))
    print("\n")


def find_src_addr(packet):
    for field in packet['proto']:
        if field['@name'] == 'wpan':
            for fof in field['field']:
                if fof['@name'] == 'wpan.src64':
                    return fof['@show']


def _print_pdml_info(parsed_pdml_file):
    print("All keys of root", parsed_pdml_file['pdml'].keys())
    print("Creator: ", parsed_pdml_file['pdml']['@creator'])
    print("Time: ", parsed_pdml_file['pdml']['@time'])
    print("File:", parsed_pdml_file['pdml']['@capture_file'])
    print("Nr. packets: ", len(parsed_pdml_file['pdml']['packet']))
    print("\n")

#os.chdir("/home/henry/Downloads/zigbee_testing_piotnet/pdml_files/")
#parsed = _parse_pdml('tshark_zbwires_diss.pdml')


def extract_zigbee_devices_from_pdml(parsed_pdml_file):
    devices = {}
    for packet in parsed_pdml_file['pdml']['packet']:

        device_src = find_src_addr(packet)

        if not device_src:
            continue
        if device_src not in devices.keys():
            devices.update({device_src: {'manufacturer': '', 'model': '', 'build': ''}})

        zbee_zcl_proto = next((proto for proto in packet['proto'] if proto['@name'] == 'zbee_zcl'), None)

        if zbee_zcl_proto:
            status_key_field = next((field for field in zbee_zcl_proto['field'] if 'Status Record' in field['@show']), None)

            if status_key_field:
                for field in status_key_field['field']:
                    if 'Model Identifier' in field['@showname']:
                        devices[device_src]['model'] = status_key_field['@show'].split(',')[1].split(': ')[1]
                    elif 'Manufacturer Name' in field['@showname']:
                        devices[device_src]['manufacturer'] = status_key_field['@show'].split(',')[1].split(': ')[1]
                    elif 'Software Build' in field['@showname']:
                        devices[device_src]['build'] = status_key_field['@show'].split(',')[1].split(': ')[1]
                    else:
                        continue

    return devices


def gather_info_from_pdml(parsed_pdml_file):
    keys = set()
    trust_keys = set()
    dst = set()
    src = set()
    for packet in parsed_pdml_file['pdml']['packet']:
        zbee_aps_proto = next((proto for proto in packet['proto'] if proto['@name'] == 'zbee_aps'), None)

        if zbee_aps_proto:
            transport_key_field = next(
                (field for field in zbee_aps_proto['field'] if 'Transport Key' in field['@show']), None)

            if transport_key_field:
                key_field = next(
                    (field for field in transport_key_field['field'] if field['@name'] == 'zbee_aps.cmd.key'), None)
                dst_field = next(
                    (field for field in transport_key_field['field'] if field['@name'] == 'zbee_aps.cmd.dst'), None)
                src_field = next(
                    (field for field in transport_key_field['field'] if field['@name'] == 'zbee_aps.cmd.src'), None)

                if key_field:
                    keys.add(key_field['@show'])

                if dst_field:
                    dst.add(dst_field['@showname'])

                if src_field:
                    src.add(src_field['@showname'])

            trust_key_fields = next((field for field in zbee_aps_proto['field'] if 'Security Header' in field['@show']),
                                    None)

            if trust_key_fields:
                tkey_field = next((field for field in trust_key_fields['field'] if field['@name'] == 'zbee.sec.key'),
                                  None)

                if tkey_field:
                    trust_keys.add(tkey_field['@show'])

    return keys, trust_keys, dst, src


if __name__ == '__main__':
    # Assuming parsed_pdml_file is defined
    parsed_pdml_file = _parse_pdml("/opt/proteciotnet_zigbee/testfile1.pdml")

    _print_pdml_info(parsed_pdml_file)
    print(extract_zigbee_devices_from_pdml(parsed_pdml_file))

    keys, trust_keys, dst, src = gather_info_from_pdml(parsed_pdml_file)

    print_formatted('TRANSPORT KEYS', keys)
    print_formatted('TRUST KEYS', trust_keys, lambda key: f'Trust key (ASCII): {_hex_to_ascii(key.replace(":", ""))}')
    print_formatted('DESTINATIONS', dst)
    print_formatted('SOURCES', src)
