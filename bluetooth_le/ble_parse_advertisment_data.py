from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_ad_types import ad_types
from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_company_identifiers import company_identifiers
from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_ms_device_type import ms_device_type
from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_ms_flags_and_device_status import ms_flags_and_device_status
from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_uuids import uuids

# from ble_assigned_numbers.ble_ad_types import ad_types
# from ble_assigned_numbers.ble_company_identifiers import company_identifiers
# from ble_assigned_numbers.ble_ms_device_type import ms_device_type
# from ble_assigned_numbers.ble_ms_flags_and_device_status import ms_flags_and_device_status
# from ble_assigned_numbers.ble_uuids import uuids


def _parse_ble_adv_data(advertisement_data: str) -> list:
    """
    Parses BLE advertisement data and returns a list of dictionaries.

    :param advertisement_data: the full advertisement data
    :type advertisement_data: str
    :return: a list of dictionaries that contain a split up version of the data consisting of a length for the segment,
    the type (deducted from https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/core/ad_types.yaml) and
    data itself that has to be interpreted
    :rtype: list
    """
    i = 0
    adv_elements = []

    while i < len(advertisement_data):
        length = int(advertisement_data[i:i + 2], 16)
        i += 2

        if length == 0:
            break

        adv_type = advertisement_data[i:i + 2]
        i += 2

        data_length = (length - 1) * 2
        data = advertisement_data[i:i + data_length]
        i += data_length

        adv_elements.append({
            'length': length,
            'type': adv_type,
            'data': data
        })

    return adv_elements


def _parse_ble_flags(flags_hex: str) -> dict:
    """Parses BLE flags and returns a dictionary.

    :param flags_hex: the flags of the BLE advertisement package in hex format
    :type flags_hex: str
    :return: dict containing the flags the device sends
    :rtype: dict
    """
    flags_int = int(flags_hex, 16)
    flag_descriptions = [
        "LE Limited Discoverable Mode",
        "LE General Discoverable Mode",
        "BR/EDR Not Supported",
        "Simultaneous LE and BR/EDR to Same Device Capable (Controller)",
        "Simultaneous LE and BR/EDR to Same Device Capable (Host)"
    ]

    return {desc: bool(flags_int & (1 << i)) for i, desc in enumerate(flag_descriptions)}


def _parse_apple_data(apple_data: str) -> dict:
    """
    Parses Apple-specific data and returns a dictionary.

    :param apple_data: data identified to belong to Apple FindMy advertisement. Documentation:
    https://images.frandroid.com/wp-content/uploads/2020/06/Find_My_network_accessory_protocol_specification.pdf
    :type apple_data: str
    :return: dict containing data that could be extracted
    :rtype: dict
    """

    bytes_data = [int(apple_data[i:i + 2], 16) for i in range(0, len(apple_data), 2)]

    payload_length = bytes_data[1]
    battery_states = ["Full", "Medium", "Low", "Critically low"]

    if payload_length == 0x02:
        return {
            "State": "Normal",
            "Maintained": bool((bytes_data[2] >> 2) & 1),
            "Battery": battery_states[(bytes_data[2] >> 6) & 3],
            "Public Key Bits": bytes_data[3] & 3
        }
    elif payload_length == 0x19:
        return {
            "State": "Separated",
            "Maintained": bool((bytes_data[2] >> 2) & 1),
            "Battery": battery_states[(bytes_data[2] >> 6) & 3],
            "Separated Public Key": '0x' + ''.join([hex(x) for x in bytes_data[3:25]]).replace("0x", "").upper(),
            "Public Key Bits": bytes_data[25] & 3,
            "Hint": bytes_data[26]
        }
    else:
        return {"Error": "Unknown payload length"}


def _parse_microsoft_ble_data(ms_adv_data: str) -> dict:
    """
    Parses Microsoft-specific BLE advertisement data.

    :param ms_adv_data: data identified to belong to Microsoft BLE advertisement. Documentation:
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cdp/77b446d0-8cea-4821-ad21-fabdf4d9a569?redirectedfrom=MSDN
    :type ms_adv_data: str
    :return: dict containing data that was encoded with Microsoft's specification
    :rtype: dict
    """
    ms_adv_data = f"1EFF{ms_adv_data}"
    output = {
        "length": ms_adv_data[:2],
        "fixed": ms_adv_data[2:4],
        "company_id": 'Microsoft' if ms_adv_data[4:8] == '0600' else ms_adv_data[4:8],
        "scenario_type": 'Bluetooth' if ms_adv_data[8:10] == '01' else 'Not Bluetooth',
        "version_and_device_type": ms_device_type.get(int(ms_adv_data[10:12], 16), ""),
        "version_and_flags": 'Nearby Share for device only' if bin(int(ms_adv_data[12:14], 16))[2:].zfill(8)[
                                                               3:] == "00000" else 'Nearby Share for everyone',
        "flags_and_device_status": ms_flags_and_device_status.get(ms_adv_data[14:16], ""),
        "salt": ms_adv_data[16:24],
        "device_hash": ms_adv_data[24:]
    }
    return output


def _parse_i_beacon_data(i_beacon_data: str) -> dict:
    """
    Parses iBeacon-specific BLE advertisement data.

    :param i_beacon_data: data identified to belong to Apple iBeacons as per
    http://www.havlena.net/en/location-technologies/ibeacons-how-do-they-technically-work/
    :type i_beacon_data: str
    :return: Dict containing the information in the data being proximity UUID, major, minor and tx power
    :rtype: dict
    """

    uuid = i_beacon_data[8:40]
    major = i_beacon_data[40:44]
    minor = i_beacon_data[44:48]
    tx_power = i_beacon_data[48:50]

    return {
        "UUID": uuid,
        "Major": int(major, 16),
        "Minor": int(minor, 16),
        "TX Power": f"{int(tx_power, 16)} dBm at 1m"
    }


def _get_company_by_uuid(data: str) -> str:
    """
    Try to get the company name by the uuid in the data.

    :param data: part of the uuid data that contains the company identifier as per
    https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml
    :type data: str
    :return: The company that produces the device or an empty string if the company can't be found
    :rtype: str
    """
    pairs = [data[i:i + 2] for i in range(0, len(data), 2)]
    pairs.reverse()
    reversed_uuid = ''.join(pairs)
    return company_identifiers.get("0x" + reversed_uuid, "")


def _parse_adv_data_to_json(advertisement_data: str) -> list:
    """
    Parses advertisement data and returns a JSON object.

    :param advertisement_data: Modified version of raw advertisement data, with the "0x" deleted and converted to
                               upper-case.
    :type advertisement_data: str
    :return: A list of dictionaries with the parsed data
    :rtype: list
    """
    parsed_data = _parse_ble_adv_data(advertisement_data)
    parsed_data_dict = []

    for elem in parsed_data:
        entry = {"Data": elem['data'],
                 "Type": {"Code": elem['type'], "Description": ad_types.get(f"0x{elem['type']}", "")}}

        if elem['type'] == "FF":
            if elem['data'].startswith("4C00"):
                if elem['data'][4:8] == "0215":
                    entry["iBeacon Data"] = _parse_i_beacon_data(elem['data'])
                else:
                    entry["Apple Data"] = _parse_apple_data(elem['data'][4:])
            elif elem['data'].startswith("0600"):
                entry["Microsoft Data"] = _parse_microsoft_ble_data(elem['data'])
            else:
                company = _get_company_by_uuid(elem['data'][:4])
                entry['company'] = company
                entry["Data"] = elem['data']

        elif "Flags" in entry["Type"]["Description"]:
            entry["Flags"] = _parse_ble_flags(elem['data'])
        elif "Service Class UUID" in entry["Type"]["Description"]:
            pairs = [elem['data'][i:i + 2] for i in range(0, len(elem['data']), 2)]
            pairs.reverse()
            reversed_uuid = ''.join(pairs)
            entry["UUID"] = uuids.get("0x" + reversed_uuid, "")
        elif "Name" in entry["Type"]["Description"]:
            entry["Name"] = bytes.fromhex(elem['data']).decode(errors='ignore')
        elif elem['type'] == "0A":
            entry["TX Power Level (dBm)"] = int(elem['data'], 16) - 256 if int(elem['data'], 16) > 127 else int(elem['data'], 16)
        else:
            entry["Data"] = elem['data']

        parsed_data_dict.append(entry)

    return parsed_data_dict


def parse_adv_data(hex_data: str) -> list:
    """
    Method to parse BLE advertisement data from different companies to find information about the device and
    company. Can currently parse some generic attributes and data from Microsoft Windows devices, as well as some
    types of Apple device's advertisement data.

    :param hex_data: The raw hex data of the BLE advertisement data
    :type hex_data: str
    :return: A list of dictionaries with the parsed data
    :rtype: list
    """
    data = str(hex_data).replace("0x", "").upper()
    parsed_data = _parse_adv_data_to_json(data)
    return parsed_data


# iBeacon: 02151CA92E23F0874DF7B9A2FD4B716A4BF60AE3000003
# Win10:   1EFF0600010920021C34290C9C8C7826DF7FC4A4107A4FB4935DC9A7FE7C00
# Win10.2: 1EFF06000109200607D3C3EBD018A8EF5B2277E2660B0EE9FEDDDEF47B658E
# Sony HP: 030303FE0E094C455F57482D31303030584D35
# Find My: 07FF4C0012020001
# Segway:  0201060B0953656777617920496F5409FFFFFF8C59DCF571A211079ECADC240EE5A9E093F3A3B50100406E
# Garmin:  02010611079F99A2DBF39118A3F24B2590E25B74AA1908424C455F4761726D696E2044726976652023333339313833
# JBL:     0201060D162CFE004008005A32345A5014020AF6031603FE0816DFFD43200153E515084A424C204C4956452050524F2B205457532D4C45
# Daikin:  020106110677AE8C12719E7BB6E6113A2110E1412107084461696B696E05FF9300E0000F0942524331482033433A33363A3234
# Samsung: 1BFF7500420401806028395EDEA9CA2A395EDEA9C901000000000000
# JBL Tune: 0303DFFD0C16DFFDB52000C8AF0000A43C11094A424C2054554E453637304E432D4C45
# Samsung Smart: 02010403025AFD17165AFD15DCC7014348F47468AACF29B30000004F0DAA910A09536D61727420546167
# Matsushita: 02010609FF9E8EEAA1DE42C8E81107454C4261686F72694103AB2D4D4952500C094C452D525A2D533330305706FF3A00BCA0E3
# Find my: 0x1EFF4C00121910E7D63F125160D7EC1974466AE4497E2362C8AD84603502E1
# Nearby: 0x02011A020A0C0CFF4C001007081F730B533C78
# Find my: 0x07FF4C0012020003

