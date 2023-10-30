import json


def create_json_project_file(filepath, filename):

    # Define the data
    header = {
        'ble_filename': 'John Doe',
        'ble_scan_start_time': 30,
        'ble_interface': 345.80,
        'ble_ltk': "",
        'ble_nr_devices': 10,
        'ble_connectable_devices': 0,

    }

    try:
        with open(filename, 'w') as json_file:
            json.dump(header, json_file, indent=4)
        print(f"JSON file was created successfully as {filename}")
    except IOError as e:
        print(f"Error writing JSON file: {e}")
