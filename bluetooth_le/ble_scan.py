import csv
import json
import sys
import logging
import multiprocessing
import os.path
from datetime import datetime
from threading import Thread
from time import sleep

from bluepy import btle
from bluepy.btle import Peripheral, UUID, Scanner, DefaultDelegate, BTLEDisconnectError

from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_appearance_dict import BLE_APPEARANCE
from proteciotnet_dev.bluetooth_le.ble_assigned_numbers.ble_company_identifiers import company_identifiers
from proteciotnet_dev.bluetooth_le.ble_parse_advertisment_data import parse_adv_data
from proteciotnet_dev.static.py.vendor_macs_dict import vendor_mac_lookup_table

# from ble_assigned_numbers.ble_company_identifiers import company_identifiers
# from ble_appearance_dict import BLE_APPEARANCE
# from vendor_macs_dict import vendor_mac_lookup_table
# from ble_parse_advertisment_data import parse_adv_data

BT_INTERFACE_INDEX = 0
BT_SCAN_TIME = 2
CONNECTION_TIMEOUT = 5
BLE_PERMISSIONS = ["WRITE NO RESPONSE", "SIGNED WRITE COMMAND", "QUEUED WRITE", "BROADCAST", "READ", "WRITE", "NOTIFY",
                   "INDICATE", "WRITABLE AUXILIARIES"]
CSV_HEADERS = ["timestamp", "address", "device_name", "vendor", "address_type", "conn", "rssi", 'interface', 'extra_data', 'attribute_data']
CONNECTION_ERROR = False
IS_SCANNING = False
BLE_STATIC_PATH = "/opt/proteciotnet/proteciotnet_dev/static/ble_reports/"

ms_device_type = {
    1: "Xbox One",
    6: "Apple iPhone",
    7: "Apple iPad",
    8: "Android device",
    9: "Windows 10 Desktop",
    11: "Windows 10 Phone",
    12: "Linux device",
    13: "Windows IoT",
    14: "Surface Hub",
    15: "Windows laptop",
    16: "Windows tablet"
}

ms_flags_and_device_status = {
    "00": "None",
    "01": "Remote Session Hosted",
    "02": "Remote Session Not Hosted",
    "04": "Near Share Auth Policy Same User",
    "08": "Near Share Auth Policy Permissive"
}


logger = logging.getLogger(__name__)
stdout = logging.StreamHandler(stream=sys.stdout)
fmt = logging.Formatter(
    "%(name)s: %(asctime)s | \t%(levelname)s\t | %(filename)s:%(lineno)s | %(process)d >>> %(message)s"
)
stdout.setFormatter(fmt)
logger.addHandler(stdout)
logger.setLevel(logging.DEBUG)


def _get_timestamp() -> str:
    """
    Returns a formatted timestamp that can be used as a filename or in a file.
    Timestamp is seperated by underscores for convenience in filenames.

    Returns:
        - str: A underscore separated timestamp of the current time
    """
    current_datetime = datetime.now()
    # return current_datetime.strftime("%Y_%m:%d_%H:%M_%S")
    return current_datetime.strftime("%A, %d. %B %Y - %H:%M:%S")

def _read_existing_data(filename: str) -> list:
    """
    Read data from a CSV file and return a list of tuples.

    Opens a file with the given filename, reads its contents, assuming a CSV
    format, skips the header, and then appends the first three columns of each
    row to a list as tuples.

    Parameters:
    - filename (str): The name of the file to read.

    Returns:
    - list of tuples: A list where each tuple contains the first three columns
      of a row from the file.

    """
    existing_data = []
    with open(filename, 'r', newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        next(csvreader)
        for row in csvreader:
            if row:
                existing_data.append(tuple(row[1:4]))
    return existing_data


def _create_ms_device(r: list) -> dict:
    """
    Create a dictionary representing a Microsoft device from a raw data string.

    Parses a string containing hexadecimal values specific to a Microsoft
    device and creates a dictionary mapping each device attribute to the
    corresponding parsed value.

    Parameters:
    - r (str): The raw string containing hexadecimal device information.

    Returns:
    - dict: A dictionary with keys representing device attributes such as
      length, fixed, company_id, and others, associated with their respective
      parsed values.

    """
    output = {
        "length": r[:2],
        "fixed": r[2:4],
        "company_id": 'Microsoft' if r[4:8] == '0600' else r[4:8],
        "scenario_type": 'Bluetooth' if r[8:10] == '01' else 'Not Bluetooth',
        "version_and_device_type": ms_device_type.get(int(r[10:12]), ""),
        "version_and_flags": 'Nearby Share for device only' if bin(int(r[12:14], 16))[2:].zfill(8)[3:] == "00000" else 'Nearby Share for everyone',
        "flags_and_device_status": ms_flags_and_device_status.get(str(r[14:16]), ""),
        "salt": r[16:24],
        "device_hash": r[24:]
    }
    return output


def _create_find_my_device(r: list, addr: str) -> dict:
    """
    Create a dictionary representing an Apple 'Find My' device from a raw data string.

    Parses a string containing hexadecimal values specific to an Apple 'Find My'
    device and uses an additional address parameter to construct a dictionary
    representing the device attributes.

    Parameters:
    - r (str): The raw string containing hexadecimal 'Find My' information.
    - addr (str): An additional string used in generating part of the 'public_key'.

    Returns:
    - dict: A dictionary with keys representing device attributes such as
      length, fixed, company_id, and others, associated with their respective
      parsed values.

    Note:
    - The function differentiates between different payload lengths and adjusts
      the output dictionary accordingly.

    """
    output = {
        "length": r[:2],
        "fixed": r[2:4],
        "company_id": 'Apple Inc.' if r[4:8].upper() == '4C00' else r[4:8],
        "apple_payload_type": 'Find My' if r[8:10] == '12' else r[8:10],
        "payload_length": r[10:12]
    }

    if output['payload_length'] == "02" or output['payload_length'] == "19":
        battery = bin(int(r[12:14], 16))[2:].zfill(8)[6:]
        battery_states = {
            "00": "Full",
            "01": "Medium",
            "10": "Low",
            "11": "Critically low"
        }
        output.update({
            "battery_state": battery_states.get(battery, "Unknown"),
        })

    if output['payload_length'] == "02":
        output.update({"public_key": f"{bin(int(r[14:16], 16))[2:].zfill(8)[:1]}{addr[1:]}"})

    elif output['payload_length'] == "19":
        output.update({"public_key": r[16:]})

    return output


class ConnectionTimeoutError(Exception):
    """
    Exception raised for errors in the connection due to a timeout.

    Attributes:
    - address (str): The address of the device where the connection timed out.
    - timeout (int): The duration (seconds) after which the connection timed out.

    Args:
    - address (str): The address of the device to which the connection was attempted.
    - timeout (int): The timeout duration in seconds.

    """
    def __init__(self, address, timeout):
        message = f"Connection to the device with address {address} timed out after {timeout} seconds."
        super().__init__(message)
        self.address = address
        self.timeout = timeout


class BLEDescriptor:
    """
    Represents a Bluetooth Low Energy (BLE) Descriptor.
    """

    def __init__(self, uuid: str, handle: int) -> None:
        """
        Initialize a BLEDescriptor object.

        :param uuid: UUID of the descriptor.
        :type uuid: str
        :param handle: Handle value for the descriptor.
        :type handle: int
        """
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.value_handle_int = handle
        self.value_handle = "0x{:04x}".format(self.value_handle_int)
        self.declaration_handle = "0x{:04x}".format(self.value_handle_int - 1)

    def __str__(self) -> str:
        """
        Return a string representation of the BLEDescriptor object.

        :return: String representation of the descriptor.
        :rtype: str
        """
        return (f"Descriptor: {self.name} ({self.uuid}) - Handle: {self.value_handle_int} ({self.value_handle} "
                f"[{self.declaration_handle}])")

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEDescriptor object.

        :return: Formal representation of the descriptor.
        :rtype: str
        """
        return f"<BLEDescriptor(uuid={self.uuid}, handle={self.value_handle})>"

    def to_dict(self) -> dict:
        """
        Convert the BLEDescriptor object to a dictionary.

        :return: Dictionary representation of the descriptor.
        :rtype: dict
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "value_handle": self.value_handle,
            "value_handle_int": self.value_handle_int,
            "declaration_handle": self.declaration_handle
        }


class BLECharacteristic:
    """
    Represents a Bluetooth Low Energy (BLE) Characteristic.
    """

    def __init__(self, uuid: str, handle: int, permissions: str, value: bytearray = None,
                 special_service: bool = False) -> None:
        """
        Initialize a BLECharacteristic object.

        :param uuid: UUID of the characteristic.
        :type uuid: str
        :param handle: Handle value for the characteristic.
        :type handle: int
        :param permissions: Permissions string for the characteristic.
        :type permissions: str
        :param value: Optional value for the characteristic.
        :type value: bytearray
        :param special_service: Flag indicating if this is a special service.
        :type special_service: bool
        """
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.value_handle_int = handle
        self.value_handle = "0x{:04x}".format(self.value_handle_int)
        self.declaration_handle = "0x{:04x}".format(self.value_handle_int - 1)
        self.permissions = self._parse_permissions(permissions, BLE_PERMISSIONS)

        if special_service:
            try:
                self.value = value.decode('utf-8')
            except Exception:
                if isinstance(value, bytes):
                    self.value = value.hex()
                else:
                    self.value = "None"
        elif value:
            try:
                self.value = ':'.join(format(x, '02x') for x in value) if self.name != "Device Name" else value.decode('utf-8')
            except UnicodeDecodeError:
                if isinstance(value, bytes):
                    self.value = value.hex()
                else:
                    self.value = "None"
        else:
            self.value = "None"

        self.appearance = ""
        if self.name == "Appearance":
            self.value = (f'{BLE_APPEARANCE.get(int.from_bytes(value, byteorder="little"), ["", ""])[1]} '
                          f'({int.from_bytes(value, byteorder="little")})')

        if self.name == "Peripheral Privacy Flag":
            self.value = "Device Privacy is not in use (00)" if self.value == '00' else "Device Privacy is in use (1)"

        self.descriptors = []

    def _parse_permissions(self, permissions_str: str, all_permissions: list) -> dict:
        """
        Parse permissions from a string representation.

        :param permissions_str: Permissions in string format.
        :type permissions_str: str
        :param all_permissions: str of all possible permissions.
        :type all_permissions: list
        :return: Dictionary of permissions.
        :rtype: dict
        """
        permissions_dict = {}
        for permission in all_permissions:
            if permission in permissions_str:
                permissions_dict[permission] = True
                permissions_str = permissions_str.replace(permission, "").strip()
            else:
                permissions_dict[permission] = False
        return permissions_dict

    def __str__(self) -> str:
        """
        Return a string representation of the BLECharacteristic object.

        :return: String representation of the characteristic.
        :rtype: str
        """
        desc_str = ', '.join([str(d) for d in self.descriptors])
        permissions_str = ', '.join([k for k, v in self.permissions.items() if v])
        return (f"Characteristic: {self.name} ({self.uuid}) - Handle: {self.value_handle_int} - "
                f"Permissions: {permissions_str} - Value: {self.value} - Descriptors: [{desc_str}]")

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLECharacteristic object.

        :return: Formal representation of the characteristic.
        :rtype: str
        """
        return f"<BLECharacteristic(uuid={self.uuid}, handle={self.value_handle_int}, properties={self.permissions})>"

    def to_dict(self) -> dict:
        """
        Convert the BLECharacteristic object to a dictionary.

        :return: Dictionary representation of the characteristic.
        :rtype: dict
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "value_handle_int": self.value_handle_int,
            "value_handle": self.value_handle,
            "declaration_handle": self.declaration_handle,
            "permissions": self.permissions,
            "value": self.value,
            "descriptors": [descriptor.to_dict() for descriptor in self.descriptors]
        }

    def add_descriptor(self, descriptor: BLEDescriptor) -> None:
        """
        Add a BLEDescriptor to the characteristic.

        :param descriptor: BLEDescriptor to add.
        :type descriptor: BLEDescriptor
        """
        self.descriptors.append(descriptor)


class BLEService:
    """
    Represents a Bluetooth Low Energy (BLE) Service.
    """

    def __init__(self, uuid: str) -> None:
        """
        Initialize a BLEService object.

        :param uuid: UUID of the service.
        :type uuid: str
        """
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.characteristics = []

    def __str__(self) -> str:
        """
        Return a string representation of the BLEService object.

        :return: String representation of the service.
        :rtype: str
        """
        char_str = '\n    '.join([str(c) for c in self.characteristics])
        return f"Service: {self.name} ({self.uuid})\n    {char_str}"

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEService object.

        :return: Formal representation of the service.
        :rtype: str
        """
        return f"<BLEService(uuid={self.uuid})>"

    def to_dict(self) -> dict:
        """
        Convert the BLEService object to a dictionary.

        :return: Dictionary representation of the service.
        :rtype: dict
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "characteristics": [char.to_dict() for char in self.characteristics]
        }

    def add_characteristic(self, characteristic: BLECharacteristic) -> None:
        """
        Add a BLECharacteristic to the service.

        :param characteristic: BLECharacteristic to add.
        :type characteristic: BLECharacteristic
        """
        self.characteristics.append(characteristic)


class BLEDevice:
    """
    Represents a Bluetooth Low Energy (BLE) Device.
    """

    def __init__(self, address: str, addr_type: str, rssi: str, name: str = "", connectable: bool = False) -> None:
        """
        Initialize a BLEDevice object.

        :param address: Address of the BLE device.
        :type address: str
        :param rssi: RSSI value for the device.
        :type rssi: str
        """
        self.address = address
        self.services = []
        self.connectable = connectable
        self.addr_type = addr_type
        self.rssi = rssi
        self.name = name

    def __str__(self) -> str:
        """
        Return a string representation of the BLEDevice object.

        :return: String representation of the device.
        :rtype: str
        """
        service_str = '\n  '.join([str(s) for s in self.services])
        return (f"Device Address: {self.address}, Name: {getattr(self, 'name', 'Unknown')} "
                f"({self.connectable}) [{self.rssi}] [Type: {self.addr_type}]\n  {service_str}")

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEDevice object.

        :return: Formal representation of the device.
        :rtype: str
        """
        return f"<BLEDevice(address={self.address}, name={getattr(self, 'name', 'Unknown')})>"

    def to_dict(self) -> dict:
        """
        Convert the BLEDevice object to a dictionary.

        :return: Dictionary representation of the device.
        :rtype: dict
        """
        return {
            "address": self.address,
            "name": getattr(self, 'name', 'Unknown'),
            "connectable": self.connectable,
            "rssi": self.rssi,
            "services": [service.to_dict() for service in self.services]
        }

    def add_service(self, service: BLEService) -> None:
        """
        Add a BLEService to the device.

        :param service: BLEService to add.
        :type service: BLEService
        """
        self.services.append(service)


class ScanDelegate(DefaultDelegate):
    """
    Delegate class for handling BLE device discovery during scanning. Specified in the BluePy documentation.
    """

    def __init__(self, filename):
        DefaultDelegate.__init__(self)
        self.filename = filename

    def handleDiscovery(self, dev, isNewDev, isNewData):
        """
        Handle the discovery of a new BLE device or new data from an existing device.

        :param dev: The discovered BLE device.
        :param isNewDev: Flag indicating if the device is newly discovered.
        :type isNewDev: bool
        :param isNewData: Flag indicating if new data is received from an existing device.
        :type isNewData: bool
        """
        if isNewDev:
            device_name = dev.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
            if device_name is None:
                device_name = dev.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)
            address = dev.addr if dev.addr else ""
            address_type = dev.addrType if dev.addrType else ""
            conn = dev.connectable
            rssi = dev.rssi if dev.rssi else ""
            device_name = device_name if device_name else ""
            extra_data = parse_adv_data(dev.rawData.hex())

            try:
                m = dev.getValueText(255)
                key = m[:4].upper()
                pairs = [key[i:i + 2] for i in range(0, len(key), 2)]
                pairs.reverse()
                key = "0x" + ''.join(pairs)
                vendor = company_identifiers.get(key, "unknown")

            except Exception:
                vendor = "unknown"

            if vendor == "unknown":
                vendor = vendor_mac_lookup_table.get(address[:8].upper(), "")
                if not vendor:
                    vendor = vendor_mac_lookup_table.get(address[:10].upper(), "")
                    if not vendor:
                        vendor = vendor_mac_lookup_table.get(address[:13].upper(), "unknown")

            logger.info(f"Found new device: {address} {device_name} {vendor} {address_type} {conn} {rssi}")

            if not os.path.isfile(f"{self.filename}.csv"):
                with open(f"{self.filename}.csv", 'w', newline='') as csvfile:
                    csv.writer(csvfile, escapechar='\\', delimiter=",").writerow(CSV_HEADERS)
                logger.info("created csv file")
                existing_data = []
            else:
                existing_data = _read_existing_data(f"{self.filename}.csv")
                logger.debug(f"File '{self.filename}' already exists. Does not have to be created.")

            curr_time = _get_timestamp()
            data = [curr_time, address, device_name, vendor, address_type, conn, rssi, dev.iface, extra_data]

            if tuple(data[1:4]) not in existing_data:
                with open(f"{self.filename}.csv", 'a', newline='') as csvfile:
                    csv.writer(csvfile, escapechar='\\', delimiter=",").writerow(data)
                    existing_data.append(tuple(data[1:4]))
                logger.info(f"wrote {data[1:6]} to file.")
            else:
                updated = False
                new_data = []
                with open(f"{self.filename}.csv", 'r', newline='') as csvfile:
                    csvreader = csv.reader(csvfile)
                    _ = next(csvreader)

                    for row in csvreader:
                        if (address, device_name, vendor) == tuple(row[1:4]):
                            row[6] += f">{rssi}"
                            updated = True
                        new_data.append(row)

                if updated:
                    with open(f"{self.filename}.csv", 'w', newline='') as csvfile:
                        csvwriter = csv.writer(csvfile, escapechar='\\', delimiter=",")
                        csvwriter.writerow(CSV_HEADERS)
                        csvwriter.writerows(new_data)
                        logger.debug("Updated RSSI value.")
                else:
                    logger.warning("No matching device found for RSSI update.")


class NotificationDelegate(DefaultDelegate):
    """
    Delegate class for handling BLE notifications. Specified in the BluePy documentation.
    """

    def __init__(self, params):
        DefaultDelegate.__init__(self)

    def handleNotification(self, cHandle, data):
        """
        Handle BLE notifications.

        :param cHandle: Handle of the characteristic sending the notification.
        :type cHandle: int
        :param data: Data received in the notification.
        :type data: bytes
        """
        logger.info((f"Notification from handle {cHandle:04x}:"
                     f"\n    {data.hex()}"))


class BLEScanner:
    """
    Class for scanning BLE devices.
    """

    def __init__(self, filename, beacons_only: bool = False, connectable_only: bool = False) -> None:
        """
        Initialize the BLEScanner object.
        """
        self.scanned_devices = {}
        self.filename = filename
        self.successful_scans = 0
        self.beacons_only = beacons_only
        self.connectable_only = connectable_only
        self.scanner = Scanner(BT_INTERFACE_INDEX).withDelegate(ScanDelegate(self.filename))

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEScanner object.

        :return: Formal representation of the scanner.
        :rtype: str
        """
        return f"<BLE_SCANNER(scanned_devices={self.scanned_devices})>"

    def __str__(self) -> str:
        """
        Return a string representation of the BLEScanner object.

        :return: String representation of the scanner.
        :rtype: str
        """
        output_string = ""
        for _, device in self.scanned_devices.items():
            output_string += device.__str__() + "\n\n"
        output_string += "\n"
        return output_string

    def _connect_peripheral(self, peripheral: Peripheral, addr: str, addr_type: str) -> None:
        """
        Connect to a BLE peripheral.

        :param peripheral: Peripheral to connect to.
        :type peripheral: bluepy.btle.Peripheral
        :param addr: Address of the peripheral.
        :type addr: str
        :param addr_type: Address type of the peripheral.
        :type addr_type: str
        """
        global CONNECTION_ERROR
        try:
            peripheral.connect(addr, addr_type)
        except Exception:
            CONNECTION_ERROR = True

    def scan(self, duration: int = 10) -> None:
        """
        Scan for BLE devices.

        :param duration: Duration of the scan in seconds.
        :type duration: int
        """
        logger.info(f"scanning for {duration} seconds")
        devices = self.scanner.scan(timeout=duration, passive=False)

        for device in devices:
            if self.connectable_only and not device.connectable:
                continue
            device_name = device.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
            if device_name is None:
                device_name = device.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)

            scanned_device = BLEDevice(address=device.addr,
                                       addr_type=device.addrType,
                                       rssi=device.rssi)
            scanned_device.connectable = device.connectable

            if device_name:
                scanned_device.name = device_name

            self.scanned_devices[device.addr] = scanned_device # device

    def scan_for_apple_airtags(self, duration: int = 10):
        logger.info(f"scanning for {duration} seconds")
        try:
            devices = self.scanner.scan(timeout=duration)

            for device in devices:
                manufacturer_data = device.getValueText(255)
                if manufacturer_data and manufacturer_data.startswith("4c000215"):
                    scanned_device = BLEDevice(address=device.addr,
                                               addr_type=device.addrType,
                                               rssi=device.rssi)
                    scanned_device.connectable = device.connectable

                    self.scanned_devices[device.addr] = device

        except Exception as e:
            logger.error(f"scan_for_apple_airtags: Error {e}")

    def connect_and_read_all(self, addr: str, addr_type: str, with_descriptors: bool = False) -> None:
        """
        Connect to a BLE device and read all its services, characteristics, and descriptors.

        :param addr: Address of the BLE device to connect to.
        :type addr: str
        :param addr_type: Address type for the connection -> either 'public' or 'random'
        :type addr_type: str
        :param with_descriptors: Flag indicating if descriptors should be read.
        :type with_descriptors: bool
        """
        global CONNECTION_ERROR
        CONNECTION_ERROR = False

        device = self.scanned_devices.get(addr)

        if not device:
            return

        p = Peripheral(iface=BT_INTERFACE_INDEX)
        try:
            # Implementation to enforce the timeout
            thread = Thread(target=self._connect_peripheral,
                            args=[p, device.address, addr_type])
            thread.start()
            thread.join(CONNECTION_TIMEOUT)
            if thread.is_alive() or CONNECTION_ERROR:
                logger.error(f"The device did not respond in the connection timeout of {CONNECTION_TIMEOUT}")
                raise ConnectionTimeoutError(device.address, CONNECTION_TIMEOUT)
            logger.info(f"Connected to {addr}.")

            logger.info(f"reading services of '{addr}'")
            services = p.getServices()
            for serv in services:
                service = BLEService(uuid=serv.uuid)
                device.add_service(service=service)

                logger.info(f"reading characteristics of service '{service.name}' on device '{addr}'")
                characteristics = serv.getCharacteristics()
                for chara in characteristics:
                    char_value = chara.read() if chara.supportsRead() else None
                    is_special_service = (UUID(chara.uuid).getCommonName() != str(chara.uuid)
                                          and not len(UUID(chara.uuid).getCommonName()) == 4)
                    characteristic = BLECharacteristic(uuid=chara.uuid,
                                                       handle=chara.getHandle(),
                                                       permissions=chara.propertiesToString(),
                                                       value=char_value,
                                                       special_service=is_special_service)
                    service.add_characteristic(characteristic=characteristic)

                    if with_descriptors:
                        logger.info(f"reading descriptors of characteristic '{characteristic.name}' of service "
                                    f"'{service.name}' on device '{addr}'")
                        for desc in chara.getDescriptors():
                            descriptor = BLEDescriptor(uuid=desc.uuid,
                                                       handle=desc.handle)
                            characteristic.add_descriptor(descriptor=descriptor)

            logger.info(f"successfully read all data from device {addr}")
            self.successful_scans += 1
            p.disconnect()
            logger.info(f"disconnected from '{addr}'\n")

        except KeyboardInterrupt:
            logger.error(f"KeyboardInterrupt - Skipping this device")

        except ConnectionTimeoutError as e:
            logger.error(str(e))
            logger.error(f"disconnecting...")
            p.disconnect()

        except Exception as e:
            logger.error(f"connect_and_read_all: Error {e}")
            logger.error(f"disconnecting...")
            p.disconnect()

    def save_to_json(self, filename: str) -> None:
        """
        Save the scanned BLE devices inside a BLEScanner to a JSON file.

        :param filename: Name of the file to save the data to.
        :type filename: str
        """
        logger.info(f"Writing to file {filename}")
        data = {address: device.to_dict() for address, device in self.scanned_devices.items()}
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"File created successfully")
    
    def append_json_to_csv(self) -> None:
        """
        Append the scanned BLE devices inside a BLEScanner to the existing CSV file.
        """

        logger.info(f"Adding json data to file {self.filename}")
        json_data = {address: device.to_dict() for address, device in self.scanned_devices.items()}

        with open(f"{self.filename}.csv", 'r', newline='') as csvfile:
            csvreader = csv.reader(csvfile)
            _ = next(csvreader)
            rows = list(csvreader)

        modified_rows = []
        for row in rows:
            address = row[0]
            no_index_7 = False
            try:
                scan_data_in_csv = row[7]
            except IndexError:
                scan_data_in_csv = ""
                no_index_7 = True

            address_in_json_data = json_data.get(address, "")

            if address_in_json_data and len(str(address_in_json_data)) > len(scan_data_in_csv):
                logger.info(f"Found new data for device {address}...")
                if no_index_7:
                    logger.info("Appending new data to CSV")
                    row_data = address_in_json_data
                    try:
                        json_string = json.dumps(row_data)
                    except TypeError:
                        json_string = ""
                        print(row_data)
                    row.append(json_string)
                else:
                    logger.info("Data is newer than what was found in CSV. replacing it")
                    json_string = json.dumps(address_in_json_data)
                    row[7] = json_string
            modified_rows.append(row) 

        with open(f"{self.filename}.csv", mode='w', encoding='utf-8', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(CSV_HEADERS)
            csv_writer.writerows(modified_rows)

        logger.info("Successfully wrote new and updated CSV file")


# ---------------------------------------------------------------------------------------------------------------------#
#                                                     Usages                                                           #
# ---------------------------------------------------------------------------------------------------------------------#


def scan_continuous(filename: str) -> None:
    """
    Continuously scan for BLE devices until a stop condition is met.

    This function starts a continuous scan process for BLE devices, logging the
    data and saving it to a file. It will run indefinitely until a 'ble_scan.lock'
    file is no longer present in the specified path or a KeyboardInterrupt is
    raised.

    Parameters:
    - filename (str): The file path where the scan results will be logged.

    """

    logger.info("Starting Script continuously. Initializing Scanner Object")
    scanner = BLEScanner(filename)

    try:
        while os.path.exists("/opt/proteciotnet/proteciotnet_dev/static/ble_scan.lock"):
            scanner.scan()

    except KeyboardInterrupt:
        logger.info("Stopped by user")


def scan_all_devices_and_read_all_fields(filename: str,
                                         with_descriptors: bool = False,
                                         connectable_only: bool = False) -> None:
    """
    Scan for all BLE devices in the vicinity and read all their fields.

    This function will scan for all available BLE devices. If a device is connectable,
    it will attempt to connect to the device and read all its services, characteristics,
    and descriptors (if the `with_descriptors` flag is set to True). After reading all
    the data, it will save the information to a JSON file.

    :param filename: Name of the file to save the scanned data to.
    :type filename: str
    :param with_descriptors: Flag indicating if descriptors should be read. Default is False.
    :type with_descriptors: bool
    :param connectable_only: Flag indicating to only scan connectable devices
    :type connectable_only: bool
    """
    # ----------------- SCANNING ALL DEVICES ----------------- #

    logger.info("Starting Script. Initializing Scanner Object")
    scanner1 = BLEScanner(filename=filename,
                          connectable_only=connectable_only)
    try:
        scanner1.scan(duration=BT_SCAN_TIME)
    except BTLEDisconnectError:
        try:
            logger.info("First scanning attempt failed. Trying again after 0.2 seconds...")
            sleep(0.2)
            scanner1.scan(duration=BT_SCAN_TIME)
        except Exception:
            logger.error(f"An error occurred while scanning devices")
            pass
    except KeyboardInterrupt:
        pass

    # ---------------- READING ALL ATTRIBUTES ---------------- #

    for address, device in scanner1.scanned_devices.items():
        if device.connectable:
            try:
                logger.info(f"Connecting to {device.address} ({device.name})...")
                scanner1.connect_and_read_all(addr=address,
                                              addr_type=device.addr_type,
                                              with_descriptors=with_descriptors)
            except Exception as e:
                logger.error(e)
                continue

    if scanner1.successful_scans > 0:
        scanner1.append_json_to_csv()


def scan_list_only(filename: str, beacons_only: bool, connectable_only: bool) -> None:
    """
    Perform a BLE scan in list mode and potentially save the results to a JSON file.

    This function initializes a BLEScanner with specific flags for listing
    beacons only or connectable devices only, executes the scan, and if any
    successful scans are detected, saves the results to a JSON file named
    after the provided filename.

    Parameters:
    - filename (str): The file path where the scan results will be saved.
    - beacons_only (bool): Flag to indicate whether only beacons should be scanned.
    - connectable_only (bool): Flag to indicate whether only connectable devices should be scanned.

    """

    scanner_list_mode = BLEScanner(filename=filename,
                                   beacons_only=beacons_only,
                                   connectable_only=connectable_only)

    try:
        scanner_list_mode.scan()

    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception:
        logger.error(f"An error occurred while scanning devices")
        pass

    if scanner_list_mode.successful_scans > 0:
        scanner_list_mode.save_to_json(filename=filename)


def scan_single_device(filename: str, device_address: str) -> None:
    """
    Scan a single BLE device by its address and save the data to a JSON file.

    The function scans for BLE devices, and if the specified device is found,
    it attempts to connect, read all the available information, and then save
    that data to a JSON file. If the device is not found or an error occurs,
    it logs the appropriate message.

    Parameters:
    - filename (str): The file path where the scan results will be saved.
    - device_address (str): The BLE address of the device to scan.

    """

    scanner_connect_single_device = BLEScanner(filename=filename)
    try:
        scanner_connect_single_device.scan()
    except Exception:
        logger.error(f"An error occurred while scanning devices")
        return None

    device = scanner_connect_single_device.scanned_devices.get(device_address, "")
    device_addr_type = device.addr_type if device else ""
    if device:
        scanner_connect_single_device.connect_and_read_all(addr=device,
                                                           addr_type=device_addr_type)
        scanner_connect_single_device.save_to_json(filename=filename)

    else:
        logger.error("Device not found. Is it advertising?")
        return None


def scan_beacons_only(filename: str) -> None:
    """
    Scan for Apple AirTag beacons only and save the results to a JSON file.

    This function is specifically tailored to scan for devices that are Apple
    AirTags, logging an error if a problem occurs during the scan.

    Parameters:
    - filename (str): The file path where the scan results will be saved.

    """

    scanner_beacons_only = BLEScanner(filename)
    try:
        scanner_beacons_only.scan_for_apple_airtags()
    except Exception:
        logger.error(f"An error occurred while scanning for AirTag beacons")
        return None

    scanner_beacons_only.save_to_json(filename=filename)


def runner(filename: str,
           scan_time: int,
           interface: int = BT_INTERFACE_INDEX,
           connection_timeout: int = CONNECTION_TIMEOUT,
           with_descriptors: bool = False,
           list_mode: bool = False,
           connectable_only: bool = False,
           beacons_only: bool = False,
           bonding_test: bool = False,
           schedule: bool = False,
           schedule_frequency: bool = False,
           specific_device_addr: str = "") -> None:

    """
    Orchestrates different BLE scanning modes and operations.

    Based on the parameters provided, this function will run the appropriate
    BLE scan operation in a new process. It can handle scanning a specific
    device, scanning in list mode, scanning for beacons only, and regular
    scanning with various options like descriptor reading, continuous scanning,
    and connectable-only filtering.

    Parameters:
    - filename (str): The file path for saving scan results.
    - scan_time (int): The duration for which the scan should run.
    - interface (int): The Bluetooth interface index to use for scanning.
    - connection_timeout (int): The connection timeout duration in seconds.
    - with_descriptors (bool): Flag to indicate if descriptors should also be scanned.
    - list_mode (bool): Flag to enable scanning in list mode.
    - connectable_only (bool): Flag to filter for connectable devices only.
    - beacons_only (bool): Flag to scan for beacon devices only.
    - bonding_test (bool): Flag to enable bonding tests (not used in function body).
    - schedule (bool): Flag to schedule scans (not used in function body).
    - schedule_frequency (bool): Flag to set the frequency of scheduled scans (not used in function body).
    - specific_device_addr (str): The BLE address of a specific device to scan for.

    """

    global BT_INTERFACE_INDEX, BT_SCAN_TIME, CONNECTION_TIMEOUT
    BT_INTERFACE_INDEX = interface
    BT_SCAN_TIME = scan_time
    CONNECTION_TIMEOUT = connection_timeout

    if specific_device_addr:
        scan_device_process = multiprocessing.Process(
            scan_single_device(filename=filename,
                               device_address=specific_device_addr)
        )
        scan_device_process.start()
        return

    if list_mode:
        scanning_process_list_mode = multiprocessing.Process(
            scan_list_only(filename=filename,
                           beacons_only=beacons_only,
                           connectable_only=connectable_only)
        )
        scanning_process_list_mode.start()
        return
    elif not beacons_only:
        scanning_process = multiprocessing.Process(
            scan_all_devices_and_read_all_fields(filename=filename,
                                                 connectable_only=connectable_only,
                                                 with_descriptors=with_descriptors)
        )
        scanning_process.start()
        return

    if beacons_only:
        beacons_process = multiprocessing.Process(
            scan_beacons_only(filename=filename)
        )
        beacons_process.start()
        return


def main2():
    print("Starting Script. Initializing Scanner Object")
    scanner1 = BLEScanner(filename="/home/henry/Downloads/long_time_scan",
                          connectable_only=False)
    try:
        scanner1.scan(duration=99999)
    except BTLEDisconnectError:
        try:
            logger.info("First scanning attempt failed. Trying again after 0.2 seconds...")
            sleep(0.2)
            scanner1.scan(duration=BT_SCAN_TIME)
        except Exception:
            logger.error(f"An error occurred while scanning devices")
            pass
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main2()
