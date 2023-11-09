import hashlib
import html
import json
import os
import re
import logging

import xmltodict
from django.http import HttpResponse

try:
    from proteciotnet_dev.static.py.cwe_descriptions_dict import cwe_descriptions
except ModuleNotFoundError:
    from static.py.cwe_descriptions_dict import cwe_descriptions

_CVSS_2_PATTERN = r"CVSS 2.0 score: (\d.\d|0|\d\d.\d)"
_CVSS_3_PATTERN = r"CVSS 3.[\d|x] score: (\d.\d|0)"
_CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
_CWE_PATTERN = r"CWE-\d{1,3}"
_BASE_DIRECTORY = "/opt/proteciotnet/proteciotnet_dev/"
_BASE_STATIC_DIRECTORY = f"{_BASE_DIRECTORY}static"
_BASE_REPORTS_DIR = f"{_BASE_STATIC_DIRECTORY}/reports/"
_BASE_ZIGBEE_REPORTS_DIR = f"/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports"
_BASE_ZIGBEE_DIR = "/opt/zigbee"

logger = logging.getLogger(__name__)


def token_check(token):
    return True


def get_cvss_color(cvss_score, version=2):
    """
    Get color codes for CVSS score based on severity levels.

    Args:
        cvss_score (str or float): The CVSS score.
        version (int, optional): The CVSS version (2 or 3). Default is 2.

    Returns:
        tuple: A tuple containing two color codes: background color and text color.

    Example:
        get_cvss_color(5.6, version=2)
        # Returns: ('yellow', 'black')
    """

    # Define score ranges and corresponding colors for CVSS version 2
    score_range_version_2 = {
        (0, 3.9): 'green',
        (4.0, 6.9): 'yellow',
        (7.0, 10.0): 'red',
    }

    score_range_version_3 = {
        (0, 0): 'grey',
        (0.1, 3.9): 'green',
        (4.0, 6.9): 'yellow',
        (7.0, 8.9): 'orange',
        (9.0, 10.0): 'red'
    }

    try:
        cvss_score = float(cvss_score)
    except ValueError:
        return 'black', 'white'  # Return None if the cvss_score cannot be converted to a float

    if version == 2:
        for score_range, color in score_range_version_2.items():
            if score_range[0] <= cvss_score <= score_range[1]:
                return color, "white" if color != "yellow" else "black"

    elif version == 3:
        for score_range_v3, color in score_range_version_3.items():
            if score_range_v3[0] <= cvss_score <= score_range_v3[1]:
                return color, "white" if color != "yellow" else "black"

    # Return None if the cvss_score is not within any defined range
    return 'black', 'white'


def get_cwe_description(cwe_nr):
    """
    Get the CWE description for a given CWE number.

    Args:
        cwe_nr (str): The CWE number.

    Returns:
        str: The CWE description or a default message if not found.
    """

    if cwe_nr in cwe_descriptions:
        return f"{cwe_nr}: {cwe_descriptions[cwe_nr]}"

    return "no description available"


def label_to_margin(label):
    """
    Convert a label to the corresponding margin value.

    Args:
        label (str): The label.

    Returns:
        str: The margin value or None if not found.
    """

    labels = {
        'Vulnerable': '10px',
        'Critical': '22px',
        'Warning': '28px',
        'Checked': '28px'
    }

    return labels.get(label)


def label_to_color(label):
    """
    Convert a label to the corresponding color.

    Args:
        label (str): The label.

    Returns:
        str: The color or None if not found.
    """

    labels = {
        'Vulnerable': 'red',
        'Critical': 'black',
        'Warning': 'orange',
        'Checked': 'special_blue'
    }

    return labels.get(label)


def from_os_type_to_font_awesome(os_type):
    """
    Convert an operating system type to the corresponding Font Awesome icon class.

    Args:
        os_type (str): The operating system type.

    Returns:
        str: The Font Awesome icon class or a default icon class if not found.
    """
    icons = {
        'windows': 'fab fa-windows',
        'solaris': 'fab fa-linux',
        'unix': 'fab fa-linux',
        'linux': 'fab fa-linux'
    }

    return icons.get(os_type.lower(), 'fas fa-question')


def nmap_ports_stats(scanfile: str) -> dict:
    """
    This module contains the `nmap_ports_stats` function that analyzes port scan data
    from an XML file generated by Nmap and returns port statistics along with debug information.

    Functions:
        nmap_ports_stats(scanfile: str) -> dict:
            Parses the Nmap XML scan data from a given file and calculates port statistics.

            Args:
                scanfile (str): The path to the Nmap XML scan file.

            Returns:
                dict: A dictionary containing port statistics and debug information.
                    - 'po' (int): Count of open ports.
                    - 'pc' (int): Count of closed ports.
                    - 'pf' (int): Count of filtered ports.
                    - 'debug' (str): JSON-encoded debug information.
                    - 'pos' (str): Formatted count of open ports.
                    - 'pcs' (str): Formatted count of closed ports.
                    - 'pfc' (str): Formatted count of filtered ports.
    """

    try:
        parsed_xml_nmap_file = xmltodict.parse(open('/opt/xml/' + scanfile, 'r').read())
    except:
        return {'po': 0, 'pc': 0, 'pf': 0}

    nmap_run_dict = parsed_xml_nmap_file['nmaprun']

    debug = {}
    ports_open, ports_closed, ports_filtered = 0, 0, 0

    if 'host' not in nmap_run_dict:
        return {'po': 0, 'pc': 0, 'pf': 0}

    port_id_counter = 0
    for items in nmap_run_dict['host']:

        if type(items) is dict:
            item = items
        else:
            item = nmap_run_dict['host']

        id_of_last_port = 0
        address = None

        if '@addr' in item['address']:
            address = item['address']['@addr']
        elif type(item['address']) is list:
            for ai in item['address']:
                if ai['@addrtype'] == 'ipv4':
                    address = ai['@addr']

        if not address:
            continue

        if 'ports' in item and 'port' in item['ports']:
            for port_object in item['ports']['port']:
                if type(port_object) is dict:
                    port = port_object
                else:
                    port = item['ports']['port']

                if id_of_last_port == port['@portid']:
                    continue
                else:
                    id_of_last_port = port['@portid']

                if address not in debug:
                    debug[address] = {'portcount': {'pc': {}, 'po': {}, 'pf': {}}}
                debug[address][port['@portid']] = port['state']

                if port['state']['@state'] == 'closed':
                    ports_closed += 1
                    debug[address]['portcount']['pc'][port_id_counter] = ports_closed
                elif port['state']['@state'] == 'open':
                    ports_open += 1
                    debug[address]['portcount']['po'][port_id_counter] = ports_open
                elif port['state']['@state'] == 'filtered':
                    ports_filtered += 1
                    debug[address]['portcount']['pf'][port_id_counter] = ports_filtered
                port_id_counter += 1

    ports_open_string = html.escape(f"{ports_open}{(4 - len(str(ports_open))) * ' '}")
    ports_closed_string = html.escape(f"{ports_closed}{(4 - len(str(ports_closed))) * ' '}")
    ports_filtered_string = html.escape(f"{ports_filtered}{(4 - len(str(ports_filtered))) * ' '}")

    return {'po': ports_open, 'pc': ports_closed, 'pf': ports_filtered, 'debug': json.dumps(debug),
            "pos": ports_open_string, "pcs:": ports_closed_string, "pfc": ports_filtered_string}


def get_cve(md5_hash_of_scan: str) -> dict:
    """
    Retrieve CVE information from files based on scan MD5 hash.

    This function searches for files in the '/opt/notes' directory that match
    the provided scan MD5 hash and extracts CVE information from them.

    Args:
        md5_hash_of_scan (str): Scan MD5 hash to match against file names.

    Returns:
        dict: A dictionary containing CVE information organized by host and CVE ID.

    Example:
        get_cve("abcdef1234567890")
        # Returns: {
        #     'abcdef1234567890': {
        #         'cve1_hash': 'CVE-123-456 information...',
        #         'cve2_hash': 'CVE-789-012 information...'
        #     }
        # }
    """
    host_cves = {}
    files = os.listdir('/opt/notes')
    for file in files:
        match = re.match(f'^({md5_hash_of_scan})_([a-z0-9]{{32,32}})\.cve$', file)
        if match is not None:
            if match.group(1) not in host_cves:
                host_cves[match.group(1)] = {}

            if match.group(2) not in host_cves[match.group(1)]:
                host_cves[match.group(1)][match.group(2)] = open('/opt/notes/' + file, 'r').read()

    return host_cves


def get_ports_details(scanfile: str) -> dict:
    """
    This function processes Nmap scan data from an XML file and retrieves details about ports, hosts, and associated information.

    Args:
        scanfile (str): The name of the Nmap XML scan file. The file has to be in the folder /opt/xml/

    Returns:
        dict: A dictionary containing port details and host information.
            - 'file' (str): The scan file path.
            - 'hosts' (dict): A dictionary of host details.
                - Address (str): Dictionary with host details.
                    - 'ports' (list): List of dictionaries containing port details.
                        - 'port' (str): Port number.
                        - 'name' (str): Service name.
                        - 'state' (str): Port state.
                        - 'protocol' (str): Protocol used by the port.
                        - 'reason' (str): Type of scan to validate port state.
                        - 'product' (str): Product information of the service.
                        - 'version' (str): Version information of the service.
                        - 'extrainfo' (str): Additional information about the service.
                    - 'hostname' (dict): Hostname details.
                    - 'label' (str): Host label.
                    - 'notes' (str): Host notes.
                    - 'CVE' (list): List of Common Vulnerabilities and Exposures (CVE) associated with the host.
    """

    # I think unused and in api.py

    try:
        parsed_xml_nmap_file = xmltodict.parse(open('/opt/xml/' + scanfile, 'r').read())
    except:
        return {}

    nmap_run_dict = parsed_xml_nmap_file['nmaprun']

    return_value_dict = {'file': scanfile, 'hosts': {}}
    md5_hash_of_scanfile = hashlib.md5(str(scanfile).encode('utf-8')).hexdigest()

    host_labels = {}
    host_notes = {}
    files = os.listdir('/opt/notes')
    for file in files:
        match_labels = re.match(f'^({md5_hash_of_scanfile})_([a-z0-9]{32, 32})\.host\.label$', file)
        if match_labels is not None:
            if match_labels.group(1) not in host_labels:
                host_labels[match_labels.group(1)] = {}
            host_labels[match_labels.group(1)][match_labels.group(2)] = open('/opt/notes/' + file, 'r').read()

        match_notes = re.match(f'^({md5_hash_of_scanfile})_([a-z0-9]{32, 32})\.notes$', file)
        if match_notes is not None:
            if match_notes.group(1) not in host_notes:
                host_notes[match_notes.group(1)] = {}
            host_notes[match_notes.group(1)][match_notes.group(2)] = open('/opt/notes/' + file, 'r').read()

    cve_of_host = get_cve(md5_hash_of_scanfile)

    for items in nmap_run_dict['host']:

        # this fixes single host report
        if type(items) is dict:
            item = items
        else:
            item = nmap_run_dict['host']

        hostname = {}
        if 'hostnames' in item and type(item['hostnames']) is dict:
            if 'hostname' in item['hostnames']:
                if type(item['hostnames']['hostname']) is list:
                    for hostname_item in item['hostnames']['hostname']:
                        hostname[hostname_item['@type']] = hostname_item['@name']
                else:
                    hostname[item['hostnames']['hostname']['@type']] = item['hostnames']['hostname']['@name']

        print(hostname)

        if item['status']['@state'] == 'up':
            services, ports = {}, {}
            id_of_last_port = 0

            address = None
            if '@addr' in item['address']:
                address = item['address']['@addr']
            elif type(item['address']) is list:
                for ai in item['address']:
                    if ai['@addrtype'] == 'ipv4':
                        address = ai['@addr']

            if not address:
                continue

            md5_hash_address = hashlib.md5(str(address).encode('utf-8')).hexdigest()

            host_labels_out = host_labels.get(md5_hash_of_scanfile, {}).get(md5_hash_address, '')
            host_notes_base64_out = host_notes.get(md5_hash_of_scanfile, {}).get(md5_hash_address, '')

            host_cves_out = cve_of_host.get(md5_hash_of_scanfile, {}).get(md5_hash_address, '')
            if host_cves_out:
                host_cves_out = json.loads(host_cves_out)

            return_value_dict['hosts'][address] = {'ports': [],
                                                   'hostname': hostname,
                                                   'label': host_labels_out,
                                                   'notes': host_notes_base64_out,
                                                   'CVE': host_cves_out
                                                   }

            if 'ports' in item and 'port' in item['ports']:
                for port_object in item['ports']['port']:
                    if isinstance(port_object, dict):
                        port = port_object
                    else:
                        port = item['ports']['port']

                    if id_of_last_port == port['@portid']:
                        continue
                    else:
                        id_of_last_port = port['@portid']

                    ports[port['@portid']] = port['@portid']
                    version = port.get('service', {}).get('@version', '')
                    product = port.get('service', {}).get('@product', '')
                    extra_info = port.get('service', {}).get('@extrainfo', '')

                    service_name = port.get('service', {}).get('@name', '')

                    if 'service' in port:
                        services[port['service']['@name']] = port['service']['@name']

                    return_value_dict['hosts'][address]['ports'].append(
                        {
                            'port': port['@portid'],
                            'name': service_name,
                            'state': port['state']['@state'],
                            'protocol': port['@protocol'],
                            'reason': port['state']['@reason'],
                            'product': product,
                            'version': version,
                            'extrainfo': extra_info
                        })
    return return_value_dict


def insert_linebreaks(input_string: str, max_line_length: int = 40) -> str:
    """
    Insert line breaks into a long string to ensure each line'input_string length does not exceed a given limit.

    Args:
        input_string (str): The input string to insert line breaks into.
        max_line_length (int, optional): Maximum length of each line. Default is 60.

    Returns:
        str: The input string with inserted line breaks into HTML paragraphs.
    """

    # words = input_string.split()
    # lines = []
    # line = ""
    # 
    # for word in words:
    #     if len(line) + len(word) + 1 <= max_line_length:
    #         if line:
    #             line += " " + word
    #         else:
    #             line = word
    #     else:
    #         lines.append(line)
    #         line = word
    # 
    # if line:
    #     lines.append(line)
    # 
    # joined_lines = "<br>".join(lines)
    # return f"<p>{joined_lines}</p>"

    lines = []
    current_line = ""
    i = 0

    while i < len(input_string):

        match = re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", input_string[i:])
        if match:
            ip = match.group()
            if len(current_line) + len(ip) <= 60:
                current_line += ip
                i += len(ip)
                continue
            else:
                lines.append(current_line)
                current_line = ip
                i += len(ip)
                continue

        if len(current_line) + 1 <= max_line_length:
            current_line += input_string[i]
            i += 1

        elif input_string[i] == ' ' or (
                input_string[i] in ['/', ',', ';', ':', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '?'] and
                input_string[i - 1] != '-'):
            lines.append(current_line)
            current_line = ""

        else:
            current_line += input_string[i]
            i += 1

    if current_line:
        lines.append(current_line)

    return f"<p>{'<br>'.join(lines)}</p>"


def _split_cve_html(CVEs):
    """
    Split the HTML content containing CVE entries into individual CVE blocks.

    Args:
        cves_html (str): HTML content containing CVE entries.

    Returns:
        list: List of individual CVE blocks.
    """

    pattern = r'<div id="CVE-'
    split_strings = re.split(pattern, CVEs)
    return ['<div id="CVE-' + part for part in split_strings[1:]]


def _extract_cwe_number_from_block(cve):
    """
    Extract the numeric portion of the CWE.

    Args:
        cve (str): CVE ID.

    Returns:
        int: Extracted numeric portion of the CWE.
    """
    cwe_match = re.findall(_CWE_PATTERN, cve)
    if cwe_match:
        try:
            return int(cwe_match[-1].split("-")[1])
        except ValueError:
            return 0
    return 0


def _extract_cvss2_score(cve):
    """
    Extract the CVSS 2.0 score from a CVE block.

    Args:
        cve (str): CVE block containing CVSS 2.x score.

    Returns:
        float: Extracted CVSS 3.x score.
    """
    match = re.findall(_CVSS_2_PATTERN, cve)
    if match:
        try:
            return float(match[0])
        except ValueError:
            return 0.0
    return 0.0


def _extract_cvss3_score(cve):
    """
    Extract the CVSS 3.x score from a CVE block.

    Args:
        cve (str): CVE block containing CVSS 3.x score.

    Returns:
        float: Extracted CVSS 3.x score.
    """
    match = re.findall(_CVSS_3_PATTERN, cve)
    if match:
        try:
            return float(match[0])
        except ValueError:
            return 0.0
    return 0.0


def search_cve_html(cves_html, search_string):
    """
    Search for a specific string within a list of HTML CVE (Common Vulnerabilities and Exposures) entries.

    Parameters:
    - cves_html (str): A string containing HTML for multiple CVEs.
    - search_string (str): The string to search for within the CVE entries. Assumes the search_string is prefixed with "search=" and removes it before performing the search.

    Returns:
    - str: A HTML string containing all CVE entries that include the search string.
    """

    search_string = search_string.replace("search=", "").strip().lower()
    logger.info(f"Trying to search in CVE entries for {search_string}")

    split_cves = _split_cve_html(cves_html)
    result = ''.join([cve for cve in split_cves if search_string in cve.lower()])

    if result:
        return result
    else:
        return """
        <div id="no_results" style="line-height:28px;padding:10px;border-bottom:solid #666 1px;margin-top:10px;" class="center">
            Your search returned no results. You can use your browser to get back or click the "x" icon in the search bar.
            <br><br>
        </div>
        """


def _sort_cve_list(cve_list, key_function, reverse_order):
    """
    Sort a list of CVE blocks based on a given key function and sorting order.

    Args:
        cve_list (list): List of CVE blocks.
        key_function (callable): Function to extract the sorting key from a CVE block.
        reverse_order (bool): True for descending order, False for ascending order.

    Returns:
        str: Sorted CVE blocks as a single html string.
    """
    return ''.join(sorted(cve_list, key=key_function, reverse=reverse_order))


def sort_cve_html(cves_html, sorting_order):
    """
    Sort the HTML content containing CVE entries based on the specified sorting order.

    Args:
        cves_html (str): HTML content containing CVE entries.
        sorting_order (str): Sorting order: "cvss2asc", "cvss2desc", "cvss3asc", "cvss3desc", "cveasc", "cvedesc", 'cweasc, "cwedesc"

    Returns:
        str: Sorted HTML content of CVE entries.
    """

    logger.info("Trying to sort CVE entries")
    split_cves = _split_cve_html(cves_html)

    if sorting_order == "cvss2asc":
        for elem in split_cves:
            print(re.findall(_CVSS_2_PATTERN, elem))
        return _sort_cve_list(split_cves, _extract_cvss2_score, False)
    elif sorting_order == "cvss2desc":
        return _sort_cve_list(split_cves, _extract_cvss2_score, True)

    elif sorting_order == "cvss3asc":
        return _sort_cve_list(split_cves, _extract_cvss3_score, False)
    elif sorting_order == "cvss3desc":
        return _sort_cve_list(split_cves, _extract_cvss3_score, True)

    elif sorting_order == "cveasc":
        return _sort_cve_list(split_cves, lambda x: re.findall(_CVE_PATTERN, x)[0], False)
    elif sorting_order == "cvedesc":
        return _sort_cve_list(split_cves, lambda x: re.findall(_CVE_PATTERN, x)[0], True)

    elif sorting_order == "cweasc":
        return _sort_cve_list(split_cves, _extract_cwe_number_from_block, False)
    elif sorting_order == "cwedesc":
        return _sort_cve_list(split_cves, _extract_cwe_number_from_block, True)

    else:
        return cves_html


def parse_config_file(filename: str = 'proteciotnet.config') -> dict:
    """
    Parse a configuration file in INI-like format and return the parsed data.

    This function reads the contents of the specified configuration file and
    parses it to create a hierarchical dictionary containing the configuration
    data.

    Args:
        filename (str, optional): The path to the configuration file to be parsed.
            Default is 'proteciotnet.config'.

    Returns:
        dict: A hierarchical dictionary containing the parsed configuration data.
            The dictionary structure is organized by sections, where each section
            is represented as a dictionary containing its associated options and
            values.

    Example:
        Given a configuration file 'example.config' with the following content:
        ```
        [Section1]
        Option1 = Value1
        Option2 = Value2

        [Section2]
        Option3 = Value3
        ```
        Calling `parse_config_file('my_config.ini')` would return:
        ```
        {
            'Section1': {
                'Option1': 'Value1',
                'Option2': 'Value2'
            },
            'Section2': {
                'Option3': 'Value3'
            }
        }
        ```

    Note:
        - Lines starting with '#' are treated as comments and are ignored.
        - The function assumes that each section header is enclosed in square brackets,
          e.g., '[Section]'.
        - Each option and value within a section should be separated by '=' and will
          be stored as strings in the parsed dictionary.
    """

    parsed_data = {}
    current_section = None

    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                parsed_data[current_section] = {}
            else:
                key, value = line.split('=', 1)
                parsed_data[current_section][key.strip()] = value.strip()

    return parsed_data


def create_file_dropdown_zigbee(filename):
    contents_directory = os.listdir(_BASE_ZIGBEE_REPORTS_DIR)
    filename_without_extension = filename.rsplit(".", 1)[0]

    dropdown_html = ''
    if any(filename_without_extension in local_file for local_file in contents_directory if not local_file.endswith(('.svg', '.dot'))):

        dropdown_html += f'<ul id="dropdown_{filename}_files" class="dropdown-content" style="min-width:300px; border-radius: 4px;">'

        if f"{filename_without_extension}.pcap" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'pcap')" style="color:#111111">Download PCAP File</a></li>"""

        if f"{filename_without_extension}.json" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'json')" style="color:#111111">Download JSON File</a></li>"""

        if f"{filename_without_extension}.pdf" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'pdf')" style="color:#111111">Open PDF File</a></li>"""

        if f"{filename_without_extension}.html" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'html')" style="color:#111111">Open HTML File</a></li>"""

        if f"{filename_without_extension}.csv" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'csv')" style="color:#111111">Download CSV File</a></li>"""

        if f"{filename_without_extension}.txt" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'txt')" style="color:#111111">Open Text File</a></li>"""

        if f"{filename_without_extension}.pcapng" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'pcapng')" style="color:#111111">Download PCAPNG File</a></li>"""

        if f"{filename_without_extension}.psml" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'psml')" style="color:#111111">Download PSML File</a></li>"""

        if f"{filename_without_extension}.pdml" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'pdml')" style="color:#111111">Download PDML file</a></li>"""

        if f"{filename_without_extension}.ekjson" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="open_zigbee_report('{filename}', 'ekjson')" style="color:#111111">Download JSON File for Elasticsearch</a></li>"""

        dropdown_html += f'</ul><a class="dropdown-trigger" href="#!" data-target="dropdown_{filename}_files" style="color: #ff9800;"><i class="material-icons">file_open</i> Files</a><br><br>'

    return dropdown_html


def create_file_dropdown(filename):
    contents_directory = os.listdir(_BASE_REPORTS_DIR)
    filename_without_extension = filename.rsplit(".", 1)[0]

    dropdown_html = ''
    if any(filename_without_extension in local_file for local_file in contents_directory):
        dropdown_html += f'<ul id="dropdown_{filename}_files" class="dropdown-content" style="min-width:300px; border-radius: 4px;">'

        if f"{filename_without_extension}.pdf" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'pdf')" style="color:#111111">Open PDF report</a></li>"""

        if f"{filename_without_extension}.md" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'md')" style="color:#111111">Download Markdown report</a></li>"""

        if f"{filename_without_extension}.html" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'html')" style="color:#111111">Open HTML report</a></li>"""

        if f"{filename_without_extension}.json" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'json')" style="color:#111111">Open JSON report</a></li>"""

        if f"{filename_without_extension}.csv" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'csv')" style="color:#111111">Download CSV report</a></li>"""

        if f"{filename_without_extension}.svg" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'svg')" style="color:#111111">Open image</a></li>"""

        if f"{filename_without_extension}.dot" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'dot')" style="color:#111111">Download .dot file</a></li>"""

        if f"{filename_without_extension}.sqlite" in contents_directory:
            dropdown_html += f"""<li><a href="#" onclick="openReport('{filename}', 'sqlite')" style="color:#111111">Download SQLite database</a></li>"""

        dropdown_html += f'</ul><a class="dropdown-trigger" href="#!" data-target="dropdown_{filename}_files" style="color: #ff9800;"><i class="material-icons">file_open</i> Files</a><br><br>'

    return dropdown_html


def set_state(request):
    res = {'p': request.POST}

    if request.method == "POST":
        toggle_status = request.POST['online_status']

        if toggle_status == "true":
            if "offline_mode.lock" not in os.listdir(_BASE_STATIC_DIRECTORY):

                try:
                    with open(f"{_BASE_STATIC_DIRECTORY}/offline_mode.lock", "w") as f:
                        pass
                except:
                    logger.error("Could not create 'offline_mode.lock' file")
                    return HttpResponse(json.dumps({'error': 'file creation problem'}, indent=4),
                                        content_type="application/json")

            logger.info("Successfully changed to offline mode")

        else:
            try:
                if "offline_mode.lock" in os.listdir(_BASE_STATIC_DIRECTORY):
                    os.remove(f"{_BASE_STATIC_DIRECTORY}/offline_mode.lock")
            except:
                logger.error("Could not delete offline_mode.lock' file")
                return HttpResponse(json.dumps({'error': 'file deletion problem'}, indent=4),
                                    content_type="application/json")
            logger.info("Successfully changed to online mode")

        return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
    else:
        logger.error("Something went wrong while trying to set offline/online mode toggle")
        res = {'error': 'invalid syntax'}
        return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
