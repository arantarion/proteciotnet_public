import hashlib
import json
import re
import requests
import xmltodict
import logging
import urllib3
import socket
import sys

from configparser import ConfigParser, ExtendedInterpolation

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    config_cve_cdn = ConfigParser(interpolation=ExtendedInterpolation())
    config_cve_cdn.read('proteciotnet.config')

    _CVE_SEARCH_IP_ADDRESS = config_cve_cdn.get('CVE_API', 'cve_search_ip_address')
    _CVE_SEARCH_PORT = config_cve_cdn.get('CVE_API', 'cve_search_port')
    _CVE_SEARCH_TIMEOUT = int(config_cve_cdn.get('CVE_API', 'cve_search_timeout'))

    _WIFI_XML_BASE_DIRECTORY = config_cve_cdn.get('WIFI_PATHS', 'wifi_xml_base_directory')
    _NOTES_DIRECTORY = config_cve_cdn.get('GENERAL_PATHS', 'notes_directory')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def _check_network_connection(ip: str, port: str) -> bool:
    """
    Check the network connection to a specified IP address and port.

    Args:
        ip (str): The IP address to check the connection.
        port (int): The port number to check the connection.

    Returns:
        bool: True if the connection is successful, False otherwise.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(_CVE_SEARCH_TIMEOUT)
    try:
        s.connect((ip, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        logger.debug(f"cve-search instance can be reached via ip {ip} and port {port}")
        return True
    except Exception as e:
        logger.error(f"cve-search can not be reached on ip {ip} and port {port}. Exception {e}")
        return False
    finally:
        s.close()
        logger.debug(f"Connection closed.")


def getcpe(xmlfile: str) -> dict:
    """
    Extract CPE and CVE information from an XML file generated by Nmap.
    This is the local cve-search version.

    Args:
        xmlfile (str): The name of the XML file to parse.

    Returns:
        dict: A dictionary containing CPE and CVE information extracted from the XML file.

    """
    cpe, cve = {}, {}

    oo = xmltodict.parse(open(f'{_WIFI_XML_BASE_DIRECTORY}/{xmlfile}', 'r').read())
    o = json.loads(json.dumps(oo['nmaprun'], indent=4))

    logger.debug(f"Successfully loaded {xmlfile}")

    for ik in o['host']:
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        lastportid = 0

        if '@addr' in i['address']:
            address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    address = ai['@addr']

        addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
        cpe[address] = {}
        cve[address] = {}

        if 'ports' in i and 'port' in i['ports']:
            for pobj in i['ports']['port']:
                if type(pobj) is dict:
                    p = pobj
                else:
                    p = i['ports']['port']

                if lastportid == p['@portid']:
                    continue
                else:
                    lastportid = p['@portid']

                if 'service' in p:
                    if 'cpe' in p['service']:
                        if type(p['service']['cpe']) is list:
                            for cpei in p['service']['cpe']:
                                cpe[address][cpei] = cpei
                        else:
                            cpe[address][p['service']['cpe']] = p['service']['cpe']

                if 'script' in p:
                    if type(p['script']) is list:
                        for scripti in p['script']:
                            if 'elem' in scripti:
                                if type(scripti['elem']) is list:
                                    for elmi in scripti['elem']:
                                        if elmi['@key'] == 'cve':
                                            cve[address][elmi['#text']] = elmi['#text']

        if type(ik) is not dict:
            break

    res = {'cpe': cpe, 'cve': cve}
    logger.debug(f"Found: {res}")
    return res


def getcve(xmlfile: str) -> None:
    """
    Extract CVE information from CPE data obtained from an XML file generated by Nmap.
    This is the local version of this function.

    Args:
        xmlfile (str): The name of the XML file containing Nmap scan results.

    Returns:
        None: This function writes JSON files containing CVE information to the '/opt/notes/' directory.
    """

    scanfilemd5 = hashlib.md5(str(xmlfile).encode('utf-8')).hexdigest()
    cpecve = getcpe(xmlfile)
    cvejson = {}

    for i in cpecve['cpe']:

        if i not in cvejson:
            cvejson[i] = []

        for cpestr in cpecve['cpe'][i]:
            if re.search('^cpe:[^:]+:[^:]+:[^:]+:.+$', cpestr):
                logger.debug(f"cpestr: {cpestr}")
                r = requests.get(f'https://{_CVE_SEARCH_IP_ADDRESS}:{_CVE_SEARCH_PORT}/api/cvefor/' + cpestr, verify=False)
                if r.json() is not None:
                    if r.json() is dict:
                        cvejson[i].append(r.json())
                    else:
                        cvejson[i].append(r.json())

    for i in cpecve['cve']:

        if i not in cvejson:
            cvejson[i] = []

        for cvestr in cpecve['cve'][i]:
            r = requests.get(f'https://{_CVE_SEARCH_IP_ADDRESS}:{_CVE_SEARCH_PORT}/api/cve/' + cvestr, verify=False)
            if r.json() is not None:
                if r.json() is dict:
                    cvejson[i].append(r.json())
                else:
                    cvejson[i].append([r.json()])

    for i in cvejson:
        hostmd5 = hashlib.md5(str(i).encode('utf-8')).hexdigest()

        if type(cvejson[i]) is list and len(cvejson[i]) > 0:
            f = open(f'{_NOTES_DIRECTORY}/{scanfilemd5}_{hostmd5}.cve', 'w')
            f.write(json.dumps(cvejson[i], indent=4))
            f.close()
            logger.debug(f"Written file {_NOTES_DIRECTORY}/{scanfilemd5}_{hostmd5}.cve")


if _check_network_connection(_CVE_SEARCH_IP_ADDRESS, _CVE_SEARCH_PORT):
    getcve(sys.argv[1])
else:
    logger.error(f"There was an error finding CVE entries. No Network connection to local cve-search instance.")
    exit(-1)