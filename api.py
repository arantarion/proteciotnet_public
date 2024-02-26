import base64
import html
import logging
import os
import urllib.parse
import subprocess
import xmltodict
import json
import hashlib
import re
import requests
from django.http import HttpResponse
from django.shortcuts import render

from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.functions import *
from proteciotnet_dev.bruteforce_attacks.automatic_service_bruteforce import auto_bruteforce

logger = logging.getLogger(__name__)

try:
    config_api = ConfigParser(interpolation=ExtendedInterpolation())
    config_api.read('proteciotnet.config')

    _BASE_DIRECTORY = config_api.get('GENERAL_PATHS', 'BASE_DIRECTORY')
    _STATIC_DIRECTORY = config_api.get('GENERAL_PATHS', 'static_directory')
    _NOTES_DIRECTORY = config_api.get('GENERAL_PATHS', 'notes_directory')
    _WIFI_XML_BASE_DIRECTORY = config_api.get('WIFI_PATHS', 'wifi_xml_base_directory')
    _PROTECIOTNET_NMAP_DIRECTORY = config_api.get('WIFI_PATHS', 'proteciotnet_nmap_directory')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def rmNotes(request, hashstr: str) -> HttpResponse:
    """
    Removes notes associated with a specific hash string.

    Args:
        request (HttpRequest): The HTTP request object containing session information.
        hashstr (str): The hash string used to identify the notes file to be removed.

    Returns:
        HttpResponse: JSON response indicating the success or failure of removing the notes file.

    """

    scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
        if os.path.exists('/opt/notes/' + scanfilemd5 + '_' + hashstr + '.notes'):
            os.remove('/opt/notes/' + scanfilemd5 + '_' + hashstr + '.notes')
            res = {'ok': 'notes removed'}
            logger.debug("Successfully removed notes")
    else:
        res = {'error': 'invalid format'}
        logger.debug("Could not remove notes")

    return HttpResponse(json.dumps(res), content_type="application/json")


def saveNotes(request) -> HttpResponse:
    """
    Saves notes associated with a specific hash string.

    Args:
        request (HttpRequest): The HTTP request object containing session information and POST data.

    Returns:
        HttpResponse: JSON response indicating the success or failure of saving the notes.

    """

    if request.method == "POST":
        scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

        if re.match('^[a-f0-9]{32,32}$', request.POST['hashstr']) is not None:
            f = open(f"{_NOTES_DIRECTORY}/{scanfilemd5}_{request.POST['hashstr']}.notes", 'w')
            f.write(request.POST['notes'])
            f.close()
            res = {'ok': 'notes saved'}
            logger.debug(f"Successfully saved notes for {scanfilemd5}")
    else:
        logger.warning(f"Could not save note {request.POST['hashstr']}")
        res = {'error': request.method}

    return HttpResponse(json.dumps(res), content_type="application/json")


def rmlabel(request, objtype: str, hashstr: str) -> HttpResponse:
    """
    Remove a label file associated with a specific object type and hash string.

    Args:
        request: The HTTP request object.
        objtype (str): The type of object (e.g., 'host', 'port') associated with the label file.
        hashstr (str): The hash string used to identify the label file.

    Returns:
        HttpResponse: A JSON response indicating the result of the label removal operation.

    """

    types = {
        'host': True,
        'port': True
    }

    scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

    res = {'error': request.method}
    if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
        if os.path.exists(f"{_NOTES_DIRECTORY}/{scanfilemd5}_{hashstr}.{objtype}.label"):
            os.remove(f"{_NOTES_DIRECTORY}/{scanfilemd5}_{hashstr}.{objtype}.label")
            logger.info(f"Label {scanfilemd5}_{hashstr}.{objtype}.label successfully removed")
            res = {'ok': 'label removed'}
            return HttpResponse(json.dumps(res), content_type="application/json")

    logger.warning("No label to remove")
    return HttpResponse(json.dumps(res), content_type="application/json")


def label(request, objtype: str, label: str, hashstr: str) -> HttpResponse:
    """
    Set a label for a specific object type identified by a hash string.

    Args:
        request: The HTTP request object.
        objtype (str): The type of object (e.g., 'host', 'port') associated with the label.
        label (str): The label to be set for the object.
        hashstr (str): The hash string used to identify the object.

    Returns:
        HttpResponse: A JSON response indicating the result of the label setting operation.

    """

    labels = {
        'Vulnerable': True,
        'Critical': True,
        'Warning': True,
        'Checked': True
    }

    types = {
        'host': True,
        'port': True
    }

    scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    logger.debug(f"scanfilemd5: {scanfilemd5}")

    if label in labels and objtype in types:
        if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
            f = open(f"{_NOTES_DIRECTORY}/{scanfilemd5}_{hashstr}.{objtype}.label", 'w')
            f.write(label)
            f.close()
            logger.debug(f"Wrote label to file.")
            res = {'ok': 'label set', 'label': str(label)}
            return HttpResponse(json.dumps(res), content_type="application/json")


def port_details(request, address: str, portid: str) -> HttpResponse:
    """
    Get details of a specific port associated with an address.

    Args:
        request: The HTTP request object.
        address (str): The IP address associated with the port.
        portid (str): The port ID to retrieve details for.

    Returns:
        HttpResponse: A JSON response containing the details of the specified port.

    """
    r = {}

    oo = xmltodict.parse(open(f"{_WIFI_XML_BASE_DIRECTORY}/{request.session['scanfile']}", 'r').read())
    r['out'] = json.dumps(oo['nmaprun'], indent=4)
    o = json.loads(r['out'])

    logger.debug(f"Read file {request.session['scanfile']} at {_WIFI_XML_BASE_DIRECTORY}")

    for ik in o['host']:
        logger.debug(f"Looking up {ik}")
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        if '@addr' in i['address']:
            saddress = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    saddress = ai['@addr']

        if str(saddress) == address:
            for pobj in i['ports']['port']:
                if type(pobj) is dict:
                    p = pobj
                else:
                    p = i['ports']['port']

                if p['@portid'] == portid:
                    logger.debug("Found port details")
                    return HttpResponse(json.dumps(p, indent=4), content_type="application/json")

    logger.warning(f"Did not find port details for address {address}")


def getCVE(request) -> HttpResponse:
    """
    Retrieve CVE entries based on the scanfile associated with the request.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: A JSON response containing the CVE entries.


    """
    res = {}

    if request.method == "POST":
        scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
        logger.info("Trying to retrieve CVE entries")
        logger.debug(f"scanfilemd5 is: {scanfilemd5}")

        if "offline_mode.lock" in os.listdir(_STATIC_DIRECTORY):
            logger.info("Using offline mode to scan CVE entries")

            command = ['sudo', 'python3', f'{_PROTECIOTNET_NMAP_DIRECTORY}/cve_cdn.py',
                       request.session['scanfile']]

            logger.debug(f"Using command: {command}")

            cveproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = cveproc.communicate()

            logger.debug(f"stdout: {stdout}")
            logger.debug(f"stderr: {stderr}")

            exit_code = cveproc.returncode
            logger.debug(f"exit_code: {exit_code}")

            if exit_code == 0:
                logger.debug(f"Exited normally. Proceed.")
                res['cveout'] = stdout
            else:
                logger.error("Could not reach host")
                res = {'error': request.method}
                return HttpResponse(json.dumps(res), content_type="application/json")

            logger.info("Done with CVEs")
        else:
            logger.info("Using online mode to scan CVE entries")
            cveproc = os.popen(
                f'sudo python3 {_PROTECIOTNET_NMAP_DIRECTORY}/nmap/cve.py ' + request.session['scanfile'])
            res['cveout'] = cveproc.read()
            cveproc.close()

        return HttpResponse(json.dumps(res), content_type="application/json")


def apiv1_hostdetails(request, scanfile: str, faddress: str = "") -> HttpResponse:
    """
    Retrieve host details from an Nmap XML report.

    Args:
        request: The HTTP request object.
        scanfile (str): The filename of the Nmap XML report.
        faddress (str, optional): The IP address of the host to retrieve details for. Defaults to "".

    Returns:
        HttpResponse: A JSON response containing the host details.

    """
    oo = xmltodict.parse(open(f'{_WIFI_XML_BASE_DIRECTORY}/{scanfile}', 'r').read())
    out2 = json.dumps(oo['nmaprun'], indent=4)
    o = json.loads(out2)

    logger.debug(f"Loaded file {scanfile}")

    r = {'file': scanfile, 'hosts': {}}
    scanmd5 = hashlib.md5(str(scanfile).encode('utf-8')).hexdigest()

    logger.debug(f"Collect all labels from {_NOTES_DIRECTORY}")
    labelhost = {}
    labelfiles = os.listdir(_NOTES_DIRECTORY)
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open('/opt/notes/' + lf, 'r').read()

    logger.debug(f"Collect all notes from {_NOTES_DIRECTORY}")
    noteshost = {}
    notesfiles = os.listdir(_NOTES_DIRECTORY)
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()

    logger.debug(f"Collect all CVE from {_NOTES_DIRECTORY}")
    cvehost = get_cve(scanmd5)

    for ik in o['host']:

        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        hostname = {}
        if 'hostnames' in i and type(i['hostnames']) is dict:
            # hostname = json.dumps(i['hostnames'])
            if 'hostname' in i['hostnames']:
                # hostname += '<br>'
                if type(i['hostnames']['hostname']) is list:
                    for hi in i['hostnames']['hostname']:
                        hostname[hi['@type']] = hi['@name']
                else:
                    hostname[i['hostnames']['hostname']['@type']] = i['hostnames']['hostname']['@name'];

        if i['status']['@state'] == 'up':
            po, pc, pf = 0, 0, 0
            ss, pp, ost = {}, {}, {}
            lastportid = 0

            if '@addr' in i['address']:
                address = i['address']['@addr']
            elif type(i['address']) is list:
                for ai in i['address']:
                    if ai['@addrtype'] == 'ipv4':
                        address = ai['@addr']

            if faddress != "" and faddress != address:
                continue

            addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
            # cpe[address] = {}

            labelout = ''
            if scanmd5 in labelhost:
                if addressmd5 in labelhost[scanmd5]:
                    labelout = labelhost[scanmd5][addressmd5]

            notesout, notesb64, removenotes = '', '', ''
            if scanmd5 in noteshost:
                if addressmd5 in noteshost[scanmd5]:
                    notesb64 = noteshost[scanmd5][addressmd5]

            cveout = ''

            if scanmd5 in cvehost:
                if addressmd5 in cvehost[scanmd5]:
                    cveout = json.loads(cvehost[scanmd5][addressmd5])

            if faddress == "":
                r['hosts'][address] = {'hostname': hostname, 'label': labelout, 'notes': notesb64}
            else:
                r['hosts'][address] = {'ports': [], 'hostname': hostname, 'label': labelout, 'notes': notesb64,
                                       'CVE': cveout}

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

                    v, z, e = '', '', ''
                    pp[p['@portid']] = p['@portid']

                    servicename = ''
                    if 'service' in p:
                        ss[p['service']['@name']] = p['service']['@name']

                        if '@version' in p['service']:
                            v = p['service']['@version']

                        if '@product' in p['service']:
                            z = p['service']['@product']

                        if '@extrainfo' in p['service']:
                            e = p['service']['@extrainfo']

                        servicename = p['service']['@name']

                    if faddress != "":
                        r['hosts'][address]['ports'].append({
                            'port': p['@portid'],
                            'name': servicename,
                            'state': p['state']['@state'],
                            'protocol': p['@protocol'],
                            'reason': p['state']['@reason'],
                            'product': z,
                            'version': v,
                            'extrainfo': e
                        })

    logger.info("Collected all host details")
    logger.debug(f"return value: {r}")

    return HttpResponse(json.dumps(r, indent=4), content_type="application/json")


def apiv1_scan(request) -> HttpResponse:
    """
    Retrieve scan information for APIv1.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: A JSON response containing scan information.

    """

    logger.info(f"Using API to retrieve scan information")

    r = {}

    gitcmd = os.popen(f'cd {_BASE_DIRECTORY} && git rev-parse --abbrev-ref HEAD')
    r['proteciotnet_version'] = gitcmd.read().strip()

    logger.debug(f"Found Version: {r['proteciotnet_version']} ")

    xmlfiles = os.listdir(_WIFI_XML_BASE_DIRECTORY)

    r['scans'] = {}

    xmlfilescount = 0
    for i in xmlfiles:
        if re.search('\.xml$', i) is None:
            continue

        xmlfilescount = (xmlfilescount + 1)

        try:
            oo = xmltodict.parse(open(f'{_WIFI_XML_BASE_DIRECTORY}/{i}', 'r').read())
        except:
            r['scans'][i] = {'filename': html.escape(i), 'startstr': '', 'nhost': 0,
                             'port_stats': {'open': 0, 'closed': 0, 'filtered': 0}}
            continue

        rout = json.dumps(oo['nmaprun'], indent=4)
        o = json.loads(rout)

        if 'host' in o:
            if type(o['host']) is not dict:
                hostnum = str(len(o['host']))
            else:
                hostnum = '1'
        else:
            hostnum = '0'

        portstats = nmap_ports_stats(i)

        r['scans'][i] = {'filename': html.escape(i), 'startstr': html.escape(o['@startstr']), 'nhost': hostnum,
                         'port_stats': {'open': portstats['po'], 'closed': portstats['pc'],
                                        'filtered': portstats['pf']}}

    logger.info("Successfully used API to get scan results")
    logger.debug(f"result: {r}")

    return HttpResponse(json.dumps(r, indent=4), content_type="application/json")


def delete_file(request):
    """
    Delete a file from the ProtecIoTnet system via the API.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: A JSON response indicating the result of the deletion.

    """

    if request.method != "POST":
        logger.error("Please use a POST request for this function.")
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

    filename = request.POST['file_to_delete']

    logger.info(f"Trying to delete {filename}")

    xml_files = os.listdir(_WIFI_XML_BASE_DIRECTORY)
    if filename in xml_files:
        os.remove(f"{_WIFI_XML_BASE_DIRECTORY}/{filename}")
        logger.info(f"Successfully deleted {filename}")
        res = {'ok': f'file {filename} deleted'}
        return HttpResponse(json.dumps(res), content_type="application/json")

    logger.error(f"Could not find {filename} in {_WIFI_XML_BASE_DIRECTORY}")
    res = {'error': request.method}
    return HttpResponse(json.dumps(res), content_type="application/json")


def bruteforce(request):
    """
    Run a brute force attack via the API.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: A JSON response indicating the result of the brute force attack.

    """

    if request.method != "POST":
        logger.error("Please use a POST request for this function.")
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

    filename = request.POST['filename']
    specified_host = request.POST['specified_host']

    logger.info(f"Trying to bruteforce {specified_host} in {filename}")

    try:
        auto_bruteforce(filename, specified_host)
        logger.info("Successfully ran auto-bruteforcer script")
        res = {'ok': f'file {filename} deleted'}
        return HttpResponse(json.dumps(res), content_type="application/json")
    except Exception as e_bruteforce_api:
        logger.error(f"Could not run function to auto bruteforce. Exception: {str(e_bruteforce_api)}")

    res = {'error': request.method}
    return HttpResponse(json.dumps(res), content_type="application/json")
