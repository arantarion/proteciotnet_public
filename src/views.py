import base64
import logging
import os.path
import subprocess
# import logging
import colorlog
import urllib.parse
from collections import OrderedDict
from datetime import datetime

from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.view_zigbee import zigbee
from proteciotnet_dev.view_ble import bluetooth_low_energy, ble_details
from proteciotnet_dev.bluetooth_le.ble_perform_data_analysis import csv_to_json, create_rssi_graph
from proteciotnet_dev.api import label
from proteciotnet_dev.CVSS_Vectors import Cvss3vector, Cvss2Vector
from proteciotnet_dev.functions import *
from proteciotnet_dev.zigbee.analyse_json_zigbee_sniff import find_unique_devices, get_start_time

_MEDUSA_SUPPORTED_SERVICES = ['ssh', 'ftp', 'postgresql', 'telnet', 'mysql', 'ms-sql-s', 'rsh',
                              'vnc', 'imap', 'imaps', 'nntp', 'pcanywheredata', 'pop3', 'pop3s',
                              'exec', 'login', 'microsoft-ds', 'smtp', 'smtps', 'submission',
                              'svn', 'iss-realsecure', 'snmptrap', 'snmp', 'http']

# Global logging level
logging_level = logging.INFO
main_logger = logging.getLogger()
main_logger.setLevel(logging_level)

stream_handler = colorlog.StreamHandler()
stream_handler.setFormatter(
    colorlog.ColoredFormatter(
        "%(log_color)s%(name)s: %(asctime)s |\t%(levelname)s\t| %(filename)s:%(lineno)s | %(process)d >>> %(message)s"))
main_logger.addHandler(stream_handler)

try:
    config_views = ConfigParser(interpolation=ExtendedInterpolation())
    config_views.read('proteciotnet.config')

    _NOTES_DIRECTORY = config_views.get('GENERAL_PATHS', 'notes_directory')

    _WIFI_XML_BASE_DIRECTORY = config_views.get('WIFI_PATHS', 'wifi_xml_base_directory')

    _BLE_CSV_BASE_DIRECTORY = config_views.get('BLE_PATHS', 'ble_csv_base_directory')
    _BLE_REPORTS_DIRECTORY = config_views.get('BLE_PATHS', 'ble_reports_directory')

    _ZIGBEE_JSON_BASE_DIRECTORY = config_views.get('ZIGBEE_PATHS', 'zigbee_json_base_directory')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)


def user_login(request) -> HttpResponse:
    """
    Handle user login. This function is currently unused.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: A response indicating the success or failure of the login attempt.
    """
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('proteciotnet_dev/file_overview.html')  # Redirect to a 'home' page or desired URL
            else:
                return HttpResponse("Invalid username or password.")
        else:
            return HttpResponse("Invalid form.")
    else:
        form = AuthenticationForm()
        return render(request, 'proteciotnet_dev/login.html', {'form': form})
    # r = {}
    #
    # if request.method == "POST":
    #     return HttpResponse(json.dumps(r), content_type="application/json")
    #
    # return render(request, 'proteciotnet_dev/main.html', r)


def about(request):
    """
    Render the 'about' page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: Rendered 'about' page.
    """
    r = {}
    return render(request, 'proteciotnet_dev/about.html', r)


def setscanfile(request, scanfile: str):
    """
        Set the scan file and redirect to the corresponding overview page based on the file type.

        Args:
            request (HttpRequest): The HTTP request object.
            scanfile (str): The name of the scan file.

        Returns:
            HttpResponse: Rendered overview page or redirect script.
        """

    xmlfiles = os.listdir(_WIFI_XML_BASE_DIRECTORY)
    jsonfiles = os.listdir(_ZIGBEE_JSON_BASE_DIRECTORY)
    csvfiles = os.listdir(_BLE_CSV_BASE_DIRECTORY)

    logger.debug(f"successfully read xmlfiles location: {xmlfiles}\n"
                 f"successfully read jsonfiles location: {jsonfiles}\n"
                 f"successfully read csvfiles location: {csvfiles}")

    if scanfile == 'unset':
        logger.info("Unsetting the scanfile and returning to start page")
        if 'scanfile' in request.session:
            del (request.session['scanfile'])

        return render(request, 'proteciotnet_dev/ip_device_overview.html',
                      {'js': '<script> location.href="/"; </script>'})

    if ".xml" in scanfile:
        logger.debug(f"Looking for XML file: {scanfile}")
        for i in xmlfiles:
            if i == scanfile:
                request.session['scanfile'] = i
                logger.debug("XML file found")
                break
        logger.debug(f"File not found. Returning to main menu.")
        return render(request, 'proteciotnet_dev/ip_device_overview.html',
                      {'js': '<script> location.href="/"; </script>'})

    elif ".json" in scanfile:
        logger.debug(f"Looking for JSON file: {scanfile}")
        for i in jsonfiles:
            if i == scanfile:
                request.session['scanfile'] = i
                logger.debug("JSON file found")
                break

        if scanfile == 'unset':
            if 'scanfile' in request.session:
                logger.info("Unsetting the scanfile and returning to start page")
                del (request.session['scanfile'])

        r = zigbee(request)
        logger.debug(f"File not found. Returning to main menu.")
        return render(request, 'proteciotnet_dev/zigbee_device_overview.html', r)

    elif ".csv" in scanfile:
        logger.debug(f"Looking for CSV file: {scanfile}")
        for i in csvfiles:
            if i == scanfile:
                request.session['scanfile'] = i
                logger.debug("CSV file found")
                break

        if scanfile == 'unset':
            if 'scanfile' in request.session:
                logger.info("Unsetting the scanfile and returning to start page")
                del (request.session['scanfile'])

        r = bluetooth_low_energy(request)
        # r['js'] = '<script> location.href="/"; </script>'
        logger.debug(f"File not found. Returning to main menu.")
        return render(request, 'proteciotnet_dev/ble_device_overview.html', r)


def port(request, port: str):
    """
        Render the 'main' page with empty data. Used for testing.

        Args:
            request (HttpRequest): The HTTP request object.
            port (str): The port number.

        Returns:
            HttpResponse: Rendered 'main' page with empty data.
        """
    return render(request, 'proteciotnet_dev/main.html',
                  {'out': '', 'table': '', 'scaninfo': '', 'scandetails': '', 'trhost': ''})


def details(request, address: str, sorting: str = 'standard'):
    """
    View function to handle HTTP requests related to displaying details of a nmap scan results.
    This function extracts the necessary information from the chosen file and handels sorting and searching of CVE.


    Args:
        request: The HTTP request object.
        address (str): The IP address of the device or "report".
        sorting (str, optional): The sorting order for CVEs. Defaults to 'standard'.

    Returns:
        HttpResponse: The HTTP response object containing the rendered HTML page.
    """

    if address == "report":
        logger.debug("address equals 'report'. Fixing behavior...")
        address = sorting

    r = {'auth': True}

    if "about" in request.path:
        logger.info("Redirecting to 'about' page")
        return render(request, 'proteciotnet_dev/about.html', r)

    if "ble_report" in request.path:
        logger.info("Redirecting to 'BLE' page")
        r = ble_details(request=request)
        logger.info("Created information to be displayed on page successfully.")
        logger.debug(f"ble data to be displayed: {r}")
        return render(request, 'proteciotnet_dev/ble_device_details.html', r)

    if "login" in request.path:
        logger.info("Redirecting to 'login' page")
        form = AuthenticationForm()
        return render(request, 'proteciotnet_dev/login.html', {'form': form})

    logger.info("Creating Wi-Fi information from scan file...")

    oo = xmltodict.parse(open(f"{_WIFI_XML_BASE_DIRECTORY}/{request.session['scanfile']}", "r").read())
    # This is just to make it look better
    r['out2'] = json.dumps(oo['nmaprun'], indent=4)
    o = json.loads(r['out2'])

    logger.info(f"XML file successfully loaded: {request.session['scanfile']}")
    logger.debug(f"Loaded file content: {o}")

    r['trhost'] = ''
    pc, po, pf = 0, 0, 0

    scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

    logger.debug(f"scanmd5: {scanmd5}")
    logger.debug(f"addressmd5: {addressmd5}")

    logger.debug(f"Collecting labels from {_NOTES_DIRECTORY}")
    labelhost = {}
    labelfiles = os.listdir(_NOTES_DIRECTORY)
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open(f"{_NOTES_DIRECTORY}/{lf}", 'r').read()
    logger.debug(f"Collected all labels from {_NOTES_DIRECTORY}")

    logger.debug(f"Collecting notes from {_NOTES_DIRECTORY}")
    noteshost = {}
    notesfiles = os.listdir(_NOTES_DIRECTORY)
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()
    logger.debug(f"Collected all notes from {_NOTES_DIRECTORY}")

    logger.debug(f"Collecting CVE from {_NOTES_DIRECTORY}")
    cvehost = get_cve(scanmd5)
    logger.debug(f"Collected all CVE from {_NOTES_DIRECTORY}")

    r[
        'trhead'] = '<tr><th>Port</th><th style="width:300px;">Product / Version</th><th>Extra Info</th><th>&nbsp;</th></tr>'
    logger.debug(f"Populating information of each host in file: {request.session['scanfile']}")
    for ik in o['host']:
        pel = 0
        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        if 'ports' not in i:
            continue

        if '@addr' in i['address']:
            saddress = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    saddress = ai['@addr']

        if str(saddress) == address:
            hostname = ''
            if 'hostnames' in i and type(i['hostnames']) is dict:
                if 'hostname' in i['hostnames']:
                    hostname += '<br>'
                    if type(i['hostnames']['hostname']) is list:
                        for hi in i['hostnames']['hostname']:
                            hostname += '<span class="small grey-text"><b>' + hi['@type'] + ':</b> ' + hi[
                                '@name'] + '</span><br>'
                    else:
                        hostname += '<span class="small grey-text"><b>' + i['hostnames']['hostname'][
                            '@type'] + ':</b> ' + i['hostnames']['hostname']['@name'] + '</span><br>'

            r['address'] = html.escape(str(saddress))
            r['hostname'] = hostname

            scantitle = request.session['scanfile'].replace('.xml', '').replace('_', ' ')
            if re.search('^webmapsched\_[0-9\.]+', request.session['scanfile']):
                m = re.search('^webmapsched\_[0-9\.]+\_(.+)', request.session['scanfile'])
                scantitle = m.group(1).replace('.xml', '').replace('_', ' ')
            r['scanfile'] = scantitle

            labelout = '<span id="hostlabel"></span>'
            if scanmd5 in labelhost:
                if addressmd5 in labelhost[scanmd5]:
                    labelcolor = label_to_color(labelhost[scanmd5][addressmd5])
                    _ = label_to_margin(labelhost[scanmd5][addressmd5])
                    _ = '<span id="hostlabel" style="margin-left:60px;margin-top:-24px;" class="rightlabel ' \
                        + labelcolor + '">' + html.escape(labelhost[scanmd5][addressmd5]) + '</span>'

                    r['label'] = html.escape(labelhost[scanmd5][addressmd5])
                    r['labelcolor'] = labelcolor

            rmdupl = {}

            # OS info
            r['os'] = ""
            device_os_fingerprint = None

            if isinstance(i, dict) and i.get('os', ''):
                nmap_os_fingerprinting_dict = i.get('os', '').get('osmatch', '')
                device_os_fingerprint = dict.fromkeys(["OS", "Accuracy", "Vendor", "osfamily"])
                if nmap_os_fingerprinting_dict:

                    if isinstance(nmap_os_fingerprinting_dict, list):
                        nmap_os_fingerprinting_dict = nmap_os_fingerprinting_dict[0]

                    device_os_fingerprint["OS"] = nmap_os_fingerprinting_dict.get('@name', '')
                    device_os_fingerprint["Accuracy"] = nmap_os_fingerprinting_dict.get('@accuracy', '')

                    dev_class = nmap_os_fingerprinting_dict.get('osclass', '')

                    if dev_class:
                        if isinstance(dev_class, list):
                            dev_class = dev_class[0]

                        device_os_fingerprint["Vendor"] = dev_class.get('@vendor', '')

                    os_class = nmap_os_fingerprinting_dict.get('osclass', '')
                    if os_class:
                        if isinstance(os_class, list):
                            osfamilies = set()
                            for device_os_class in os_class:
                                osfamilies.add(device_os_class.get('@osfamily', ''))

                            osfamilies_cleaned = []
                            for item in list(osfamilies):
                                if "OS X" in item:
                                    continue
                                osfamilies_cleaned.append(item)

                            device_os_fingerprint["osfamily"] = osfamilies_cleaned
                        else:
                            device_os_fingerprint["osfamily"] = os_class.get('@osfamily', '')

            if device_os_fingerprint:
                device_os = device_os_fingerprint['OS']

                oshtml = '<div style="font-family:monospace;padding:6px;margin:6px;border-left:solid #666 1px;font-size:75%;">'

                oshtml += '<u><b>Operating System</b></u>'
                if "Android" in device_os:
                    oshtml += ' <i class="fab fa-android" style="font-size: 15px;"></i><br>'
                elif "Linux" in device_os:
                    oshtml += ' <i class="fab fa-linux" style="font-size: 15px;"></i><br>'
                elif "Windows" in device_os:
                    oshtml += ' <i class="fab fa-linux" style="font-size: 15px;"></i><br>'
                elif "iOS" in device_os or "Mac OS" in device_os:
                    oshtml += ' <i class="fab fa-linux" style="font-size: 15px;"></i><br>'
                else:
                    oshtml += ' <br>'

                oshtml += html.escape(device_os)
                oshtml += '<table cellspacing="0" cellpadding="0" style="border-collapse: collapse; margin: 0; padding: 0; border:0!;">'

                vendor = device_os_fingerprint.get("Vendor", "")
                if vendor:
                    oshtml += '<tr style="border: none;"><td style="padding: 0; margin: 0; border: none;">Vendor</td><td style="padding: 0; margin: 0; border: none;">' + html.escape(
                        vendor) + '</td></tr>'

                os_family = device_os_fingerprint.get("osfamily", "")

                if os_family and isinstance(os_family, list):
                    oshtml += '<tr style="border: none;"><td style="padding: 0; margin: 0; border: none;">OS Family</td><td style="padding: 0; margin: 0; border: none;">' + html.escape(
                        ', '.join(sorted(os_family))) + '</td></tr>'
                elif os_family:
                    oshtml += '<tr style="border: none;"><td style="padding: 0; margin: 0; border: none;">OS Family</td><td style="padding: 0; margin: 0; border: none;">' + html.escape(
                        os_family) + '</td></tr>'

                accuracy = device_os_fingerprint.get("Accuracy", "")
                if accuracy:
                    oshtml += '<tr style="border: none;"><td style="padding: 0; margin: 0; border: none;">Accuracy</td><td style="padding: 0; margin: 0; border: none;">' + html.escape(
                        accuracy) + '%</td></tr>'

                oshtml += '</table>'

                oshtml += '</div>'
                r['os'] = oshtml

            r['tr'] = {}
            for pobj in i['ports']['port']:
                if type(pobj) is dict:
                    p = pobj
                else:
                    p = i['ports']['port']

                if p['@portid'] in rmdupl:
                    continue

                rmdupl[p['@portid']] = 1

                if p['state']['@state'] == 'closed':
                    pc = (pc + 1)
                elif p['state']['@state'] == 'open':
                    po = (po + 1)
                elif p['state']['@state'] == 'filtered':
                    pf = (pf + 1)

                pel = (pel + 1)

                so = ''
                if 'script' in p:
                    if '@id' in p['script']:
                        if p['script']['@id'] != 'fingerprint-strings':
                            so += '<div style="word-wrap: break-word;word-break: break-all;padding:6px;margin-left:6px;border-left:solid #666 1px;max-width:300px;font-size:12px;color:#ccc;font-family:monospace;"><sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>' + html.escape(
                                p['script']['@id']) + '</b> ' + html.escape(p['script']['@output']) + '</div>'
                    else:
                        for sosc in p['script']:
                            if '@id' in sosc:
                                if sosc['@id'] != 'fingerprint-strings':
                                    so += '<div style="word-wrap: break-word;word-break: break-all;padding:6px;margin:6px;border-left:solid #666 1px;max-width:300px;font-size:12px;color:#ccc;font-family:monospace;"><sup style="color:#999;border-bottom:solid #999 1px;">script output</sup><br><b>' + html.escape(
                                        sosc['@id']) + '</b> ' + html.escape(sosc['@output']) + '</div>'

                v, z, e = '', '', '<i class="grey-text">N/A</i>'
                if p['state']['@state'] == 'open':
                    if 'service' in p:
                        if '@version' in p['service']:
                            v = p['service']['@version']
                        else:
                            v = '<i class="grey-text">No Version</i>'

                        if '@product' in p['service']:
                            z = p['service']['@product']
                        else:
                            z = '<i class="grey-text">No Product</i>'

                        if '@extrainfo' in p['service']:
                            e = p['service']['@extrainfo']

                        cpe = ''
                        if 'cpe' in p['service']:
                            if type(p['service']['cpe']) is list:
                                for cpei in p['service']['cpe']:
                                    cpe += '<div class="grey-text" style="font-family:monospace;font-size:12px;">' + html.escape(
                                        cpei) + '</div>'
                            else:
                                cpe = '<div class="grey-text" style="font-family:monospace;font-size:12px;">' + html.escape(
                                    p['service']['cpe']) + '</div>'

                        servicename = p['service']['@name']
                    else:
                        servicename = ''

                    r['tr'][p['@portid']] = {
                        'service': servicename,
                        'protocol': p['@protocol'],
                        'portid': p['@portid'],
                        'product': z,
                        'version': v,
                        'cpe': cpe,
                        'state': p['state']['@state'],
                        'reason': p['state']['@reason'],
                        'extrainfo': e,
                        'pel': str(pel)
                    }

                    r['trhost'] += '<tr><td style="vertical-align:top;">' + \
                                   '<span style="color:#999;font-size:12px;">' + servicename + '</span><br>' + \
                                   '<span class="new badge blue" data-badge-caption="">' + p['@protocol'] + ' / ' + p[
                                       '@portid'] + '</span>' + \
                                   '</td>' + \
                                   '<td>' + z + ' / ' + v + '<br><span style="font-size:12px;color:#999;">State: ' + \
                                   p['state']['@state'] + '<br>Reason: ' + p['state']['@reason'] + '</span></td>' + \
                                   '<td style="vertical-align:top">' + e + '<br>' + cpe + '</td>' + \
                                   '<td><ul id="dropdown' + str(
                        pel) + '" class="dropdown-content" style="min-width:300px;">' + \
                                   '	<li><a href="#!" class="btncpy" data-clipboard-text="curl -v -A \'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1\' -k \'http://' + html.escape(
                        address) + ':' + html.escape(p['@portid']) + '\'">Copy as curl command</a></li>' + \
                                   '	<li><a href="#!" class="btncpy" data-clipboard-text="nikto -host \'http://' + html.escape(
                        address) + ':' + html.escape(p['@portid']) + '\'">Copy as nikto command</a></li>' + \
                                   '	<li><a href="#!" class="btncpy" data-clipboard-text="telnet ' + html.escape(
                        address) + ' ' + html.escape(p['@portid']) + '">Copy as telnet command</a></li>' + \
                                   '</ul><a class="dropdown-trigger btn blue right" href="#!" data-target="dropdown' + str(
                        pel) + '"><i class="material-icons">arrow_drop_down</i></a> ' + \
                                   '<button onclick="javascript:apiPortDetails(\'' + html.escape(
                        address) + '\',\'' + html.escape(p[
                                                             '@portid']) + '\');" class="btn blue right"><i class="material-icons">receipt</i></button></td>' + \
                                   '</tr>'
                elif p['state']['@state'] == 'filtered':
                    if 'service' in p:
                        servicename = p['service']['@name']
                    else:
                        servicename = ''

                    r['tr'][p['@portid']] = {
                        'service': servicename,
                        'protocol': p['@protocol'],
                        'portid': p['@portid'],
                        'state': p['state']['@state'],
                        'reason': p['state']['@reason'],
                        'pel': str(pel)
                    }
                    r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">' + p[
                        '@protocol'] + ' / ' + p['@portid'] + '</span><br>' + \
                                   '<span style="color:#999;font-size:12px;">' + servicename + '</span></td>' + \
                                   '<td colspan="2" style="color:#999;font-size:12px;">State: filtered<br>Reason: ' + \
                                   p['state']['@reason'] + '</td>' + \
                                   '<td><button onclick="javascript:apiPortDetails(\'' + html.escape(
                        address) + '\',\'' + html.escape(p[
                                                             '@portid']) + '\');" class="btn blue right"><i class="material-icons">receipt</i></button></td></tr>'
                else:
                    if 'service' in p:
                        servicename = p['service']['@name']
                    else:
                        servicename = ''

                    r['tr'][p['@portid']] = {
                        'service': servicename,
                        'protocol': p['@protocol'],
                        'portid': p['@portid'],
                        'state': p['state']['@state'],
                        'reason': p['state']['@reason'],
                        'pel': str(pel)
                    }
                    r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">' + p[
                        '@protocol'] + ' / ' + p['@portid'] + '</span><br>' + \
                                   '<span style="color:#999;font-size:12px;">' + servicename + '</span></td>' + \
                                   '<td colspan="2" style="color:#999;font-size:12px;">State: ' + p['state'][
                                       '@state'] + '<br>Reason: ' + p['state']['@reason'] + '</td>' + \
                                   '<td><button onclick="javascript:apiPortDetails(\'' + html.escape(
                        address) + '\',\'' + html.escape(p[
                                                             '@portid']) + '\');" class="btn blue right"><i class="material-icons">receipt</i></button></td></tr>'

        # this fix single host report
        if type(ik) is not dict:
            break

    logger.debug(f"Preparing notes for {request.session['scanfile']}")
    r['table'] = ''
    if scanmd5 in noteshost:
        if addressmd5 in noteshost[scanmd5]:
            notesb64 = noteshost[scanmd5][addressmd5]
            r['table'] += '<div class="card" style="background-color:#3e3e3e;">' + \
                          '	<div class="card-content"><h5>Notes</h5>' + \
                          '		' + base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii') + \
                          '	</div>' + \
                          '</div>'
            r['notes'] = base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')

    logger.debug(f"Preparing CVE for {request.session['scanfile']}")
    cveout = ''
    if scanmd5 in cvehost:
        if addressmd5 in cvehost[scanmd5]:
            logger.info(f"Found CVE entries for {scanmd5}: {addressmd5}")
            cvejson = json.loads(cvehost[scanmd5][addressmd5])
            cveids = {}

            for i in cvejson:
                if type(i) is list:
                    listcve = i
                elif type(i) is dict:
                    listcve = [i]

                for cveobj in listcve:
                    try:
                        if 'message' in cveobj.keys():
                            if cveobj['message'] == 'No cves found':
                                continue
                    except KeyError:
                        continue

                    cverefout = ''
                    for cveref in cveobj['references']:
                        cverefout += '<a href="' + cveref + '">' + cveref + '</a><br>'

                    cveexdbout = ''
                    if 'exploit-db' in cveobj:
                        cveexdbout = '<br><div class="small" style="line-height:20px;"><b>Exploit DB:</b><br>'
                        for cveexdb in cveobj['exploit-db']:
                            if 'title' in cveexdb:
                                cveexdbout += '<a href="' + cveexdb['source'] + '">' + html.escape(
                                    cveexdb['title']) + '</a><br>'
                        cveexdbout += '</div>'

                    cvss_score = cveobj.get('cvss', '')
                    cvss3_score = cveobj.get('cvss3', '')
                    cvss3_vector = cveobj.get('cvss3-vector', '')

                    if cvss3_score:
                        label3_color, font3_color = get_cvss_color(cvss3_score, 3)

                    label_color, font_color = get_cvss_color(cvss_score, 2)

                    if "Other" not in cveobj["cwe"] and "noinfo" not in cveobj["cwe"]:
                        cwe_tooltip = f'<div class="tt2" style="color:white"><a href="https://cwe.mitre.org/data/definitions/{cveobj["cwe"][4:]}.html" target="_BLANK" style="color:white">{cveobj["cwe"]}</a><span class="ttt2">{get_cwe_description(cveobj["cwe"])}</span></div>'
                    else:
                        cwe_tooltip = f'<div class="tt2" style="color:white">{cveobj["cwe"]}<span class="ttt2">{get_cwe_description(cveobj["cwe"])}</span></div>'

                    cwe_string = f'<span class="label grey">' + cwe_tooltip + '</span>'

                    cvss_vector = cveobj.get('cvss-vector')
                    if cvss_vector:
                        cvss_vec_obj = Cvss2Vector(cvss_vector)
                        cvss_vector_html = f'<div class="tooltip" style="color:white">{html.escape(cvss_vector)}<span class="tooltiptext">{cvss_vec_obj.__str__()}</span></div>'

                    if cvss3_vector:
                        cvss3_vec_obj = Cvss3vector(cvss3_vector)
                        cvss3_vector_html = f'<div class="tooltip" style="color:white">{html.escape(cvss3_vector)}<span class="tooltiptext">{cvss3_vec_obj.__str__()}</span></div>'

                    cveout += f'<div id="' + html.escape(cveobj[
                                                             'id']) + '" style="line-height:28px;padding:10px;border-bottom:solid #666 1px;margin-top:10px;">'
                    cveout += f'<a href=https://nvd.nist.gov/vuln/detail/{html.escape(cveobj["id"])} style="color:white" target="_BLANK"> <span class="label blue" style="box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);">' + html.escape(
                        cveobj['id']) + '</span></a> '

                    if cvss_score:
                        cveout += '&nbsp; - &nbsp;'
                        cveout += f'<span class="label {label_color}" style="color:{font_color}">' + html.escape(
                            f"CVSS 2.0 score: {str(cvss_score)}") + '</span> '
                        cveout += f'<span class="label grey">' + cvss_vector_html + '</span>' + " "
                    else:
                        cveout += '&nbsp; - &nbsp;'
                        cveout += f'<span class="label grey" style="color:white;">' + html.escape(
                            f"CVSS 2.0 score: N/A") + '</span> '
                        cveout += f'<span class="label grey">' + "AV:-/AC:-/Au:-/C:-/I:-/A:-" + '</span>' + " "

                    if cvss3_score and cvss3_vector:
                        cveout += '&nbsp; - &nbsp;'
                        cveout += f'<span class="label {label3_color}" style="color:{font3_color}">' + html.escape(
                            f"CVSS {cvss3_vec_obj.version} score: {str(cvss3_score)}") + '</span> '
                        cveout += f'<span class="label grey">' + cvss3_vector_html + '</span>' + " "
                        cveout += '&nbsp; - &nbsp;'
                    else:
                        cveout += '&nbsp; - &nbsp;'
                        cveout += f'<span class="label grey" style="color: white;">' + html.escape(
                            f"CVSS 3.x score: N/A") + '</span> '
                        cveout += f'<span class="label grey">' + "CVSS:3.x/AV:-/AC:-/PR:-/UI:-/S:-/C:-/I:-/A:-" + '</span>' + " "
                        cveout += '&nbsp; - &nbsp;'

                    cveout += cwe_string
                    cveout += '<br><br>'
                    cveout += html.escape(cveobj['summary'])
                    cveout += '<br><br>'
                    cveout += f'<div class="small" style="line-height:20px;"><b>References:</b><br>' + cverefout + '</div>' + cveexdbout + '</div>'

                    cveids[cveobj['id']] = cveobj['id']

            if sorting != "standard" and not sorting.startswith("search="):
                logger.debug(f"Items have to be sorted. Order: {sorting}")
                cveout = sort_cve_html(cveout, sorting)

            elif sorting.startswith("search="):
                logger.debug(f"Searching for: {sorting}")
                cveout = search_cve_html(cveout, sorting)

            r['cveids'] = cveids
            r['cvelist'] = cveout

    r['js'] = '<script> ' + \
              '$(document).ready(function() { ' + \
              '	$("#scantitle").html("' + html.escape(request.session['scanfile']) + '");' + \
              '	var clipboard = new ClipboardJS(".btncpy"); ' + \
              '	clipboard.on("success", function(e) { ' + \
              '		M.toast({html: "Copied to clipboard"}); ' + \
              '	}); ' + \
              '	$(".dropdown-trigger").dropdown(); ' + \
              '	$("#detailspo").html(\'<center><h4><i class="fas fa-lock-open green-text"></i> ' + str(
        po) + '</h4><span class="small grey-text">OPEN PORTS</span></center>\');' + \
              '	$("#detailspc").html(\'<center><h4><i class="fas fa-lock red-text"></i> ' + str(
        pc) + '</h4><span class="small grey-text">CLOSED PORTS</span></center>\');' + \
              '	$("#detailspf").html(\'<center><h4><i class="fas fa-filter grey-text"></i> ' + str(
        pf) + '</h4><span class="small grey-text">FILTERED PORTS</span></center>\');' + \
              '}); ' + \
              '</script>'

    logger.info(f"Device details for {request.session['scanfile']} prepared successfully. Now showing page.")
    logger.debug(f"Device details to be rendered: {r}")

    return render(request, 'proteciotnet_dev/ip_device_details.html', r)


def index(request, filterservice: str = "", filterportid: str = ""):
    """
    View function to handle HTTP requests related to displaying the start page.
    This function extracts the necessary information from the chosen files to display it on the start page.


    Args:
        request: The HTTP request object.
        filterservice (str, optional): Filter for certain services.
        filterportid (str, optional): Filter for certain ports.

    Returns:
        HttpResponse: The HTTP response object containing the information to be rendered.
    """

    r = {'auth': True}
    bruteforce_available_in_file = False

    proteciotnet_version = subprocess.check_output(
        'cd /opt/proteciotnet/proteciotnet_dev && git describe --long --abbrev=10 --tag',
        shell=True, text=True).strip()
    r['webmapver'] = proteciotnet_version
    logger.debug(f"generated version information: {proteciotnet_version}")

    if 'scanfile' in request.session and "json" not in request.session['scanfile']:
        logger.debug("Redirecting to nmap scan results view. instead of start page...")
        oo = xmltodict.parse(open(f"{_WIFI_XML_BASE_DIRECTORY}/{request.session['scanfile']}", 'r').read())
        r['out2'] = json.dumps(oo['nmaprun'], indent=4)
        o = json.loads(r['out2'])
    else:
        logger.debug("No file has been selected. Generating information for start page...")
        xmlfiles = os.listdir(_WIFI_XML_BASE_DIRECTORY)
        jsonfiles = os.listdir(_ZIGBEE_JSON_BASE_DIRECTORY)
        csvfiles = os.listdir(_BLE_CSV_BASE_DIRECTORY)

        r['tr'] = {}
        r['zigbee_files'] = OrderedDict()
        r['ble_files'] = OrderedDict()
        r['stats'] = {'po': 0, 'pc': 0, 'pf': 0}

        ble_files_count = 0
        for csv_file in csvfiles:
            logger.debug("Generating information for BLE files...")
            if re.search('\.csv$', csv_file) is None:
                continue

            json_filepath = f'{_BLE_REPORTS_DIRECTORY}/{csv_file.replace(".csv", ".json")}'
            svg_filepath = f'{_BLE_REPORTS_DIRECTORY}/{csv_file.replace(".csv", ".svg")}'
            ble_scan_results = ""

            if not os.path.isfile(json_filepath):
                logger.debug(f"CSV file {csv_file} has no matching JSON file. It has to be created...")
                try:
                    ble_scan_results, rssi_values = csv_to_json(csv_file_path=f"{_BLE_CSV_BASE_DIRECTORY}/{csv_file}",
                                                                json_file_path=json_filepath)
                except Exception as e:
                    logger.error(f"Could not create JSON file for {csv_file} - {e}")
                    continue
                logger.debug(f"Successfully created JSON file from CSV file {csv_file}")

            elif not os.path.isfile(svg_filepath):
                logger.debug(f"CSV file {csv_file} has no matching SVG file. It has to be created...")

                if ble_scan_results:
                    try:
                        logger.debug("Trying to create RSSI graph...")
                        create_rssi_graph(csv_file_path=f"{_BLE_CSV_BASE_DIRECTORY}/{csv_file}",
                                          ble_scan_results=ble_scan_results,
                                          output_path=svg_filepath)
                        logger.debug("Successfully created RSSI graph.")
                    except Exception as e:
                        logger.error(f"Could not create SVG file for {csv_file} - {e}")
                        continue
                    logger.debug(f"Successfully created SVG file from CSV file {csv_file}")
                else:
                    logger.error(f"Can't create SVG graph because ble_scan_results are missing")


            else:
                logger.debug(f"Found CSV file {csv_file}. Json path is {json_filepath}")

            try:
                with open(f'{json_filepath}', "r", encoding='utf-8') as f:
                    json_input = json.load(f)

                logger.debug(f"Successfully read json file {csv_file}")

            except Exception:
                r['ble_files'][csv_file] = r['ble_files'][csv_file] = {
                    'bl_filename': html.escape(csv_file),
                    'bl_startstr': 0,
                    'bl_nr_devices': 0,
                    'bl_nr_conn_devices': 0,
                    'bl_href': '#!',
                    'bl_interface': 'invalid'
                }
                logger.debug(f"Could not read json file for {csv_file}")
                logger.debug(f"Using {r['ble_files']}")
                continue

            ble_files_count += 1
            ble_info_header = json_input[0]

            logger.debug(f"Increased file count and extracted info header from {csv_file}")

            if ble_info_header['ble_nr_devices'] != 0:
                view_href = '/setscanfile/' + html.escape(csv_file)
                logger.debug(f"Found at least one device in {csv_file}")
            else:
                view_href = '#!'
                logger.debug(f"Found no device in {csv_file}")

            r['ble_files'][csv_file] = {
                'bl_filename': html.escape(csv_file),
                'bl_startstr': html.escape(ble_info_header['ble_scan_start_time']),
                'bl_nr_devices': ble_info_header['ble_nr_devices'],
                'bl_nr_conn_devices': ble_info_header['ble_connectable_devices'],
                'bl_href': view_href,
            }

            logger.debug(f"Parsed all BLE files. Created: {r['ble_files']}")

        zigbee_files_count = 0
        logger.debug("Generating information for ZigBee files...")
        for j in jsonfiles:
            if re.search('\.json$', j) is None:
                continue

            try:
                with open(f'{_ZIGBEE_JSON_BASE_DIRECTORY}/{j}', "r", encoding='utf-8') as f:
                    json_input = json.load(f)
                logger.debug(f"Successfully loaded {j}")

            except Exception:
                logger.warning(f"Could not load {f}. Using empty values instead.")
                r['zigbee_files'][j] = {'filename': html.escape(j), 'start': 0, 'startstr': 'Incomplete / Invalid',
                                        'hostnum': 0,
                                        'zb_href': '#!', 'channel': 'None'}
                continue

            if "scan_info" not in json_input[0]:
                continue

            zigbee_files_count += 1
            _, zigbee_host_number = find_unique_devices(json_input)

            if zigbee_host_number != '0':
                view_href = '/setscanfile/' + html.escape(j)
            else:
                view_href = '#!'

            zigbee_channel = json_input[0]['sniffing_channel']

            zigbee_ctime = get_start_time(json_input)

            r['zigbee_files'][j] = {
                'zb_filename': html.escape(j),
                'zb_startstr': html.escape(zigbee_ctime),
                'zb_hostnum': zigbee_host_number,
                'zb_href': view_href,
                'zb_channel': zigbee_channel
            }

        logger.debug(f"Parsed all ZigBee files. {r['zigbee_files']}")

        # XML FILE
        xmlfilescount = 0
        logger.debug("Generating information for Wi-Fi files...")
        for i in xmlfiles:
            if re.search('\.xml$', i) is None:
                continue

            # portstats = {}
            xmlfilescount = (xmlfilescount + 1)

            try:
                oo = xmltodict.parse(open(f"{_WIFI_XML_BASE_DIRECTORY}/{i}", 'r').read())
                logger.debug(f"Successfully parsed {i}")
            except Exception as e:
                logger.warning(f"Could not parse {i}. Using empty values. Error {e}")
                r['tr'][i] = {'filename': html.escape(i), 'start': 0, 'startstr': 'Incomplete / Invalid', 'hostnum': 0,
                              'href': '#!', 'portstats': {'po': 0, 'pc': 0, 'pf': 0}}
                continue

            r['out2'] = json.dumps(oo['nmaprun'], indent=4)
            o = json.loads(r['out2'])

            if 'host' in o:
                if type(o['host']) is not dict:
                    hostnum = str(len(o['host']))
                else:
                    hostnum = '1'
            else:
                hostnum = '0'

            if hostnum != '0':
                view_href = '/setscanfile/' + html.escape(i)
            else:
                view_href = '#!'

            filename = i
            if re.search('^webmapsched\_[0-9\.]+', i):
                m = re.search('^webmapsched\_([0-9\.]+)\_(.+)', i)
                filename = '<i class="fas fa-calendar-alt grey-text"></i> ' + html.escape(m.group(2))

            portstats = nmap_ports_stats(i)

            r['stats']['po'] = (r['stats']['po'] + portstats['po'])
            r['stats']['pc'] = (r['stats']['pc'] + portstats['pc'])
            r['stats']['pf'] = (r['stats']['pf'] + portstats['pf'])

            r['tr'][o['@start']] = {
                'filename': filename,
                'start': o['@start'],
                'startstr': html.escape(datetime.fromtimestamp(int(o['@start'])).strftime('%A, %d. %B %Y - %H:%M:%S')),
                # html.escape(o['@startstr']),
                'hostnum': hostnum,
                'href': view_href,
                'portstats': portstats
            }

        logger.debug(f"All files scanned. Sorting results now.")
        r['tr'] = OrderedDict(sorted(r['tr'].items(), reverse=True))
        r['zigbee_files'] = OrderedDict(sorted(r['zigbee_files'].items(), reverse=True))
        r['ble_files'] = OrderedDict(sorted(r['ble_files'].items(), reverse=True))
        r['stats']['xmlcount'] = xmlfilescount
        r['stats']['zigbee_files_count'] = zigbee_files_count
        r['stats']['ble_files_count'] = ble_files_count

        logger.info("All information successfully created to display start page.")
        logger.debug(f"Return value: {r}")

        return render(request, 'proteciotnet_dev/file_overview.html', r)

    scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
    r['scanfile'] = html.escape(str(request.session['scanfile']))
    r['scanmd5'] = scanmd5

    # collect all labels in labelhost dict
    labelhost = {}
    labelfiles = os.listdir('/opt/notes')
    for lf in labelfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.host\.label$', lf)
        if m is not None:
            if m.group(1) not in labelhost:
                labelhost[m.group(1)] = {}
            labelhost[m.group(1)][m.group(2)] = open('/opt/notes/' + lf, 'r').read()

    # collect all notes in noteshost dict
    noteshost = {}
    notesfiles = os.listdir('/opt/notes')
    for nf in notesfiles:
        m = re.match('^(' + scanmd5 + ')_([a-z0-9]{32,32})\.notes$', nf)
        if m is not None:
            if m.group(1) not in noteshost:
                noteshost[m.group(1)] = {}
            noteshost[m.group(1)][m.group(2)] = open('/opt/notes/' + nf, 'r').read()

    # collect all cve in cvehost dict
    cvehost = get_cve(scanmd5)

    hostsup = 0
    hostindex = 1
    ports = {'open': 0, 'closed': 0, 'filtered': 0}
    allostypelist, sscount, picount, cpe = {}, {}, {}, {}

    r['tr'] = {}
    r['stats'] = {}

    for ik in o['host']:

        # this fix single host report
        if type(ik) is dict:
            i = ik
        else:
            i = o['host']

        hostname = ''
        info_hostnames = '<sup style="font-size: 70%; position: relative; top: 0.2em; left: -0.3em;"> <span class="material-icons" style="font-size: inherit;">question_mark</span></sup>'
        if 'hostnames' in i and type(i['hostnames']) is dict:
            if 'hostname' in i['hostnames']:
                if type(i['hostnames']['hostname']) is list:
                    for hi in i['hostnames']['hostname']:
                        hostname += '<div class="small grey-text"><b><span title="DNS pointer record">' + hi[
                            '@type'] + info_hostnames + '&#8594; </span></b> ' + hi['@name'] + '</div>'
                else:
                    hostname += '<div class="small grey-text"><b><span title="DNS pointer record">' + \
                                i['hostnames']['hostname']['@type'] + info_hostnames + '&#8594; </span></b>' + \
                                i['hostnames']['hostname']['@name'] + '</div>'

        po, pc, pf = 0, 0, 0
        ss, pp, ost = {}, {}, {}
        lastportid = 0

        if '@addr' in i['address']:
            address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'ipv4':
                    address = ai['@addr']

        vendor = ""
        mac_address = ""
        if '@vendor' in i['address']:
            try:
                vendor = i['address']['@vendor']
            except KeyError:
                pass
            mac_address = i['address']['@addr']
        elif type(i['address']) is list:
            for ai in i['address']:
                if ai['@addrtype'] == 'mac':
                    try:
                        vendor = ai['@vendor']
                    except KeyError:
                        pass
                    mac_address = ai['@addr']

        if vendor == "" and mac_address == "":
            vendor = 'unknown'

        if vendor == "":
            vendor = f'<a href="https://maclookup.app/search/result?mac={urllib.parse.quote(mac_address)}" style="color: #9e9e9e; text-decoration: none;">{mac_address}<sup style="font-size: 70%; position: relative; top: -0.9em;"><span class="material-icons" style="font-size: 12px; vertical-align: middle;">question_mark</span></sup></a>'

        addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

        if i['status']['@state'] == 'up':
            if address not in cpe:
                hostsup = (hostsup + 1)

                r['tr'][address] = {
                    'hostindex': '',
                    'hostname': hostname,
                    'po': 0,
                    'pc': 0,
                    'pf': 0,
                    'totports': str(0),
                    'addressmd5': addressmd5
                }

        cpe[address] = {}

        striggered = False
        e = ''
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
                    if filterservice != "" and p['service']['@name'] == filterservice:
                        striggered = True

                    if filterportid != "" and p['@portid'] == filterportid:
                        striggered = True

                pp[p['@portid']] = p['@portid']

                if 'service' in p:
                    ss[p['service']['@name']] = p['service']['@name']

                    if '@extrainfo' in p['service']:
                        e = p['service']['@extrainfo']

                    # cpehtml = ''
                    if 'cpe' in p['service']:
                        if type(p['service']['cpe']) is list:
                            for cpei in p['service']['cpe']:
                                cpe[address][cpei] = cpei
                        else:
                            cpe[address][p['service']['cpe']] = p['service']['cpe']

                    if '@ostype' in p['service']:
                        if p['service']['@ostype'] in allostypelist:
                            allostypelist[p['service']['@ostype']] = (allostypelist[p['service']['@ostype']] + 1)
                        else:
                            allostypelist[p['service']['@ostype']] = 1;

                        ost[p['service']['@ostype']] = p['service']['@ostype']

                    if p['service']['@name'] in sscount:
                        sscount[p['service']['@name']] = (sscount[p['service']['@name']] + 1)
                    else:
                        sscount[p['service']['@name']] = 1

                if p['@portid'] in picount:
                    picount[p['@portid']] = (picount[p['@portid']] + 1)
                else:
                    picount[p['@portid']] = 1

                if p['state']['@state'] == 'closed':
                    ports['closed'] = (ports['closed'] + 1)
                    pc = (pc + 1)
                elif p['state']['@state'] == 'open':
                    ports['open'] = (ports['open'] + 1)
                    po = (po + 1)
                elif p['state']['@state'] == 'filtered':
                    ports['filtered'] = (ports['filtered'] + 1)
                    pf = (pf + 1)

            services = ''
            service_counter = 0
            for s in ss:
                if filterservice != ss[s]:
                    services += f'<a href="/report/service/{ss[s]}/">{ss[s]}</a>, '
                else:
                    services += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">' + ss[
                        s] + '</span>, '
                service_counter += 1

            ostype = ''
            for oty in ost:
                ostype += '<i class="' + from_os_type_to_font_awesome(
                    html.escape(ost[oty])) + '"></i> <span class="grey-text small">' + ost[oty].lower() + '</span> '

            tdports = ''
            for kp in pp:
                if filterportid != pp[kp]:
                    tdports += '<a href="/report/portid/' + pp[kp] + '/">' + pp[kp] + '</a>, '
                else:
                    tdports += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">' + pp[
                        kp] + '</span>, '

            poclass = ''
            if po == 0:
                poclass = 'zeroportopen'

            labelout = '<span id="hostlabel' + str(hostindex) + '"></span>'
            newlabelout = '<div id="hostlabel' + str(hostindex) + '"></div><div id="hostlabelbb' + str(
                hostindex) + '"></div>'
            if scanmd5 in labelhost:
                if addressmd5 in labelhost[scanmd5]:
                    labelcolor = label_to_color(labelhost[scanmd5][addressmd5])
                    labelmargin = label_to_margin(labelhost[scanmd5][addressmd5])
                    labelout = '<span id="hostlabel' + str(
                        hostindex) + '" style="margin-left:' + labelmargin + '" class="rightlabel ' + labelcolor + '">' + html.escape(
                        labelhost[scanmd5][addressmd5]) + '</span>'
                    newlabelout = '<div id="hostlabel' + str(
                        hostindex) + '" style="z-index:99;transform: rotate(-8deg);margin-top:-14px;margin-left:-40px;" class="leftlabel ' + labelcolor + '">' + html.escape(
                        labelhost[scanmd5][addressmd5]) + '</div>' + \
                                  '<div id="hostlabelbb' + str(
                        hostindex) + '" class="' + labelcolor + '" style="border-radius:0px 4px 0px 4px;z-index:98;position:absolute;width:18px;height:10px;margin-left:-54px;margin-top:-3px;"></div>'

            notesout, notesb64, removenotes = '', '', ''
            if scanmd5 in noteshost:
                if addressmd5 in noteshost[scanmd5]:
                    notesb64 = noteshost[scanmd5][addressmd5]
                    notesout = '<a id="noteshost' + str(
                        hostindex) + '" class="grey-text" href="#!" onclick="javascript:openNotes(\'' + hashlib.md5(
                        str(address).encode(
                            'utf-8')).hexdigest() + '\', \'' + notesb64 + '\');"><i class="fas fa-comment"></i> contains notes</a>'
                    removenotes = '<li><a href="#!" class="grey-text" onclick="javascript:removeNotes(\'' + addressmd5 + '\', \'' + str(
                        hostindex) + '\');">Remove notes</a></li>'

            cveout = ''
            cvecount = 0
            if scanmd5 in cvehost:
                if addressmd5 in cvehost[scanmd5]:
                    cvejson = json.loads(cvehost[scanmd5][addressmd5])
                    for ic in cvejson:
                        if type(ic) is list:
                            listcve = ic
                        elif type(ic) is dict:
                            listcve = [ic]

                        for cvei in listcve:
                            if 'id' in cvei:
                                cvecount = (cvecount + 1)

                    if cvecount > 0:
                        cveout = '<a href="/report/' + address + '" class="red-text"><i class="fas fa-bug"></i> ' + str(
                            cvecount) + ' CVE found</a>'

            service_action = ''
            if service_counter > 0:
                device_services = list(ss.keys())

                count = 0
                for service in device_services:
                    if service in _MEDUSA_SUPPORTED_SERVICES:
                        count += 1
                        bruteforce_available_in_file = True

                if count == 1:
                    service_action += f"""<a href="#!" onclick="start_bruteforcer('{r['scanfile']}', '{address}');" class="grey-text"><i class="material-icons">dynamic_form</i> {count} Bruteforce Option Available</a>"""
                elif count > 1:
                    service_action += f"""<a href="#!" onclick="start_bruteforcer('{r['scanfile']}', '{address}');" class="grey-text"><i class="material-icons">dynamic_form</i> {count} Bruteforce Options Available</a>"""

            if (filterservice != "" and striggered is True) or (filterportid != "" and striggered is True) or (
                    filterservice == "" and filterportid == ""):
                portstateout = '<div style="overflow:none;background-color:#444;" class="tooltipped" data-position="top" data-tooltip="' + str(
                    po) + ' open, ' + str(pc) + ' closed, ' + str(pf) + ' filtered">' + \
                               '		<div class="perco" data-po="' + str(
                    po) + '" style="padding-left:16px;padding-right:20px;"><b>' + str(po) + '</b></div>' + \
                               ' </div>'

                if (filterservice != "" and striggered is True):
                    portstateout = '<div style="overflow:none;background-color:#444;" class="tooltipped" data-position="top" data-tooltip="' + str(
                        po) + ' open, ' + str(pc) + ' closed, ' + str(pf) + ' filtered">' + \
                                   '		<div class="perco" data-po="' + str(po) + '" data-pt="' + str(
                        (po + pf + pc)) + '" style="padding-left:16px;padding-right:20px;"><b>' + str(
                        po) + '</b></div>' + \
                                   '	</div>'

                tags = []
                extrainfosplit = e.split(' ')
                for eis in extrainfosplit:
                    if re.search('[a-zA-Z0-9\_]+\/[0-9\.]+', eis) is not None:
                        robj = re.search('([a-zA-Z0-9\_]+)\/([0-9\.]+)', eis)
                        tags.append(robj.group(1) + ' ' + robj.group(2))

                # Auto setting labels if CVE detected
                if cveout:
                    label(request, objtype="host", label="Warning", hashstr=addressmd5)

                r['tr'][address] = {
                    'hostindex': str(hostindex),
                    'hostname': hostname,
                    'ostype': ostype,
                    'notes': notesout,
                    'cve': cveout,
                    'portstate': portstateout,
                    'po': po,
                    'pc': pc,
                    'pf': pf,
                    'tags': tags,
                    'totports': str((po + pf + pc)),
                    'services': str(services[0:-2]),
                    'ports': str(tdports[0:-2]),
                    'addressmd5': addressmd5,
                    'removenotes': removenotes,
                    'labelout': labelout,
                    'newlabelout': newlabelout,
                    'notesb64': notesb64,
                    'notesout': notesout,
                    'cveout': cveout,
                    'cvecount': cvecount,
                    'serviceaction': service_action,
                    'vendor': vendor
                }

                hostindex = (hostindex + 1)

                # this fix single host report
                if type(ik) is not dict:
                    break
            else:
                if address in r['tr']:
                    del r['tr'][address]
        else:
            if address in r['tr']:
                del r['tr'][address]

    totports = (ports['open'] + ports['closed'] + ports['filtered'])
    if filterservice == "" and filterportid == "":
        scaninfobox2 = '<canvas id="chart1"></canvas>'
        scaninfobox3 = '<canvas id="chart3" height="150"></canvas>'
    else:
        scaninfobox2 = '<div class="small">' + \
                       '	<b class="orange-text">Filter port / service:</b> <b>' + html.escape(
            filterportid + filterservice) + '</b> <a href="/"><i class="fas fa-trash-alt"></i></a><br>' + \
                       '	<b class="orange-text">Total Ports:</b> ' + str(totports) + '<br>' + \
                       '	<b class="orange-text">Open Ports:</b> ' + str(ports['open']) + '<br>' + \
                       '	<b class="orange-text">Closed Ports:</b> ' + str(ports['closed']) + '<br>' + \
                       '	<b class="orange-text">Filtered Ports:</b> ' + str(ports['filtered']) + '</div>'
        scaninfobox3 = '<div id="detailstopports"></div>'

    scantype = ''
    if 'scaninfo' in o and '@type' in o['scaninfo']:
        scantype = o['scaninfo']['@type']

    if 'scaninfo' in o and type(o['scaninfo']) is list:
        for sinfo in o['scaninfo']:
            scantype += sinfo['@type'] + ', '
        scantype = scantype[0:-2]

    protocol = ''
    if 'scaninfo' in o and '@protocol' in o['scaninfo']:
        protocol = o['scaninfo']['@protocol']

    if 'scaninfo' in o and type(o['scaninfo']) is list:
        for sinfo in o['scaninfo']:
            protocol += sinfo['@protocol'] + ', '
        protocol = protocol[0:-2]

    numservices = ''
    if 'scaninfo' in o and '@numservices' in o['scaninfo']:
        numservices = o['scaninfo']['@numservices']

    verbose, debugging = '', ''
    if 'verbose' in o and '@level' in o['verbose']:
        verbose = o['verbose']['@level']

    if 'debugging' in o and '@level' in o['debugging']:
        debugging = o['debugging']['@level']

    r['stats'] = {
        'filename': r['scanfile'],
        'startstr': html.escape(datetime.fromtimestamp(int(o['@start'])).strftime('%A, %d. %B %Y - %H:%M:%S')),
        # o['@startstr'],
        'scantype': scantype,
        'protocol': protocol,
        'verbose': verbose,
        'debugging': debugging,
        'numservices': numservices,
        'nmapver': o['@version'],
        'nmapargs': insert_linebreaks(o['@args']),  # o['@args'],
        'xmlver': o['@xmloutputversion'],
        'hostsup': str(hostsup),
        'popen': ports['open'],
        'pclosed': ports['closed'],
        'pfiltered': ports['filtered']
    }

    allss = ''
    allsslabels = ''
    allssdata = ''
    allssc = 0
    for i in sorted(sscount, key=sscount.__getitem__, reverse=True):
        if allssc <= 30:
            if filterservice != i:
                allss += '<a href="/report/service/' + html.escape(i) + '/">' + html.escape(i) + '(' + str(
                    sscount[i]) + ')</a>, '
            else:
                allss += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">' + html.escape(
                    i) + '</span>, '

            allsslabels += '"' + html.escape(i) + '", '
            allssdata += '' + str(sscount[i]) + ','
            allssc = (allssc + 1)

    allpilabels = ''
    allpidata = ''
    allpilinks = ''
    allpic = 1
    for i in sorted(picount, key=picount.__getitem__, reverse=True):
        if allpic <= 5:
            allpilinks += '<a href="/report/portid/' + str(i) + '/">' + str(i) + '</a>, '
            allpilabels += '"' + html.escape(i) + '", '
            allpidata += '' + str(picount[i]) + ','
            allpic = (allpic + 1)
        elif allpic > 5 and allpic <= 10:
            allpilinks += '<a href="/report/portid/' + str(i) + '/">' + str(i) + '</a>, '
            allpic = (allpic + 1)

    allostypelinks = ''
    for i in sorted(allostypelist, key=allostypelist.__getitem__, reverse=True):
        allostypelinks += '<a href="">' + str(i) + '</a>, '

    r['stats']['services'] = allss[0:-2]
    r['stats']['portids'] = allpilinks[0:-2]
    r['stats']['ostypes'] = allostypelinks[0:-2]

    r['pretable'] = ''
    r['js'] = ''

    r['js'] += '<script>' + \
               '	$(document).ready(function() {' + \
               '		/* $("#scantitle").html("' + html.escape(request.session['scanfile']) + '"); */ ' + \
               '		$(".dropdown-trigger").dropdown();' + \
               '		$(".tooltipped").tooltip();' + \
               '		$(".perco").each(function() { ' + \
               '			var pwidth = ( (($(this).attr("data-po") * 100) / ' + str(totports) + ') ); ' + \
               '			/* console.log(pwidth); */ ' + \
               '			$(this).css("width", pwidth+"%" ); ' + \
               '			if($(this).attr("data-po") < 1) { $(this).html("&nbsp;"); $(this).css("background-color","#666") } ' + \
               '		});' + \
               '	$("#detailstopports").html(\'<span class="small">' + str(allss[0:-2]) + '</span>\');' + \
               '	});' + \
               '</script>'

    cpedict = {}
    # r['cpestring'] = ''
    for cpeaddr in cpe:
        for cpei in cpe[cpeaddr]:
            if re.search('^cpe:.+:.+:.+:.+$', cpei) is not None:
                # r['cpestring'] += cpei+'<br>'
                if cpei not in cpedict:
                    cpedict[cpei] = {}
                if cpeaddr not in cpedict[cpei]:
                    cpedict[cpei][cpeaddr] = 1

    r['cpestring'] = ' <input type="hidden" id="cpestring" value="' + urllib.parse.quote_plus(
        base64.b64encode(json.dumps(cpedict).encode())) + '" /> '

    if r['scanfile']:
        r['file_dropdown'] = create_file_dropdown(r['scanfile'])

        if bruteforce_available_in_file:
            r['bruteforce_all_action'] = f"""
                <a href="#!" onclick="start_bruteforcer('{r['scanfile']}', 'all');" style="color: #ff9800;">
                    <i class="material-icons">dynamic_form</i> Bruteforce all                  
                </a><br><br>
            """

    return render(request, 'proteciotnet_dev/ip_device_overview.html', r)
