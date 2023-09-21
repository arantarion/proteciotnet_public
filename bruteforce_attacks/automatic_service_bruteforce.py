import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import logging
from datetime import datetime

# Medusa Docu http://foofus.net/goons/jmk/medusa/medusa.html

logger = logging.getLogger(__name__)

NAME_MAP = {
    "ms-sql-s": "mssql",
    "microsoft-ds": "smbnt",
    "cifs": "smbnt",
    "pcanywheredata": "pcanywhere",
    "postgresql": "postgres",
    "shell": "rsh",
    "exec": "rexec",
    "login": "rlogin",
    "smtps": "smtp",
    "submission": "smtp",
    "imaps": "imap",
    "pop3s": "pop3",
    "iss-realsecure": "vmauthd",
    "snmptrap": "snmp"
}

_USERLIST_BASE_LOCATION = "/home/henry/Downloads/wordlist/"
_PASSWORDLIST_BASE_LOCATION = "/home/henry/Downloads/wordlist/"
_OUTPUT_DIRECTORY = "/home/henry/Downloads/protec_medusa_logs/"
_XML_STANDARD_DIR = "/opt/xml/"

_services = {}


def _parse_xml(filename):
    supported = ['ssh', 'ftp', 'postgresql', 'telnet', 'mysql', 'ms-sql-s', 'rsh',
                 'vnc', 'imap', 'imaps', 'nntp', 'pcanywheredata', 'pop3', 'pop3s',
                 'exec', 'login', 'microsoft-ds', 'smtp', 'smtps', 'submission',
                 'svn', 'iss-realsecure', 'snmptrap', 'snmp', 'http']

    tree = ET.parse(filename)
    root = tree.getroot()
    for host in root.iter('host'):
        ipaddr = host.find('address').attrib['addr']
        for port in host.iter('port'):
            cstate = port.find('state').attrib['state']
            if cstate == "open":
                try:
                    name = port.find('service').attrib['name']
                    tmp_port = port.attrib['portid']
                    iplist = ipaddr.split(',')
                except:
                    continue
                if name in supported:
                    name = NAME_MAP.get(name, name)
                    if name in _services:
                        if tmp_port in _services[name]:
                            _services[name][tmp_port] += iplist
                        else:
                            _services[name][tmp_port] = iplist
                    else:
                        _services[name] = {tmp_port: iplist}


def _check_file_format(filename):
    in_format = None
    with open(filename) as f:
        filename_line = f.readlines()
        if '<?xml ' in filename_line[0] and 'nmaprun' in filename_line[1]:
            return "xml"

    return in_format


"""
Syntax: Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
    -b           : Suppress startup banner
    -H [FILE]    : File containing target hostnames or IP addresses
----------------------------------------------------------------------------------------------
    -h [TEXT]    : Target hostname or IP address
----------------------------------------------------------------------------------------------   
    -U [FILE]    : File containing usernames to test
    -P [FILE]    : File containing passwords to test
    -M [TEXT]    : Name of the module to execute (without the .mod extension)
    -t [NUM]     : Total number of logins to be tested concurrently
    -n [NUM]     : Use for non-default TCP port number
    -T [NUM]     : Total number of hosts to be tested concurrently
    -f           : Stop scanning host after first valid username/password found.
    -v [NUM]     : Verbose level [0 - 6 (more)]
    -w [NUM]     : Error debug level [0 - 10 (more)]
    -e [n/s/ns]  : Additional password checks ([n] No Password, [s] Password = Username)
    -O [FILE]    : File to append log information to
----------------------------------------------------------------------------------------------
    -V           : Display version
    -m [TEXT]    : Parameter to pass to the module. This can be passed multiple times with a
                 different parameter each time and they will all be sent to the module (i.e.
                 -m Param1 -m Param2, etc.)
    -F           : Stop audit after first valid username/password found on any host.
"""

def _brute(service, port, filename, output, single_host=""):
    userlist = f'{_USERLIST_BASE_LOCATION}{service}/user2'
    passlist = f'{_PASSWORDLIST_BASE_LOCATION}{service}/password2'
    output_file = f'{output}/{port}-{service}-success.txt'
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    logfile_name = f'{_OUTPUT_DIRECTORY}{timestamp}_proteciotnet_medusa.log'

    cmd = ['medusa', '-b', '-H', filename, '-U', userlist, '-P', passlist, '-M', service, '-t', '2', '-n', port, '-T',
           '1', '-f', '-v', '5', '-w', '5', '-e' 'ns', '-O', logfile_name]

    if single_host:
        cmd = ['medusa', '-b', '-h', single_host, '-U', userlist, '-P', passlist, '-M', service, '-t', '2', '-n', port,
               '-T', '1', '-f', '-v', '5', '-w', '5', '-e' 'ns', '-O', logfile_name]

    if service == "smtp":
        cmd.extend(["-m", "AUTH:LOGIN"])

    logger.info(f"Using username list: {userlist}")
    logger.info(f"Using password list: {passlist}")
    logger.info(f"Output directory is set to: {output_file}")
    logger.info(f"Starting medusa with: {' '.join(cmd)}")

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)

    print("#"*150)
    for line in p.stdout:
        print(line.strip('\n'))
        if 'SUCCESS' in line:
            with open(output_file, 'a') as out_file:
                out_file.write("[+]" + line)
    print("#" * 150)
    logger.info("Medusa has finished.")
    return logfile_name


def auto_bruteforce(filename, host):
    logger.info("Starting auto bruteforcing attempt using medusa.")
    filename = f"{_XML_STANDARD_DIR}{filename}"

    if os.system("command -v medusa > /dev/null") != 0:
        logger.error("Command medusa not found. Please install medusa")
        return

    if not os.path.exists(_OUTPUT_DIRECTORY):
        logger.warning(f"{_OUTPUT_DIRECTORY} does not exist. Trying to create it.")
        os.mkdir(_OUTPUT_DIRECTORY)

    if os.path.isfile(filename) and _check_file_format(filename) == "xml":
        _parse_xml(filename)
    else:
        logger.error("Error loading file, please check your filename.")
        return

    try:
        tmppath = tempfile.mkdtemp(prefix="proteciotnet-tmp")
    except:
        logger.error("Error while creating temporary directory.")
        exit(4)

    logger.info(f"Successfully passed all preliminary checks and parsing / {filename}")

    logfile_name = ""
    something_worked = False
    for service in _services:
        if host == "all":
            for port in _services[service]:
                logger.info(f"Instructing medusa with bruteforcing on port {port} for service {service}")
                temp_ip_filename = f'{tmppath}/tmp-{service}-{port}'
                iplist = set(_services[service][port])
                with open(temp_ip_filename, 'w+') as f:
                    for ip in iplist:
                        f.write(ip + '\n')
                logger.info(f"Successfully wrote IPs to temporary file {temp_ip_filename}")
                logfile_name = _brute(service=service, port=port, filename=temp_ip_filename, output=_OUTPUT_DIRECTORY)
                something_worked = True
        else:
            for port in _services[service]:
                if host in _services[service][port]:
                    logger.info(f"Instructing medusa with bruteforcing {host} on port {port} for service {service}")
                    temp_ip_filename = f'{tmppath}/tmp-{service}-{port}'
                    logfile_name = _brute(service=service, port=port, filename=temp_ip_filename, output=_OUTPUT_DIRECTORY, single_host=host)
                    something_worked = True

    if not something_worked:
        logger.error(f"Specified host {host} was not found in file {filename} or has no services to bruteforce with this toolchain")

    if something_worked and logfile_name:
        logger.info(f"The log of this scan is available at {logfile_name}")
