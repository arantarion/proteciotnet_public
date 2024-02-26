import json
import os
import re
import time
import logging

from configparser import ConfigParser, ExtendedInterpolation

"""
The script parses an handels the creation of cronjobs for repeated nmaps scans.
It is not intended to be run alone. Please use the ProtecIoTnet web-frontend instead.

"""

logger = logging.getLogger(__name__)

try:
    config_cron = ConfigParser(interpolation=ExtendedInterpolation())
    config_cron.read('proteciotnet.config')

    _PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY = config_cron.get('WIFI_PATHS', 'proteciotnet_nmap_schedule_directory')
    _NSE_SCRIPTS_DIRECTORY = config_cron.get('WIFI_PATHS', 'nse_scripts_directory')

    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e} in file {__file__}")
    exit(-3)

schedfiles = os.listdir(_PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY)
logger.debug(f"Schedule Files: {schedfiles}")


def gethours(duration: str) -> int:
    """
    Converts a time duration string into its equivalent number of seconds.

    Args:
    - duration (str): A string representing the time duration. It can be one of the following:
        - '1h' for 1 hour
        - '1d' for 1 day
        - '1w' for 1 week
        - '1m' for 1 month

    Returns:
    - int: The number of seconds equivalent to the input time duration.

    Raises:
    - KeyError: If the input string is not one of the supported time duration strings.
    """
    return {
        '1h': 3600,
        '1d': 86400,
        '1w': 604800,
        '1m': 2592000
    }[duration]


for i in schedfiles:
    if re.search('^[a-f0-9]{32,32}\.json$', i.strip()) is not None:
        sched = json.loads(open(f'{_PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY}/{i}', "r").read())

        logger.debug(f"sched {sched}")

        nextrun = (sched['lastrun'] + gethours(sched['params']['frequency']))
        logger.debug(nextrun)

        if nextrun <= time.time():
            sched['number'] = (sched['number'] + 1)
            logger.debug(
                f"[RUN] scan:{sched['params']['filename']} id:{sched['number']} (nextrun:{nextrun} / now:{time.time()})")

            sched['lastrun'] = time.time()

            logger.debug('nmap ' + sched['params']['params'] + ' --script=' + cdir + '/nse/ -oX /tmp/' + str(
                sched['number']) + '_' + sched['params']['filename'] + '.active ' + sched['params'][
                             'target'] + ' > /dev/null 2>&1 && ' +
                         'sleep 5 && mv /tmp/' + str(sched['number']) + '_' + sched['params'][
                             'filename'] + '.active /opt/xml/webmapsched_' + str(sched['lastrun']) + '_' +
                         sched['params']['filename'] + ' && ' +
                         'ls -lart /opt/xml/webmapsched_' + str(sched['lastrun']) + '_' + sched['params'][
                             'filename'] + ' && python3 ' + cdir + '/cve.py webmapsched_' + str(
                sched['lastrun']) + '_' + sched['params']['filename'] + '')

            logger.debug(
                f"nmap {sched['params']['params']} --script={_NSE_SCRIPTS_DIRECTORY} -oX /tmp/{sched['number']}_{sched['params']['filename']}.active {sched['params']['target']} > /dev/null 2>&1 && " +
                f"sleep 5 && "
                f"mv /tmp/{sched['number']}_{sched['params']['filename']}.active /opt/xml/webmapsched_{sched['lastrun']}_{sched['params']['filename']} && " +
                f"ls -lart /opt/xml/webmapsched_{sched['lastrun']}_{sched['params']['filename']} && " +
                f"python3 {_PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY}/cve.py webmapsched_{sched['lastrun']}_{sched['params']['filename']}"
            )

            nmapout = os.popen(
                f"nmap {sched['params']['params']} --script={_NSE_SCRIPTS_DIRECTORY} -oX /tmp/{sched['number']}_{sched['params']['filename']}.active {sched['params']['target']} > /dev/null 2>&1 && " +
                f"sleep 5 && "
                f"mv /tmp/{sched['number']}_{sched['params']['filename']}.active /opt/xml/webmapsched_{sched['lastrun']}_{sched['params']['filename']} && " +
                f"ls -lart /opt/xml/webmapsched_{sched['lastrun']}_{sched['params']['filename']} && " +
                f"python3 {_PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY}/cve.py webmapsched_{sched['lastrun']}_{sched['params']['filename']}"
                )

            logger.debug(f"nmapout: {nmapout}")

            f = open(f'{_PROTECIOTNET_NMAP_SCHEDULE_DIRECTORY}/{i}', "w")
            f.write(json.dumps(sched, indent=4))

            time.sleep(10)
        else:
            logger.debug("[SKIP]  scan:" + sched['params']['filename'] + " id:" + str(sched['number']) + " (nextrun:" + str(
                nextrun) + " / now:" + str(time.time()) + ")")
