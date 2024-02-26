import os
import tempfile
import time
import subprocess
import datetime
import json
import logging
import csv

from time import sleep
from django.http import HttpResponse
from django.shortcuts import render
from configparser import ConfigParser, ExtendedInterpolation

from proteciotnet_dev.functions import *

# _BASE_REPORTS_DIR = "/opt/proteciotnet/proteciotnet_dev/static/reports/"
# _BASE_ZIGBEE_REPORTS_DIR = "/opt/proteciotnet/proteciotnet_dev/static/zigbee_reports/"
# _NMAP_FORMATTER_BASE_DIR = "/opt/nmap_formatter/nmap-formatter"
# _XML_BASE_DIR = "/opt/xml/"
# _JSON_BASE_DIR = "/opt/zigbee/"

logger = logging.getLogger(__name__)

try:
    config_pdf = ConfigParser(interpolation=ExtendedInterpolation())
    config_pdf.read('proteciotnet.config')
    _REPORTS_DIRECTORY = config_pdf.get('GENERAL_PATHS', 'report_directory')
    _ZIGBEE_REPORTS_DIRECTORY = config_pdf.get('ZIGBEE_PATHS', 'zigbee_reports_directory')
    _NMAP_FORMATTER_LOCATION = config_pdf.get('WIFI_PATHS', 'nmap_formatter_location')
    _WIFI_XML_BASE_DIRECTORY = config_pdf.get('WIFI_PATHS', 'wifi_xml_base_directory')
    _ZIGBEE_JSON_BASE_DIRECTORY = config_pdf.get('ZIGBEE_PATHS', 'zigbee_json_base_directory')
    logger.info("Successfully loaded config file 'proteciotnet.config'")
except Exception as e:
    logger.error(f"Could not load configuration values from 'proteciotnet.config'. Error: {e}")
    exit(-3)


def _create_yaml_header(filename):
    """
    Create a YAML header for an NMAP report.

    Args:
    - filename (str): The name of the file for which the header is being generated.

    Returns:
    - str: A formatted YAML header string.
    """

    _BACKGROUND_IMAGE_PATH = "/opt/proteciotnet/proteciotnet_dev/static/reports/backgrounds/background.pdf"
    _PAGE_BACKGROUND_IMAGE_PATH = "/opt/proteciotnet/proteciotnet_dev/static/reports/backgrounds/page_background.pdf"
    _DATE = datetime.datetime.now().strftime('%A, %d. %B %Y - %H:%M')

    logger.info("Retrieving nmap-formatter version")
    _NMAP_FORMATTER_VERSION = (subprocess.check_output('/opt/nmap_formatter/nmap-formatter --version',
                                                       shell=True,
                                                       text=True)
                               .strip().replace("version: ", "v."))

    yaml_header = (f'---\n'
                   f'title: "NMAP Scan Result"\n'
                   f'author: ["Created with {_NMAP_FORMATTER_VERSION}"]\n'
                   f'date: "{_DATE}"\n'
                   f'subject: "nmap report"\n'
                   f'keywords: [nmap, report, proteciotnet]\n'
                   f'subtitle: "for {filename}.xml"\n'
                   f'lang: "en"\n'
                   f'titlepage: true\n'
                   f'titlepage-rule-color: "5F5F5F"\n'
                   f'titlepage-rule-height: 0\n'
                   f'titlepage-background: "{_BACKGROUND_IMAGE_PATH}"\n'
                   f'page-background: "{_PAGE_BACKGROUND_IMAGE_PATH}"\n'
                   f'toc-own-page: true\n'
                   f'...\n'
                   f'\n')

    logger.info("Created YAML header for markdown file")
    return yaml_header


def _append_yaml_header(filename):
    """
    Prepend a string to the beginning of a file.

    Parameters:
    - filename: The path to the file.
    - text_to_prepend: The string to prepend to the file.
    """

    logger.info(f"Appending YAML header to markdown file -> {_REPORTS_DIRECTORY}{filename}.md")
    md_filename = f'{_REPORTS_DIRECTORY}{filename}.md'

    try:
        with open(md_filename, 'r') as file:
            original_content = file.read()

        new_content = _create_yaml_header(filename) + original_content

        with open(md_filename, 'w') as file:
            file.write(new_content)

        logger.info("Successfully added YAML header to file")

    except Exception:
        logger.error(f"Could not append YAML header to {_REPORTS_DIRECTORY}{filename}.md")


def create_report(request):
    """
    Create a report based on the request type.
    Possibilities are pdf, markdown (md), html, json, csv and png (dot)

    Args:
    - request: The incoming request object.

    Returns:
    - HttpResponse: A response object containing the result or error message.
    """

    if request.method != "POST":
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

    logger.info(f"Creating {request.POST['report_type']} report")
    res = {'p': request.POST}

    report_type = request.POST['report_type']
    report_type_orig = report_type
    name = request.POST['filename']
    filename_without_ext = name.rsplit('.', 1)[0]

    cmd = ""
    convert_to_pdf_cmd = ""
    convert_to_png_cmd = ""

    if os.path.isfile(f"{_REPORTS_DIRECTORY}{filename_without_ext}.{report_type}"):
        logger.warning(f"file {filename_without_ext}.{report_type} already exists. Deleting it to create anew.")
        os.remove(f"{_REPORTS_DIRECTORY}{filename_without_ext}.{report_type}")
    elif report_type == "png" and os.path.isfile(f"{_REPORTS_DIRECTORY}{filename_without_ext}.dot"):
        logger.warning(f"file {filename_without_ext}.dot already exists. Deleting it to create anew.")
        os.remove(f"{_REPORTS_DIRECTORY}{filename_without_ext}.dot")

    if report_type == "svg":
        report_type = "dot"

    base_cmd = f'{_NMAP_FORMATTER_LOCATION} {report_type} {_WIFI_XML_BASE_DIRECTORY}{name} -f {_REPORTS_DIRECTORY}{filename_without_ext}'.replace(
        "pdf", "md")

    if report_type == "pdf":
        cmd = f'{base_cmd}.md &'
        convert_to_pdf_cmd = f'sudo pandoc {_REPORTS_DIRECTORY}{filename_without_ext}.md -o {_REPORTS_DIRECTORY}{filename_without_ext}.pdf --from markdown --template eisvogel &'
    elif report_type in ["md", "html", "json", "csv", "dot"] and not report_type_orig == "svg":
        cmd = f'{base_cmd}.{report_type} &'
    elif report_type == "sqlite":
        cmd = f'{_NMAP_FORMATTER_LOCATION} {report_type} {_WIFI_XML_BASE_DIRECTORY}{name} --sqlite-dsn {_REPORTS_DIRECTORY}{filename_without_ext}.sqlite &'
    elif report_type_orig == "svg":
        cmd = f'{base_cmd}.dot &'
        convert_to_png_cmd = f"sudo dot -Tsvg {_REPORTS_DIRECTORY}{filename_without_ext}.dot -o {_REPORTS_DIRECTORY}{filename_without_ext}.svg &"

    if cmd:
        logger.info(f"Using {cmd} to create file")
        os.popen(cmd)

    if convert_to_pdf_cmd:
        logger.info(f"Converting to PDF using pandoc")
        while not os.path.isfile(f"{_REPORTS_DIRECTORY}{filename_without_ext}.md"):
            sleep(1)
        _append_yaml_header(filename_without_ext)
        os.popen(convert_to_pdf_cmd)

    if convert_to_png_cmd:
        logger.info(f"Converting to PNG using graphviz")
        dot_filename = f"{_REPORTS_DIRECTORY}{filename_without_ext}.dot"
        while not os.path.isfile(dot_filename):
            sleep(1)

        # replace layout engine
        with open(dot_filename, 'r') as file:
            file_contents = file.read()

        updated_contents = file_contents.replace('layout=dot', 'layout=circo')

        with open(dot_filename, 'w') as file:
            file.write(updated_contents)

        os.popen(convert_to_png_cmd)

    logger.info("Creation (and conversion) completed successfully")

    return HttpResponse(json.dumps(res, indent=4), content_type="application/json")


def _prepend_column_from_first_to_second(file1_path, file2_path, output_path):
    """
    Prepend the first column from the first CSV file to the rows of the second CSV file.

    Parameters:
    - file1_path: Path to the first CSV file.
    - file2_path: Path to the second CSV file.
    - output_path: Path to the output CSV file.
    """

    # Read the first column from the first CSV file
    with open(file1_path, 'r') as f1:
        reader1 = csv.reader(f1)
        first_column = ["info"] + [row[0] for row in reader1]

    # Read the second CSV file and prepend the values from the first column
    with open(file2_path, 'r') as f2, open(output_path, 'w', newline='') as out_file:
        reader2 = csv.reader(f2)
        writer = csv.writer(out_file)

        for i, row in enumerate(reader2):
            if i < len(first_column):  # Ensure we don't go out of bounds
                writer.writerow([first_column[i]] + row)
            else:
                writer.writerow(row)


def _create_temp_folder(path):
    try:
        os.mkdir(path)
    except:
        logger.error(f"Could not create directory at {path}")
        return HttpResponse(json.dumps({'error': 'Cannot create temporary folder'}, indent=4),
                            content_type="application/json")


def create_zigbee_report(request):
    if request.method != "POST":
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

    res = {'p': request.POST}

    report_type = request.POST['report_type']
    name = request.POST['filename']
    filename_without_ext = name.rsplit('.', 1)[0]

    convert_command2 = ""
    tmp_path = f"/tmp/proteciotnet_temp_csv{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if report_type == "html":
        _create_temp_folder(tmp_path)
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T pdml > {tmp_path}/tmp.pdml && xsltproc {_ZIGBEE_JSON_BASE_DIRECTORY}pdml2html.xsl {tmp_path}/tmp.pdml > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.html"
    elif report_type == "csv":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T fields -E separator=, -E header=y -E quote=d -e frame -e wpan.src16 -e zbee_nwk.src -e wpan.dst16 -e zbee_nwk.dst -e wpan.seq_no -e zbee_nwk.seqno > {tmp_path}/fields.csv"
        convert_command2 = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap > {tmp_path}/info.csv"
    elif report_type == "pcapng":
        _create_temp_folder(tmp_path)
        convert_command = f"tcpdump -Z root -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -w {tmp_path}/{filename_without_ext}.pcapng && mv {tmp_path}/{filename_without_ext}.pcapng {_ZIGBEE_REPORTS_DIRECTORY}"
    elif report_type == "pcap":
        convert_command = f"cp {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap {_ZIGBEE_REPORTS_DIRECTORY}"
    elif report_type == "psml":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T psml > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.psml"
    elif report_type == "pdml":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T pdml > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.pdml"
    elif report_type == "plain":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T tabs > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.txt"
    elif report_type == "ek":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T ek > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.ekjson"
    elif report_type == "json":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T json > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.json"
    elif report_type == "ps":
        convert_command = f"tshark -r {_ZIGBEE_JSON_BASE_DIRECTORY}{filename_without_ext}.pcap -T ps > {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.ps && ps2pdf {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.ps {_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.pdf"
    else:
        return HttpResponse(json.dumps({'error': 'not a valid filetype'}, indent=4), content_type="application/json")

    if report_type in ["html", "pcapng", "psml", "pdml", "plain", "ek", "ps", "json", "pcap"] and convert_command:
        logger.info(f"Creating report of type {report_type} with command {convert_command}")
        os.popen(convert_command)
    if report_type == "csv" and convert_command and convert_command2:
        _create_temp_folder(path=tmp_path)
        logger.info(f"Creating csv report with command {convert_command} and {convert_command2}")
        os.popen(convert_command)
        os.popen(convert_command2)

        while not os.path.isfile(f"{tmp_path}/info.csv") and not os.path.isfile(f"{tmp_path}/fields.csv"):
            time.sleep(1)
        _prepend_column_from_first_to_second(file1_path=f"{tmp_path}/info.csv",
                                             file2_path=f"{tmp_path}/fields.csv",
                                             output_path=f"{_ZIGBEE_REPORTS_DIRECTORY}{filename_without_ext}.csv")

    return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
