import base64
import html
import urllib.parse
import os, xmltodict, json, hashlib, re
from time import sleep

from django.http import HttpResponse
from django.shortcuts import render
import subprocess
import datetime
import logging

from proteciotnet_dev.functions import *

_BASE_REPORTS_DIR = "/opt/proteciotnet/proteciotnet_dev/static/reports/"
_NMAP_FORMATTER_BASE_DIR = "/opt/nmap_formatter/nmap-formatter"
_XML_BASE_DIR = "/opt/xml/"

logger = logging.getLogger(__name__)


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
    # _NMAP_FORMATTER_VERSION = _NMAP_FORMATTER_VERSION.replace("version: ", "v.")

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

    logger.info(f"Appending YAML header to markdown file -> {_BASE_REPORTS_DIR}{filename}.md")
    md_filename = f'{_BASE_REPORTS_DIR}{filename}.md'

    try:
        with open(md_filename, 'r') as file:
            original_content = file.read()

        new_content = _create_yaml_header(filename) + original_content

        with open(md_filename, 'w') as file:
            file.write(new_content)

        logger.info("Successfully added YAML header to file")

    except:
        logger.error(f"Could not append YAML header to {_BASE_REPORTS_DIR}{filename}.md")


def create_report(request):
    """
    Create a report based on the request type.
    Possibilities are pdf, markdown (md), html, json, csv and png (dot)

    Args:
    - request: The incoming request object.

    Returns:
    - HttpResponse: A response object containing the result or error message.
    """
    print("HERE")
    if request.method != "POST":
        return HttpResponse(json.dumps({'error': 'invalid syntax'}, indent=4), content_type="application/json")

    logger.info(f"Creating {request.POST['report_type']} report")
    res = {'p': request.POST}

    report_type = request.POST['report_type']
    name = request.POST['filename']
    # filename_without_ext = name.replace(name.split(".")[-1], "")
    filename_without_ext = name.rsplit('.', 1)[0]

    cmd = ""
    convert_to_pdf_cmd = ""
    convert_to_png_cmd = ""

    base_cmd = f'{_NMAP_FORMATTER_BASE_DIR} {report_type} {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}'.replace("pdf", "md")

    if report_type == "pdf":
        cmd = f'{base_cmd}.md &'
        convert_to_pdf_cmd = f'sudo pandoc {_BASE_REPORTS_DIR}{filename_without_ext}.md -o {_BASE_REPORTS_DIR}{filename_without_ext}.pdf --from markdown --template eisvogel &'
    elif report_type in ["md", "html", "json", "csv"]:
        cmd = f'{base_cmd}.{report_type} &'
    elif report_type == "dot":
        cmd = f'{base_cmd}.dot &'
        convert_to_png_cmd = f"sudo dot -Tpng {_BASE_REPORTS_DIR}{filename_without_ext}.dot -o {_BASE_REPORTS_DIR}{filename_without_ext}.png &"

    if cmd:
        logger.info(f"Using {cmd} to create file")
        os.popen(cmd)

    if convert_to_pdf_cmd:
        logger.info(f"Converting to PDF using pandoc")
        while not os.path.isfile(f"{_BASE_REPORTS_DIR}{filename_without_ext}.md"):
            sleep(1)
        _append_yaml_header(filename_without_ext)
        os.popen(convert_to_pdf_cmd)

    if convert_to_png_cmd:
        logger.info(f"Converting to PNG using graphviz")
        while not os.path.isfile(f"{_BASE_REPORTS_DIR}{filename_without_ext}.dot"):
            sleep(1)
        os.popen(convert_to_png_cmd)

    logger.info("Creation (and conversion) successfull")

    return HttpResponse(json.dumps(res, indent=4), content_type="application/json")


# if report_type == "pdf":
#     cmd = f'{_NMAP_FORMATTER_BASE_DIR} md {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}.md &'
#     convert_to_pdf_cmd = f'sudo pandoc {_BASE_REPORTS_DIR}{filename_without_ext}.md -o {_BASE_REPORTS_DIR}{filename_without_ext}.pdf --from markdown --template eisvogel &'
# elif report_type == "md":
#     cmd = f'{_NMAP_FORMATTER_BASE_DIR} md {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}.md &'
# elif report_type == "html":
#     cmd = f'{_NMAP_FORMATTER_BASE_DIR} html {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}.html &'
# elif report_type == "json":
#     cmd = f'{_NMAP_FORMATTER_BASE_DIR} json {_XML_BASE_DIR}{name} --json-pretty=true -f {_BASE_REPORTS_DIR}{filename_without_ext}.json &'
# elif report_type == "csv":
#     cmd = f'{_NMAP_FORMATTER_BASE_DIR} csv {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}.csv &'
# elif report_type == "dot":
#     cmd = f'{_NMAP_FORMATTER_BASE_DIR} dot {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}.dot &'
#     convert_to_png_cmd = f"sudo dot -Tpng {_BASE_REPORTS_DIR}{filename_without_ext}.dot -o {_BASE_REPORTS_DIR}{filename_without_ext}.png &"
