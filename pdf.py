from time import sleep

from django.http import HttpResponse
import subprocess
import datetime
import json
import logging

from django.shortcuts import render

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

    except Exception:
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

    if os.path.isfile(f"{_BASE_REPORTS_DIR}{filename_without_ext}.{report_type}"):
        logger.warning(f"file {filename_without_ext}.{report_type} already exists. Deleting it to create anew.")
        os.remove(f"{_BASE_REPORTS_DIR}{filename_without_ext}.{report_type}")
    elif report_type == "png" and os.path.isfile(f"{_BASE_REPORTS_DIR}{filename_without_ext}.dot"):
        logger.warning(f"file {filename_without_ext}.dot already exists. Deleting it to create anew.")
        os.remove(f"{_BASE_REPORTS_DIR}{filename_without_ext}.dot")

    if report_type == "svg":
        report_type = "dot"

    base_cmd = f'{_NMAP_FORMATTER_BASE_DIR} {report_type} {_XML_BASE_DIR}{name} -f {_BASE_REPORTS_DIR}{filename_without_ext}'.replace("pdf", "md")

    if report_type == "pdf":
        cmd = f'{base_cmd}.md &'
        convert_to_pdf_cmd = f'sudo pandoc {_BASE_REPORTS_DIR}{filename_without_ext}.md -o {_BASE_REPORTS_DIR}{filename_without_ext}.pdf --from markdown --template eisvogel &'
    elif report_type in ["md", "html", "json", "csv", "dot"] and not report_type_orig == "svg":
        cmd = f'{base_cmd}.{report_type} &'
    elif report_type == "sqlite":
        cmd = f'{_NMAP_FORMATTER_BASE_DIR} {report_type} {_XML_BASE_DIR}{name} --sqlite-dsn {_BASE_REPORTS_DIR}{filename_without_ext}.sqlite &'
    elif report_type_orig == "svg":
        cmd = f'{base_cmd}.dot &'
        convert_to_png_cmd = f"sudo dot -Tsvg {_BASE_REPORTS_DIR}{filename_without_ext}.dot -o {_BASE_REPORTS_DIR}{filename_without_ext}.svg &"

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
        dot_filename = f"{_BASE_REPORTS_DIR}{filename_without_ext}.dot"
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
