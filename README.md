<div align="center">
  <a href="https://gitlab.com/hweckermann/proteciotnet">
    <img src="docs/images/banner_centered_rounded.png" alt="Logo" width="1024" height="271">
  </a>
</div>

<br>
<hr>

<div align="center">
  <h1>ProtecIoTnet</h1>

  <strong>A web based application for identification and vulnerability scanning of smart home IoT devices</strong>
  <br />
  <br />
  <a href="https://gitlab.com/hweckermann/proteciotnet/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  ·
  <a href="https://gitlab.com/hweckermann/proteciotnet/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  .
  <a href="https://gitlab.com/hweckermann/proteciotnet/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+">Ask a Question</a>
</div>

<div align="center">
<br />

[![GitLab (self-managed)](https://img.shields.io/gitlab/license/47584685)](LICENSE)

[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](https://gitlab.com/hweckermann/proteciotnet/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) 
[![code with love by hweckermann](https://img.shields.io/badge/%3C%2F%3E%20with%20%E2%99%A5%20by-hweckermann-ff1414.svg)](https://gitlab.com/hweckermann)

</div>

<hr>
<br>

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
  - [Key Features](#key-features)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Authors \& contributors](#authors--contributors)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

</details>

---

## About

Welcome to the ProtecIoTnet repository! ProtecIoTnet is a web-based python application developed to support users in securely utilizing IoT devices in a home network. The application aims to provide a user-friendly interface, catering to both novice and experienced users, while addressing a wide range of identified risks associated with IoT devices in home networks. Currently supported are IP-, ZigBee-, Bluetooth- and BLE-based products.

### Key Features

- Open source development in python using the Flask web framework
- Assist users in identifying and mitigating potential risks through automated and repeatable tests
- Leverages existing open-source software for detection and attack simulations wherever possible
- Detects and gathers comprehensive information about IoT devices in the network
- Developed for Raspberry Pi 4 as a cost-effective and highly supported open-source platform
- Supports common Smart Home standards, including Wi-Fi, MQTT, ZigBee, Bluetooth, and Bluetooth Low Energy
- Intuitive web interface for setting parameters, displaying results, and managing modules
- Modular design to encapsulate tests and attacks, enabling easy integration of additional modules
- Stores output in a single SQLite database for easy accessibility and compatibility

> Pictures here!

### Built With

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
- something

## Getting Started

### Prerequisites

- Raspberry Pi 4b (or a similar single-board computer) with sufficient memory and processing power
- Raspbian or another compatible operating system installed on the Raspberry Pi
- Internet connection to access the web-based application and update dependencies
- RaspBee II
- Ubertooth One

### Installation

```bash
# Clone this repository
$ git clone https://gitlab.com/hweckermann/proteciotnet

# Go into the repository
$ cd proteciotnet

# Install dependencies
$ pip install -r requirements.txt

# Run the app
$ python3 proteciotnet.py --start-server
```

The application will now start on the local server. If the browser doesn't open automatically , please open a web browser and navigate to http://localhost:8000 to access the application.


## Usage

```bash
# Starting the server 
$ python3 proteciotnet.py --start-server

# Starting the server with verbose output
$ python3 proteciotnet.py --start-server -v

# Printing the version
$ python3 proteciotnet.py -V
```

## Project Structure

The Git repository includes the following files and directories:

- **/docs**: This directory contains the project documentation, including the project description, user manual, and other relevant information.
- **/src**: This directory contains the source code of the web-based application.
- **/tests**: Here, you will find test cases and scripts to verify the functionality of the application.
- **/dependencies**: This directory lists all external dependencies required for the project. Make sure to install these dependencies before running the application.
- **/data**: You can store test data and sample files used for development and testing in this directory.
- **README.md**: This file contains essential information about the project and instructions for using the application.


## Roadmap

See the [open issues](https://gitlab.com/hweckermann/proteciotnet/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://gitlab.com/hweckermann/proteciotnet/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://gitlab.com/hweckermann/proteciotnet/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://gitlab.com/hweckermann/proteciotnet/issues?q=is%3Aopen+is%3Aissue+label%3Abug)


## Contributing

First off, thanks for taking the time to contribute! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody else and are **greatly appreciated**.


Please read [our contribution guidelines](docs/CONTRIBUTING.md), and thank you for being involved!

## Authors & contributors

The original setup of this repository is by [Henry Weckermann](https://gitlab.com/hweckermann).


## Security

ProtecIoTnet follows good practices of security, but 100% security cannot be assured.
ProtecIoTnet is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the **MIT license**.

See [LICENSE](LICENSE) for more information.

## Acknowledgements

I would like to thank the SySS GmbH for funding and supporting my masters thesis and in turn also this project.
