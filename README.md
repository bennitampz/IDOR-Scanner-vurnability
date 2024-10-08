# IDOR and MFLAC Scanning Tool

## Overview

This tool is designed to detect **Insecure Direct Object Reference (IDOR)** and **Mass Function Level Access Control (MFLAC)** vulnerabilities in web applications. It automates the crawling of websites, tests for potential vulnerabilities, and generates detailed reports.

## Features

- Automated crawling of web applications
- IDOR and MFLAC vulnerability detection
- Detailed reporting in JSON and CSV formats
- Configurable parameters for flexibility

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Technologies Used](#technologies-used)
- [Contributing](#contributing)
- [License](#license)

## Installation
1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/IDOR-MFLAC-Scanner.git
   cd IDOR-MFLAC-Scanner

## Configuration
1. **Sample config.yaml**

log_level: INFO

start_url: "http://example.com/resource"

test_parameters:

  - "id"
    
test_values:

  - "1"
    
  - "2"
    
output_file: "scan_results"

output_format: "json"  # Options: json, csv

depth: 2

user_agents:

  - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"

retries: 3

timeout: 10


Configuration Options

log_level: Set the logging level (e.g., DEBUG, INFO, WARNING).

start_url: The initial URL to begin crawling.

test_parameters: List of parameters to test for vulnerabilities.

test_values: List of values corresponding to the parameters.

output_file: The name of the output file (without extension).

output_format: Format of the output file (json or csv).

depth: Depth of crawling (number of levels to explore).

user_agents: List of user-agent strings to use for requests.

retries: Number of retries for failed requests.

timeout: Timeout for HTTP requests in seconds.

## Usage ##

1. **Usage**
Run the Tool

Execute the following command to start the scanning process:

python3 IDOR.py --config config.yaml

2. **View Results**

After the scan is complete, the results will be saved in the specified output file format (JSON or CSV). Additionally, a detailed vulnerability report will be generated.

## Technologies Used ##
Python: Main programming language used for development.

aiohttp: For making asynchronous HTTP requests.

BeautifulSoup: For parsing HTML and extracting links.

YAML: For configuration management.

## Contributing ##

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License ##
This project is licensed under the MIT License. See the LICENSE file for more details.
