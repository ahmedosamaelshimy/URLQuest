# URLQuest

## Overview
a command-line tool for extracting various types of URLs from webpages and suggesting URLs for firewall whitelisting.


## Installation

URLQuest requires Python 3.x and the following dependencies:

- `argparse`
- `requests`
- `beautifulsoup4`

You can install the dependencies via pip:

```
pip install argparse requests beautifulsoup4
```

## Usage

To use URLQuest, run it from the command line with the desired options. Here's the basic usage:

```
python digurl.py [options] <url> 
```
### Command-Line Options

- **URL**: The URL of the webpage to inspect.
- **--skip-duplicates**: Skip duplicated domains while extracting URLs.
- **--extract-urls**: Extract normal URLs (HTTP/HTTPS).
- **--extract-all**: Extract all types of URLs.
- **--extract-js-urls**: Extract JavaScript URLs.
- **--extract-css**: Extract CSS URLs.
- **--extract-images**: Extract Image URLs.
- **--extract-fonts**: Extract Font URLs.
- **--extract-htmls**: Extract HTML URLs.
- **--suggest**: Suggests URLs to the user that can be added to the firewall whitelist. , Note: --extract-all option is a MUST
- **--extract-sec-headers**: Extract security headers.
- **--extract-robots-txt**: Extract the contents of the robots.txt file.
- **--extract-cookies**: Extract cookies from the HTTP response.
- **--extract-all-headers**: Extract all headers from the HTTP response.

| Option                 | Description                                                                                               |
|------------------------|-----------------------------------------------------------------------------------------------------------|
| URL                    | The URL of the webpage to inspect.                                                                        |
| `--skip-duplicates`    | Skip duplicated domains while extracting URLs.                                                            |
| `--extract-urls`       | Extract normal URLs (HTTP/HTTPS).                                                                         |
| `--extract-all`        | Extract all types of URLs.                                                                                |
| `--extract-js-urls`    | Extract JavaScript URLs.                                                                                  |
| `--extract-css`        | Extract CSS URLs.                                                                                         |
| `--extract-images`     | Extract Image URLs.                                                                                       |
| `--extract-fonts`      | Extract Font URLs.                                                                                        |
| `--extract-htmls`      | Extract HTML URLs.                                                                                        |
| `--suggest`            | Suggests URLs to add to the firewall whitelist. (Note: `--extract-all` option is a MUST)                |
| `--extract-sec-headers`| Extract security headers.                                                                                 |
| `--extract-robots-txt` | Extract the contents of the robots.txt file.                                                              |
| `--extract-cookies`    | Extract cookies from the HTTP response.                                                                    |
| `--extract-all-headers`| Extract all headers from the HTTP response.                                                               |



