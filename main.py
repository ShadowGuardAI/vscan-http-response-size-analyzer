import argparse
import requests
import logging
import sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes HTTP response sizes to detect anomalies.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-t", "--threshold", type=int, default=100000, help="Threshold size (in bytes) for flagging large responses. Default: 100000")
    parser.add_argument("-w", "--wordlist", type=str, help="Path to a wordlist for directory brute-forcing.")
    parser.add_argument("-d", "--detect_tech", action="store_true", help="Attempt to detect the technology stack used by the website.")
    return parser.parse_args()


def get_response_size(url):
    """
    Fetches the HTTP response size for a given URL.

    Args:
        url (str): The URL to check.

    Returns:
        int: The content length of the response, or -1 if an error occurs.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return len(response.content)  # Use content to get actual size. header Content-Length can be unreliable
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return -1


def analyze_response_size(url, threshold):
    """
    Analyzes the HTTP response size and flags anomalies.

    Args:
        url (str): The URL to analyze.
        threshold (int): The threshold size (in bytes) for flagging large responses.
    """
    size = get_response_size(url)
    if size == -1:
        return

    logging.info(f"Response size for {url}: {size} bytes")

    if size > threshold:
        logging.warning(f"Large response size detected for {url}. Size: {size} bytes, Threshold: {threshold} bytes. Potential data exfiltration or DoS vulnerability.")


def directory_bruteforce(url, wordlist_path):
    """
    Performs a basic directory brute-force using a wordlist.

    Args:
        url (str): The base URL.
        wordlist_path (str): Path to the wordlist file.
    """
    try:
        with open(wordlist_path, 'r') as f:
            directories = [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
        return

    logging.info(f"Starting directory brute-force on {url} using {wordlist_path}")
    for directory in directories:
        target_url = f"{url.rstrip('/')}/{directory}"
        size = get_response_size(target_url)

        if size != -1:
            logging.info(f"{target_url}: Response size {size} bytes")

def detect_technology(url):
    """
    Attempts to detect the technology stack used by the website.

    Args:
        url (str): The URL to analyze.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for common indicators. This can be expanded.
        if "WordPress" in response.text:
            logging.info("Technology Detection: WordPress detected (based on HTML content).")
        if response.headers.get("X-Powered-By"):
            logging.info(f"Technology Detection: X-Powered-By header: {response.headers.get('X-Powered-By')}")

        # Meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator':
                logging.info(f"Technology Detection: Generator meta tag: {meta.get('content')}")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error detecting technology for {url}: {e}")



def validate_url(url):
    """
    Validates that the input URL is properly formatted.
    Args:
        url (str): the url to validate.
    Returns:
        boolean: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) # Check for scheme (http/https) and netloc (domain)
    except:
        return False


def main():
    """
    Main function to execute the HTTP response size analyzer.
    """
    args = setup_argparse()

    if not validate_url(args.url):
        logging.error("Invalid URL provided.  Please ensure the URL starts with http:// or https://")
        sys.exit(1)

    analyze_response_size(args.url, args.threshold)

    if args.wordlist:
        directory_bruteforce(args.url, args.wordlist)

    if args.detect_tech:
        detect_technology(args.url)



if __name__ == "__main__":
    main()

# Example Usage:
# python vscan-http-response-size-analyzer.py https://www.example.com
# python vscan-http-response-size-analyzer.py https://www.example.com -t 50000
# python vscan-http-response-size-analyzer.py https://www.example.com -w wordlist.txt
# python vscan-http-response-size-analyzer.py https://www.example.com -d
# python vscan-http-response-size-analyzer.py https://www.example.com -w wordlist.txt -d