# PATH XSS Scanner

## Overview  
**PATH XSS Scanner** is an advanced tool for detecting Cross-Site Scripting (XSS) vulnerabilities in the URL path of web applications. It automates scanning using **Selenium** and **Chrome WebDriver**, ensuring high accuracy in detecting vulnerabilities.

## Features  
- **Automated XSS Detection**: Scans URLs by injecting payloads in the path segment.  
- **Headless Browser Testing**: Uses **Selenium** and **Chrome** to detect XSS alerts.  
- **Multi-threaded Scanning**: Enhances speed using concurrent scanning.  
- **Detailed Scan Summary**: Displays the total number of scanned and vulnerable URLs.  
- **Saves Vulnerabilities**: Logs detected vulnerable URLs into a file for later analysis.  

## Prerequisites

- Python 3.6 or higher
- Google Chrome installed

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/hrishikeshY22/path-xss-scanner.git
    cd path-xss-scanner
    ```
    
2. Install the required Python packages:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Prepare a file containing the URLs you want to scan. Each URL should be on a new line.
2. Prepare a file containing the XSS payloads. Each payload should be on a new line.
3. Run the scanner:

    ```sh
    python deep.py
    ```

4. Follow the prompts to provide the paths to the URL and payload files.

## Example

Here's an example of how to use the PATH XSS Scanner:

1. Create a file named `urls.txt` with the following content:

    ```
    http://example.com/FUZZ
    http://test.com/search/FUZZ
    ```

2. Create a file named `payloads.txt` with the following content:

    ```
    <script>alert(1)</script>
    <img src=x onerror=alert(1)>
    ```

3. Run the scanner:

    ```sh
    python deep.py
    ```

4. Follow the prompts to provide the paths to `urls.txt` and `payloads.txt`.

## Results

The results will be saved in a file named `vulnerable_urls.txt` in the same directory.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Contact

For any questions or suggestions, please contact [Hrishikesh Y](https://github.com/hrishikeshY22).
