KeyLoggerDetect

Status: Beta Version 1.1

Author: ZakaLino

KeyLoggerDetect+ is a Python-based application designed to detect keyloggers and other suspicious activities on a user's system. It utilizes various methods, including process name scanning and hash comparisons, to identify potentially malicious processes. The application also monitors network activity for known malicious IP addresses and provides system usage analysis.

Features:

Standard Scan: Detects suspicious processes based on a predefined list and scraped data from trusted sources.
Hash Scan: Allows users to input a SHA256 hash to find matching running processes.
Network Activity Monitor: Monitors active network connections and checks against a regularly updated list of malicious IPs from Spamhaus.
System Usage Analysis: Provides insights into CPU and memory usage, alerting users of potential high usage concerns.

Project Status

This project is still in beta. As my first project, I am eager to receive reviews and constructive feedback. Your insights can help me improve this tool and my programming skills. I appreciate any suggestions on what features or improvements you would like to see!


INSTALATION 

Clone the repository
     
     git clone https://github.com/ZakaLino/KeyLoggerDetect.git

Navigate to the project directory:

     cd KeyLoggerDetect

Install the required libraries (e.g., psutil, beautifulsoup4, requests):

     pip install -r requirements.txt

Run the application:

     python main.py


Upon running the application, you will be greeted with an ASCII art logo and a menu. Follow the prompts to perform various scans and analyses.

_______________________________________________________________________________________________________________________________________________________

Contributions are welcome! If you have suggestions or improvements, feel free to open an issue or submit a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for more details.

Feel free to customize any part of it further to match your style or additional details you'd like to include!
