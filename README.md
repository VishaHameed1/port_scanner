**🌐 Network Analysis and Monitoring Tool**
A comprehensive web-based application designed for real-time network traffic analysis, multi-threaded port scanning, and geographical traffic visualization within a unified dashboard.

**🚀 Key Features**
**🛡️ Security & Scanning**
Multi-threaded Port Scanner: Utilizes ThreadPoolExecutor for high-speed concurrent scanning, supporting custom port ranges and target IPs.

Vulnerability Assessment: Identifies open ports to help administrators analyze potential security entry points.

Robust Input Validation: Strictly validates all user inputs (IP addresses and port ranges) to ensure system stability and security.

**📊 Monitoring & Analysis**
Real-time Packet Capture: Capable of processing 1400+ packets within a 30-second capture window.

Traffic Visualization: Features an interactive world map using Leaflet.js (migrated from Google Maps) for live connection tracking.

Heatmap Integration: Visualizes traffic density across different geographical regions to identify high-activity zones.

Statistical Dashboards: Provides real-time charts for Protocol distribution (TCP/UDP/TLS) and Country-wise traffic analysis using Chart.js.

**🏗️ Architecture Overview**
The application follows a modular architecture:

Backend: Powered by Python Flask, managing core network operations, multithreading, and data processing.

Frontend: Built with Tailwind CSS and JavaScript (AJAX) to facilitate real-time data updates without page refreshes.

Data Pipeline: Captures raw network packets and converts them into GeoJSON format for seamless geographical mapping.

**🛠️ Technical Stack**
Framework: Flask (Python)

Network Libraries: * pyshark: For deep packet capture and analysis.

geoip2: For IP geolocation tracking.

socket & threading: For network operations and concurrency.

Frontend Technologies: HTML5, Tailwind CSS, Leaflet.js, Chart.js.

**⚙️ Operational Requirements**
Python 3.x environment.

Network Interface (NIC) Access: Promiscuous mode recommended for full packet capture.

Dependencies: Wireshark/TShark must be installed (required by PyShark).

Database: GeoLite2-City database (.mmdb file) for geolocation accuracy.

**📝 Setup Instructions**
Clone the Repository:

Bash

git clone https://github.com/VishaHameed1/port_scanner.git
cd port_scanner
Install Required Dependencies:

Bash

pip install flask pyshark geoip2
Run the Application:

Bash

python app.py
Access the Dashboard: Open http://127.0.0.1:5000 in your web browser.

**📑 Project Documentation**
For a detailed breakdown of the implementation, system metrics, and security considerations, refer to the: Technical Project Report (DOCX)

**📈 Future Enhancements**
Implementation of Machine Learning for automated threat detection.

Integration of an Advanced API for third-party security tools.

Enhanced automated reporting system for historical traffic data.
