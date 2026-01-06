**🌐 Network Analysis and Monitoring Tool**
Ek comprehensive web-based application jo network traffic analysis, multithreaded port scanning, aur real-time geographical visualization ko ek hi dashboard par pesh karti hai.

**🚀 Key Features**
**🛡️ Security & Scanning**
Multi-threaded Port Scanner: ThreadPoolExecutor ka istemal karte hue fast scanning jo target IPs aur custom port ranges ko support karti hai.

Vulnerability Assessment: Open ports ko identify karke potential security risks ka analysis.

Input Validation: Har user input (IP/Ports) ko strictly validate kiya jata hai performance aur security ke liye.

**📊 Monitoring & Analysis**
Real-time Packet Capture: 30-second window mein 1400+ packets tak process karne ki salahiyat.

Traffic Visualization: Leaflet.js (Migrated from Google Maps) ka istemal karte hue live connection mapping aur markers.

Heatmap: Traffic density ko heatmap ke zariye visualize karne ki facility.

Statistical Charts: Protocol distribution (TCP/UDP/TLS) aur country-wise traffic analysis Chart.js ke sath.

**🏗️ Architecture Overview**
Application ko modular design par banaya gaya hai:

Backend: Python Flask jo network operations aur data processing handle karta hai.

Frontend: Tailwind CSS aur JavaScript (AJAX) real-time data refresh ke liye.

Data Processing: Packets ko capture karke GeoJSON format mein convert karna taaki geographical mapping mumkin ho sake.

**🛠️ Technical Stack**
Framework: Flask (Python)

**Libraries:**

pyshark: Packet capture aur analysis ke liye.

geoip2: IP geolocation tracking ke liye.

socket & threading: Network operations aur concurrency ke liye.

Frontend: HTML5, Tailwind CSS, Leaflet.js, Chart.js.

**⚙️ Operational Requirements**
Python 3.x environment.

Network interface (NIC) access (Promiscuous mode recommended).

Wireshark/TShark installed (PyShark dependency).

GeoLite2-City database (.mmdb file).

**📝 How to Setup**
Clone the Repo:

Bash

git clone https://github.com/VishaHameed1/port_scanner.git
cd port_scanner
Install Dependencies:

Bash

pip install flask pyshark geoip2
Run the App:

Bash

python app.py
Access Dashboard: Browser mein http://127.0.0.1:5000 open karein.

**📈 Future Enhancements**
Machine learning-based threat detection.

Advanced packet analysis aur API integration.

Enhanced automated reporting system.
