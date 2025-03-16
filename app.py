import logging
from flask import Flask, render_template, request, jsonify, send_file
import socket
import threading
import time
import re
import os
import pyshark
import asyncio
from datetime import datetime
import geoip2.database
import json
from pathlib import Path
import ipaddress

# Initialize Flask app
app = Flask(__name__)

# Configure logging
def setup_logger():
    logger = logging.getLogger('network_analyzer')
    logger.setLevel(logging.DEBUG)
    
    # Prevent duplicate log handlers
    if not logger.handlers:
        # Create handlers
        file_handler = logging.FileHandler('network_analyzer.log')
        console_handler = logging.StreamHandler()
        
        # Create formatters and add it to handlers
        log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(log_format)
        console_handler.setFormatter(log_format)
        
        # Add handlers to the logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger

# Initialize logger
logger = setup_logger()

# Utility Functions
def is_valid_ip(ip):
    """Validate IP address format"""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def log_activity(message):
    """Log port scanner activity to file"""
    log_file = "port_scanner_log.txt"
    if not os.path.exists(log_file):
        with open(log_file, "w") as file:
            file.write("Port Scanner Log File\n")
            file.write("=" * 50 + "\n")
    
    with open(log_file, "a") as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp} - {message}\n")

# Network Capture Functions
def convert_pcap_to_geojson(pcap_file, output_file='network_traffic.geojson'):
    """Convert PCAP file to GeoJSON with IP geolocation data"""
    logger.info(f"Starting PCAP to GeoJSON conversion: {pcap_file} -> {output_file}")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    GEOIP_DB_PATH = Path('GeoLite2-City.mmdb')
    
    if not GEOIP_DB_PATH.exists():
        logger.error(f"GeoIP database not found at {GEOIP_DB_PATH}")
        raise FileNotFoundError(f"GeoIP database not found at {GEOIP_DB_PATH}")
    
    geojson_data = {
        "type": "FeatureCollection",
        "features": [],
        "metadata": {
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Network Traffic Analysis"
        }
    }
    
    seen_ips = set()
    packet_counter = 0
    
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            logger.debug("Successfully opened GeoIP reader")
            capture = pyshark.FileCapture(pcap_file, keep_packets=False)
            
            for packet in capture:
                packet_counter += 1
                
                if packet_counter % 100 == 0:
                    logger.debug(f"Processed {packet_counter} packets...")
                
                try:
                    if 'IP' in packet:
                        ip = packet.ip.src
                        
                        if ip not in seen_ips and not ipaddress.ip_address(ip).is_private:
                            seen_ips.add(ip)
                            
                            try:
                                response = reader.city(ip)
                                if response.location.latitude and response.location.longitude:
                                    feature = {
                                        "type": "Feature",
                                        "geometry": {
                                            "type": "Point",
                                            "coordinates": [
                                                response.location.longitude,
                                                response.location.latitude
                                            ]
                                        },
                                        "properties": {
                                            "ip": ip,
                                            "country": response.country.name if response.country else "Unknown",
                                            "city": response.city.name if response.city else "Unknown",
                                            "timestamp": packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S") if hasattr(packet, 'sniff_time') else None,
                                            "protocol": packet.highest_layer if hasattr(packet, 'highest_layer') else "unknown"
                                        }
                                    }
                                    geojson_data["features"].append(feature)
                                    logger.debug(f"Added feature for IP: {ip}")
                                    
                            except geoip2.errors.AddressNotFoundError:
                                logger.warning(f"IP {ip} not found in GeoIP database")
                                continue
                            
                except AttributeError as e:
                    logger.warning(f"Failed to process packet {packet_counter}: {str(e)}")
                    continue
                    
            capture.close()
            
    except Exception as e:
        logger.error(f"Error processing PCAP: {str(e)}")
        raise
    finally:
        loop.close()
        
    with open(output_file, 'w') as f:
        json.dump(geojson_data, f, indent=2)
    
    logger.info(f"Conversion completed. Processed {packet_counter} packets, found {len(seen_ips)} unique IPs")
    return packet_counter, len(seen_ips)

def capture_to_pcap(interface, output_file, duration=60):
    """Capture live traffic on specified interface"""
    logger.info(f"Starting capture on interface {interface} for {duration} seconds")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=f"{output_file}.pcap")
        packet_counter = 0
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_counter += 1
            current_time = time.time() - start_time
            
            if packet_counter % 100 == 0:
                logger.debug(f"{packet_counter} packets captured")
            
            if current_time >= duration:
                logger.info(f"Duration {duration}s reached")
                break
                
    except Exception as e:
        logger.error(f"Capture error: {str(e)}")
        raise
    finally:
        try:
            capture.close()
        except:
            pass
        loop.close()
    
    logger.info(f"Capture completed. Saved to {output_file}.pcap")

def process_conversion_in_thread(pcap_file, output_file):
    """Thread wrapper for PCAP conversion"""
    return convert_pcap_to_geojson(pcap_file, output_file)

# Port Scanner Functions
def scan_port(target, port, open_ports):
    """Scan a single port"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
    except:
        pass
    finally:
        sock.close()

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get-traffic-data')
def get_traffic_data():
    """API endpoint for traffic data with enhanced debugging"""
    logger.info("Request received for traffic data")
    
    try:
        geojson_dir = Path('geojson')
        if not geojson_dir.exists():
            logger.error("GeoJSON directory not found")
            return jsonify({'error': 'No traffic data available'}), 404
            
        geojson_files = list(geojson_dir.glob('network_traffic_*.geojson'))
        if not geojson_files:
            logger.warning("No GeoJSON files found in directory")
            return jsonify({'error': 'No traffic data available'}), 404
            
        latest_file = max(geojson_files, key=lambda x: x.stat().st_mtime)
        logger.info(f"Selected latest file: {latest_file}")
        
        with open(latest_file) as f:
            data = json.load(f)
            logger.debug(f"Raw GeoJSON content: {json.dumps(data, indent=2)}")
            
            # Validate GeoJSON structure
            if not isinstance(data, dict):
                logger.error("Invalid GeoJSON: root element is not an object")
                return jsonify({'error': 'Invalid GeoJSON format'}), 500
                
            if data.get('type') != 'FeatureCollection':
                logger.error("Invalid GeoJSON: not a FeatureCollection")
                return jsonify({'error': 'Invalid GeoJSON format'}), 500
                
            features = data.get('features', [])
            if not isinstance(features, list):
                logger.error("Invalid GeoJSON: features is not an array")
                return jsonify({'error': 'Invalid GeoJSON format'}), 500
                
            feature_count = len(features)
            logger.info(f"Successfully loaded GeoJSON with {feature_count} features")
            
            # Validate all features
            valid_features = []
            for idx, feature in enumerate(features):
                try:
                    # Check basic structure
                    if not isinstance(feature, dict):
                        logger.error(f"Invalid feature at index {idx}: not an object")
                        continue
                        
                    if not all(k in feature for k in ['type', 'geometry', 'properties']):
                        logger.error(f"Invalid feature at index {idx}: missing required fields")
                        continue
                        
                    geometry = feature.get('geometry', {})
                    if not all(k in geometry for k in ['type', 'coordinates']):
                        logger.error(f"Invalid feature at index {idx}: invalid geometry")
                        continue
                        
                    coordinates = geometry.get('coordinates', [])
                    if len(coordinates) != 2 or not all(isinstance(x, (int, float)) for x in coordinates):
                        logger.error(f"Invalid feature at index {idx}: invalid coordinates {coordinates}")
                        continue
                        
                    properties = feature.get('properties', {})
                    if not isinstance(properties, dict):
                        logger.error(f"Invalid feature at index {idx}: invalid properties")
                        continue
                        
                    # Add debug info to properties
                    properties['_debug'] = {
                        'feature_index': idx,
                        'coord_type': [type(x).__name__ for x in coordinates]
                    }
                    
                    valid_features.append(feature)
                    logger.debug(f"Validated feature {idx}: {feature['properties'].get('ip', 'unknown IP')}")
                    
                except Exception as e:
                    logger.error(f"Error processing feature {idx}: {str(e)}")
                    continue
            
            # Update features with only valid ones
            data['features'] = valid_features
            
            # Add metadata for frontend debugging
            data['_debug'] = {
                'timestamp': datetime.now().isoformat(),
                'feature_count': len(valid_features),
                'file_path': str(latest_file),
                'invalid_features': feature_count - len(valid_features)
            }
            
            logger.info(f"Returning {len(valid_features)} valid features out of {feature_count} total")
            return jsonify(data)
            
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Invalid JSON in GeoJSON file'}), 500
    except Exception as e:
        logger.error(f"Error retrieving traffic data: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/traffic-map')
def traffic_map():
    """Render traffic map visualization page with debugging info"""
    logger.info("Accessing traffic map page")
    
    geojson_dir = Path('geojson')
    geojson_files = []
    file_info = []
    
    if geojson_dir.exists():
        logger.debug(f"Scanning directory: {geojson_dir}")
        for file in geojson_dir.glob('network_traffic_*.geojson'):
            geojson_files.append(file.name)
            try:
                with open(file) as f:
                    data = json.load(f)
                    feature_count = len(data.get('features', []))
                    file_info.append({
                        'name': file.name,
                        'size': file.stat().st_size,
                        'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                        'features': feature_count
                    })
            except Exception as e:
                logger.error(f"Error reading file {file}: {str(e)}")
                
        logger.info(f"Found {len(geojson_files)} GeoJSON files")
        logger.debug(f"File details: {json.dumps(file_info, indent=2)}")
    else:
        logger.warning("GeoJSON directory does not exist")
        
    return render_template(
        'traffic_map.html',
        geojson_files=geojson_files,
        debug_info={'files': file_info}
    )

@app.route('/debug-geojson')
def debug_geojson():
    """Debug endpoint for GeoJSON data"""
    try:
        geojson_dir = Path('geojson')
        if not geojson_dir.exists():
            return jsonify({'error': 'GeoJSON directory not found'}), 404
            
        geojson_files = list(geojson_dir.glob('network_traffic_*.geojson'))
        if not geojson_files:
            return jsonify({'error': 'No GeoJSON files found'}), 404
            
        latest_file = max(geojson_files, key=lambda x: x.stat().st_mtime)
        
        with open(latest_file) as f:
            data = json.load(f)
            
        return jsonify({
            'file_info': {
                'path': str(latest_file),
                'size': latest_file.stat().st_size,
                'modified': datetime.fromtimestamp(latest_file.stat().st_mtime).isoformat()
            },
            'data_info': {
                'type': data.get('type'),
                'feature_count': len(data.get('features', [])),
                'sample_coordinates': data['features'][0]['geometry']['coordinates'] if data.get('features') else None,
                'sample_properties': data['features'][0]['properties'] if data.get('features') else None
            },
            'raw_data': data
        })
    except Exception as e:
        logger.error(f"Error in debug-geojson endpoint: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/convert_capture', methods=['POST'])
def convert_capture():
    """Handle PCAP to GeoJSON conversion"""
    logger.info("Received capture conversion request")
    
    try:
        captures_dir = Path('captures')
        if not captures_dir.exists():
            logger.error("Captures directory not found")
            return jsonify({'error': 'No captures directory found'}), 404
            
        capture_files = list(captures_dir.glob('capture_*.pcap'))
        if not capture_files:
            logger.warning("No capture files found in directory")
            return jsonify({'error': 'No capture files found'}), 404
            
        latest_capture = max(capture_files, key=lambda x: x.stat().st_mtime)
        logger.info(f"Selected latest capture file: {latest_capture}")
        
        output_file = f"geojson/network_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.geojson"
        os.makedirs('geojson', exist_ok=True)
        
        logger.debug(f"Starting conversion process: {latest_capture} -> {output_file}")
        packets_processed, unique_ips = process_conversion_in_thread(
            str(latest_capture),
            output_file
        )
        
        logger.info(f"Conversion completed: {packets_processed} packets processed, {unique_ips} unique IPs")
        
        return jsonify({
            'status': 'success',
            'message': 'Conversion completed successfully',
            'details': {
                'input_file': str(latest_capture),
                'output_file': output_file,
                'packets_processed': packets_processed,
                'unique_ips': unique_ips
            }
        })
        
    except Exception as e:
        logger.error(f"Conversion failed: {str(e)}", exc_info=True)
        return jsonify({'error': f'Conversion failed: {str(e)}'}), 500

@app.route('/scan', methods=['POST'])
def scan():
    """Handle port scanning requests"""
    data = request.get_json()
    target = data.get('target')
    start_port = data.get('start_port')
    end_port = data.get('end_port')
    
    # Validate input
    if not all([target, start_port, end_port]):
        return jsonify({'error': 'All fields must be filled!'}), 400
        
    if not is_valid_ip(target):
        return jsonify({'error': 'Please enter a valid IP address!'}), 400
        
    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        return jsonify({'error': 'Please enter valid port numbers!'}), 400
        
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return jsonify({'error': 'Invalid port range!'}), 400
        
    # Start scanning
    start_time = time.time()
    log_activity(f"Scanning started for target: {target}, Ports: {start_port}-{end_port}")
    
    open_ports = []
    threads = []
    
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target, port, open_ports))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        thread.join()
        
    end_time = time.time()
    elapsed_time = round(end_time - start_time, 2)
    
    if not open_ports:
        log_activity(f"No open ports found for target: {target}, Ports: {start_port}-{end_port}")
    else:
        for port in open_ports:
            log_activity(f"Port {port} is open on target: {target}")
            
    log_activity(f"Scanning completed for target: {target}, Time elapsed: {elapsed_time} seconds")
    
    return jsonify({
        'open_ports': sorted(open_ports),
        'elapsed_time': elapsed_time,
        'message': 'Scan completed successfully'
    })

@app.route('/capture')
def capture_page():
    """Render capture configuration page"""
    interfaces = ['Wi-Fi', 'Ethernet', 'eth0', 'wlan0']
    return render_template('capture.html', interfaces=interfaces)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    """Start packet capture on specified interface"""
    data = request.get_json()
    interface = data.get('interface')
    duration = int(data.get('duration', 60))
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"captures/capture_{timestamp}"
    
    os.makedirs('captures', exist_ok=True)
    
    try:
        # Start capture in a thread
        capture_thread = threading.Thread(
            target=capture_to_pcap,
            args=(interface, output_file, duration)
        )
        capture_thread.start()
        
        logger.info(f"Started capture on interface {interface} for {duration} seconds")
        return jsonify({
            'status': 'success',
            'message': 'Capture started successfully',
            'output_file': f"capture_{timestamp}.pcap"
        })
    except Exception as e:
        logger.error(f"Failed to start capture: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to start capture: {str(e)}'
        }), 500

@app.route('/download_capture/<filename>')
def download_capture(filename):
    """Download captured PCAP file"""
    try:
        logger.info(f"Downloading capture file: {filename}")
        return send_file(
            f'captures/{filename}',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Failed to download file: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to download file: {str(e)}'
        }), 404

if __name__ == '__main__':
    logger.info("Starting Flask application")
    app.run(debug=True)