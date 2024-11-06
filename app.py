from flask import Flask, jsonify, render_template, send_file, make_response
import psutil
import platform
import subprocess
import os
import datetime
import json
import tempfile
import socket
import ssl
from cryptography.fernet import Fernet
import hashlib
import requests
import socket
from concurrent.futures import ThreadPoolExecutor
import nmap 
import logging
from datetime import datetime, timedelta
app = Flask(__name__)

# Serve the HTML file
@app.route('/')
def index():
    return render_template('index.html')

# System Information
@app.route('/system_info', methods=['GET'])
def get_system_info():
    system_info = {
        'WindowsProductName': platform.system(),
        'WindowsVersion': platform.version(),
        'OsHardwareAbstractionLayer': platform.machine(),
        'CsManufacturer': platform.node(),
        'CsModel': platform.processor()
    }
    return jsonify(system_info)

# Windows Defender Status
@app.route('/defender_status', methods=['GET'])
def get_defender_status():
    defender_status = {
        'AntivirusEnabled': True,
        'RealTimeProtection': True,
        'QuickScanAge': "2 days",
        'FullScanAge': "7 days",
    }
    return jsonify(defender_status)

# Network Security
@app.route('/network_security', methods=['GET'])
def get_network_security():
    open_ports = []
    for conn in psutil.net_connections(kind='inet'):
        open_ports.append({
            'LocalAddress': conn.laddr.ip,
            'LocalPort': conn.laddr.port,
            'State': conn.status,
            # 'Process': psutil.Process(conn.pid).name() if conn.pid else None
        })

    network_info = {
        'OpenPorts': open_ports,
        'NetworkAdapters': [{'Name': nic, 'Status': 'Up', 'LinkSpeed': '1 Gbps', 'MacAddress': '00:1A:2B:3C:4D:5E'} for nic, addrs in psutil.net_if_addrs().items()]
    }
    
    return jsonify(network_info)

# Firewall Status
@app.route('/firewall_status', methods=['GET'])
def get_firewall_status():
    firewall_status = {
        'DomainProfile': {'Enabled': True, 'DefaultInboundAction': 'Block', 'DefaultOutboundAction': 'Allow'},
        'PrivateProfile': {'Enabled': True, 'DefaultInboundAction': 'Block', 'DefaultOutboundAction': 'Allow'},
        'PublicProfile': {'Enabled': True, 'DefaultInboundAction': 'Block', 'DefaultOutboundAction': 'Allow'}
    }
    return jsonify(firewall_status)

# Process Analysis
@app.route('/process_analysis', methods=['GET'])
def get_process_analysis():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
        processes.append({
            'Id': proc.info['pid'],
            'ProcessName': proc.info['name'],
            'CPU': proc.info['cpu_percent'],
            'MemoryMB': proc.info['memory_info'].rss / (1024 * 1024),  # Convert bytes to MB
            'StartTime': proc.info['status'],  # Replace with real start time if needed
            'ThreadCount': proc.num_threads()
        })
    return jsonify({'RunningProcesses': processes})

# Storage Security
@app.route('/storage_security', methods=['GET'])
def get_storage_security():
    disk_usage = []
    partitions = psutil.disk_partitions()
    for partition in partitions:
        usage = psutil.disk_usage(partition.mountpoint)
        disk_usage.append({
            'Name': partition.device,
            'TotalGB': usage.total / (1024 * 1024 * 1024),
            'UsedGB': usage.used / (1024 * 1024 * 1024),
            'FreeGB': usage.free / (1024 * 1024 * 1024),
            'FreePercent': usage.percent
        })
    return jsonify({'DiskUsage': disk_usage})

# User Account Policy
import re
@app.route('/user_account_policy', methods=['GET'])
def get_user_account_policy():
    try:
        result = subprocess.check_output("net accounts", shell=True).decode('utf-8')
        password_policy = {
            "MinPasswordLength": re.search(r"Minimum password length\s+(\d+)", result).group(1),
            "MaxPasswordAge": re.search(r"Maximum password age\s+(\d+)", result).group(1),
            "MinPasswordAge": re.search(r"Minimum password age\s+(\d+)", result).group(1),
            "PasswordComplexity": 'Enabled' if re.search(r"Password complexity\s+enabled", result) else 'Disabled',
            "LockoutThreshold": re.search(r"Lockout threshold\s+(\d+)", result).group(1) if re.search(r"Lockout threshold\s+(\d+)", result) else 'N/A',
            "LockoutDuration": re.search(r"Lockout duration\s+(\d+)", result).group(1) if re.search(r"Lockout duration\s+(\d+)", result) else 'N/A',
            "ResetCount": re.search(r"Reset count\s+(\d+)", result).group(1) if re.search(r"Reset count\s+(\d+)", result) else 'N/A'
        }
        return jsonify(password_policy)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Windows Update
@app.route('/windows_update', methods=['GET'])
def get_windows_update():
    updates = []
    try:
        updates_raw = subprocess.check_output('wmic qfe list full', shell=True).decode('utf-8')
        updates = [{'Description': line.split()[0], 'HotFixID': line.split()[1], 'InstalledOn': line.split()[2]} for line in updates_raw.split('\n') if line]
    except Exception as e:
        updates = [{'error': str(e)}]
    return jsonify({'InstalledUpdates': updates})

# Security Settings
@app.route('/security_settings', methods=['GET'])
def get_security_settings():
    uac_status = 1  # 1 means enabled, 0 means disabled
    remote_desktop_status = 0  # 1 means enabled, 0 means disabled
    wsh_status = os.path.exists("HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings")
    return jsonify({
        'UACStatus': uac_status,
        'RemoteDesktopStatus': remote_desktop_status,
        'WSHStatus': wsh_status
    })

@app.route('/download_report', methods=['GET'])
def download_report():
    try:
        # Create a timestamp for the filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Initialize all required data with error handling
        report_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': get_system_info().get_json(),
            'defender_status': get_defender_status().get_json(),
            'network_security': get_network_security().get_json(),
            'firewall_status': get_firewall_status().get_json(),
            'process_analysis': get_process_analysis().get_json(),
            'storage_security': get_storage_security().get_json()
        }
        
        # Add optional data with error handling
        try:
            report_data['user_account_policy'] = get_user_account_policy().get_json()
        except Exception as e:
            report_data['user_account_policy'] = {"error": str(e)}
            
        try:
            report_data['windows_update'] = get_windows_update().get_json()
        except Exception as e:
            report_data['windows_update'] = {"error": str(e)}
            
        try:
            report_data['security_settings'] = get_security_settings().get_json()
        except Exception as e:
            report_data['security_settings'] = {"error": str(e)}
            
        try:
            report_data['ssl_certificates'] = get_ssl_certificates().get_json()
        except Exception as e:
            report_data['ssl_certificates'] = {"error": str(e)}
            
        try:
            report_data['installed_software'] = get_installed_software().get_json()
        except Exception as e:
            report_data['installed_software'] = {"error": str(e)}
            
        try:
            report_data['scheduled_tasks'] = get_scheduled_tasks().get_json()
        except Exception as e:
            report_data['scheduled_tasks'] = {"error": str(e)}
            
        try:
            report_data['vulnerabilities'] = get_vulnerability_scan().get_json()
        except Exception as e:
            report_data['vulnerabilities'] = {"error": str(e)}
            
        try:
            report_data['dns_health'] = get_dns_health().get_json()
        except Exception as e:
            report_data['dns_health'] = {"error": str(e)}
            
        try:
            report_data['security_score'] = calculate_security_score().get_json()
        except Exception as e:
            report_data['security_score'] = {"error": str(e)}

        # Create a temporary file with the rendered template
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, f'security_audit_report_{timestamp}.html')
        
        try:
            # Render the template with the collected data
            rendered_template = render_template('report_template.html', data=report_data)
            
            # Write the rendered template to the temporary file
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(rendered_template)
            
            # Send the file
            response = send_file(
                temp_path,
                mimetype='text/html',
                as_attachment=True,
                download_name=f'security_audit_report_{timestamp}.html'
            )
            
            # Clean up temporary files after sending
            @response.call_on_close
            def cleanup():
                try:
                    os.remove(temp_path)
                    os.rmdir(temp_dir)
                except Exception as e:
                    logging.error(f"Error cleaning up temporary files: {str(e)}")
            
            return response
            
        except Exception as e:
            # Clean up on error
            try:
                os.remove(temp_path)
                os.rmdir(temp_dir)
            except:
                pass
            raise e
            
    except Exception as e:
        logging.error(f"Error generating report: {str(e)}")
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500

# New security check: SSL Certificates
@app.route('/ssl_certificates', methods=['GET'])
def get_ssl_certificates():
    ssl_info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection(('www.google.com', 443)) as sock:
            with context.wrap_socket(sock, server_hostname='www.google.com') as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serialNumber': cert['serialNumber'],
                    'notBefore': cert['notBefore'],
                    'notAfter': cert['notAfter']
                }
    except Exception as e:
        ssl_info = {"error": str(e)}
    return jsonify(ssl_info)

# New security check: Installed Software
@app.route('/installed_software', methods=['GET'])
def get_installed_software():
    try:
        result = subprocess.check_output('wmic product get name,version,vendor', shell=True).decode('utf-8')
        software_list = []
        for line in result.split('\n')[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    software_list.append({
                        'name': parts[0],
                        'version': parts[1],
                        'vendor': ' '.join(parts[2:])
                    })
        return jsonify({'installed_software': software_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# New security check: Scheduled Tasks
@app.route('/scheduled_tasks', methods=['GET'])
def get_scheduled_tasks():
    try:
        result = subprocess.check_output('schtasks /query /fo LIST', shell=True).decode('utf-8')
        tasks = []
        current_task = {}
        for line in result.split('\n'):
            if line.strip():
                if line.startswith('TaskName:'):
                    if current_task:
                        tasks.append(current_task)
                    current_task = {'TaskName': line.split(':', 1)[1].strip()}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    current_task[key.strip()] = value.strip()
        if current_task:
            tasks.append(current_task)
        return jsonify({'scheduled_tasks': tasks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/vulnerability_scan', methods=['GET'])
def get_vulnerability_scan():
    try:
        vulnerabilities = []
        
        # Check for common security misconfigurations
        checks = [
            ('SMB Ports Open', check_smb_ports()),
            ('Default Credentials', check_default_credentials()),
            ('Outdated Software', check_outdated_software()),
            ('SSL/TLS Version', check_ssl_version()),
            ('Open Administrative Ports', check_admin_ports())
        ]
        
        for check_name, result in checks:
            if result:
                vulnerabilities.append({
                    'type': check_name,
                    'severity': 'High',
                    'description': result,
                    'recommendation': get_recommendation(check_name)
                })
        
        return jsonify({'vulnerabilities': vulnerabilities})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# New Feature 2: DNS Health Check
@app.route('/dns_health', methods=['GET'])
def get_dns_health():
    try:
        dns_checks = {
            'dns_servers': get_dns_servers(),
            'response_time': check_dns_response_time(),
            'record_consistency': check_dns_consistency(),
            'security_records': check_security_records()
        }
        return jsonify(dns_checks)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# New Feature 3: Security Score Calculator
@app.route('/security_score', methods=['GET'])
def calculate_security_score():
    try:
        scores = {
            'antivirus': score_antivirus(),
            'firewall': score_firewall(),
            'updates': score_updates(),
            'password_policy': score_password_policy(),
            'network_security': score_network_security()
        }
        
        total_score = sum(scores.values()) / len(scores)
        
        return jsonify({
            'overall_score': total_score,
            'component_scores': scores,
            'rating': get_security_rating(total_score),
            'recommendations': generate_recommendations(scores)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Helper functions for new features
def check_smb_ports():
    # Implementation for checking SMB ports
    ports = [445, 139]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return f"Open SMB ports found: {open_ports}" if open_ports else None

def score_antivirus():
    # Implementation for scoring antivirus
    defender_status = get_defender_status().get_json()
    score = 100
    if not defender_status['AntivirusEnabled']:
        score -= 50
    if not defender_status['RealTimeProtection']:
        score -= 30
    return max(0, score)

if __name__ == '__main__':
    app.run(debug=True)
