from flask import Flask, jsonify, render_template, request, send_file, redirect, url_for
app = Flask(__name__, static_url_path="/static")
from flask import Flask, request, jsonify, render_template, Response
from flask_socketio import SocketIO
from flask_sockets import Sockets
import json
import numpy as np
import pandas as pd
import joblib
from flask_cors import CORS
import os
from app_factory import create_app
from flask import Blueprint, jsonify
from flask import Flask, render_template, send_file
import pdfkit 
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
 
import random
import json
import numpy as np
import pandas as pd
import joblib
from flask_cors import CORS
import os
from flask import Blueprint, jsonify
from sklearn.linear_model import LogisticRegression
import requests
import pickle
from flask import Flask, jsonify, render_template, request
from scapy.all import *
import firebase_admin
from firebase_admin import db, credentials
import subprocess
import datetime 
import pyodbc
from sklearn.preprocessing import LabelEncoder
from flask_socketio import SocketIO
from flask_socketio import SocketIO, emit

app = Flask(__name__)
main = Blueprint('main', __name__)
 
socketio = SocketIO(app) 
 # Initialize Firebase Admin SDK
# Initialize the default Firebase app
cred_default = credentials.Certificate('credentials.json')
default_app = firebase_admin.initialize_app(cred_default, {
    'databaseURL': 'https://ddos-real-time-deduction-default-rtdb.firebaseio.com/'
})

# Initialize the secondary Firebase app
cred_secondary = credentials.Certificate('credentials_secondary.json')
secondary_app = firebase_admin.initialize_app(cred_secondary, {
    'databaseURL': 'https://ddos-real-time-deduction-secondary-rtdb.firebaseio.com/'
}, name='secondary')

# Verify that the default app has been initialized
if not firebase_admin.get_app():
    firebase_admin.initialize_app(cred_default, {
        'databaseURL': 'https://ddos-real-time-deduction-default-rtdb.firebaseio.com/'
    })

# Verify that the secondary app has been initialized
if not firebase_admin.get_app('secondary'):
    firebase_admin.initialize_app(cred_secondary, {
        'databaseURL': 'https://ddos-real-time-deduction-secondary-rtdb.firebaseio.com/'
    }, name='secondary')
# Reference to the database
ref = db.reference('network_traffic')
app, jwt = create_app()
# Load the trained DDoS detection model
model_path = r'best_model.pkl'
model = joblib.load(model_path)
app.config['SECRET_KEY'] = 'secret!'
sockets = SocketIO(app)  # Capitalized SocketIO and parentheses
CORS(app, resources={r"/api*":{"origins":"*"} } )
# Initialize logging
logging.basicConfig(filename='attack_logs.txt', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')
# Define a global list to store attack details
attacks = []
#firebase_admin.initialize_app(cred, {
    #'databaseURL': 'https://ddos-real-time-deduction-default-rtdb.firebaseio.com/'})
 
# Reference to the database
#ref = db.reference('/')
 
ref = db.reference('network_traffic')
@main.route('/data')
def get_data():
    docs = db.collection(u'collection_name').stream()
    data = [doc.to_dict() for doc in docs]
    return jsonify(data), 200
# Load the trained DDoS detection model

model_path = r'best_model.pkl'
 
model = joblib.load(model_path)

blacklist = {'suspicious_ip1', 'suspicious_ip2'}
request_counts = {}
HIGH_TRAFFIC_THRESHOLD = 1000
application = Flask(__name__)

sockets = SocketIO(application, engineio_logger=True, async_mode='threading',
                   firebase_app=default_app)
@app.route('/')
def index():
    return render_template('index.html')
# Initialize the Socket.IO instance
 
# Define the Socket.IO event handler
@sockets.on('ddos_detection')
def handle_ddos_detection(data):
    print(f"Received ddos_detection event: {data}")
    # Send the message back to the client
    sockets.emit('ddos_detection', data)

 
# Flask route for capturing network traffic
@app.route('/capture', methods=['POST'])
def capture():
    try:
        # Start packet capture on specified interface (e.g., eth0)
        sniff(iface='eth0', prn=packet_capture, store=0, filter="ip")
        return jsonify({'message': 'Packet capture started successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500       

# Packet capture and analysis function
def packet_capture(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        # Store packet information in Firebase Realtime Database
        ref.push({
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'protocol': protocol
        })
@main.route('/attacks')
def get_attacks():
    attacks = [
        {'timestamp': '2023-04-01 10:30:00', 'source_ip': '192.168.1.1', 'attack_type': 'UDP Flood'},
        {'timestamp': '2023-04-01 11:05:00', 'source_ip': '192.168.1.2', 'attack_type': 'HTTP Flood'},
        # Add more attacks as needed
    ]
    return jsonify(attacks)
# Flask route for anomaly detection
@app.route('/detect_anomalies', methods=['POST'])
def detect_anomalies():
    try:
        # Retrieve network traffic data from Firebase
        network_traffic = ref.get()
        
        # Preprocess data
        X = []  # Features
        for key, value in network_traffic.items():
            X.append([value['source_ip'], value['destination_ip'], value['protocol']])
        X = np.array(X)
        
        # Predict anomalies using pre-trained model
        anomalies = model.predict(X)
        
        # Identify indices of anomalies
        anomaly_indices = np.where(anomalies == 1)[0]  # Assuming 1 indicates anomaly
        
        if len(anomaly_indices) > 0:
            # Trigger alerts or mitigation procedures
            alert_message = f"Anomalies detected at indices: {anomaly_indices.tolist()}"
            # Implement alerting mechanism (e.g., send email, log to file, etc.)
            print(alert_message)
            return jsonify({'message': alert_message, 'anomaly_indices': anomaly_indices.tolist()}), 200
        else:
            return jsonify({'message': 'No anomalies detected'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
 
@app.route('/api/anomaly-status')
def get_anomaly_status():
    # Retrieve the current anomaly count from your data source
    # For example, you could query your Firebase Realtime Database or any other data source
    anomalies = ref.child('anomaly_count').get()
    if anomalies is None:
        return jsonify({'anomaly_count': 0}), 200
    else:
        return jsonify({'anomaly_count': anomalies}), 200
        return render_template('detect_anomalies.html')
# Flask route for handling incoming traffic
@app.route('/handle_traffic', methods=['POST'])
def handle_traffic():
 
    try:
        # Retrieve request data. Ensure you're using Flask and have imported 'request'
        data = request.get_json()  # Using get_json() is a more common approach
        
        # It's a good practice to check if 'data' is not None
        if data is None:
            return jsonify({'error': 'Bad request, no data provided'}), 400

        # Extract 'source_ip' safely with .get() to avoid KeyError if 'source_ip' is missing
        source_ip = data.get('source_ip')
        if source_ip is None:
            return jsonify({'error': 'Bad request, source IP missing'}), 400

        # Check if source IP is in blacklist
        if source_ip in blacklist:
            # Apply filtering: Drop the request or return an error response
            return jsonify({'error': 'Access denied due to suspicious activity'}), 403
        
        # Handle the request normally if the IP is not blacklisted
        # This part of your code was missing. You need to decide how to handle non-blacklisted requests.
        return jsonify({'message': 'Request accepted'}), 200

    except Exception as e:
        # Catching general exceptions is not always a good practice, but it's okay for debugging.
        # Consider catching specific exceptions for production code.
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
    if is_ddos_attack_detected():
        # If so, redirect traffic to the scrubbing center
        redirect_to_scrubbing_center(data)
        # Return a success message and HTTP 200 status code
        return jsonify({'message': 'Traffic redirected to scrubbing center'}), 200
    
    # If no DDoS attack is detected, check if traffic volume is high
    if is_high_traffic_volume():
        # If traffic is high, scale resources to handle the load
        scale_resources()

    # Implement your request processing logic here
    # For example, you could add code to process the request and generate a response

    return jsonify({'message': 'Request processed successfully'}), 200

# Initialize a list to store attack details
attacks = []
def preprocess_data(network_traffic):
    # Check if network_traffic is not None and not empty
    if network_traffic:
        source_ips = [value['source_ip'] for key, value in network_traffic.items()]
        destination_ips = [value['destination_ip'] for key, value in network_traffic.items()]
        protocols = [value['protocol'] for key, value in network_traffic.items()]

        # Convert IPs to numerical format (simplified example, consider a more appropriate conversion)
        source_ips_numeric = [int(ipaddress.ip_address(ip)) for ip in source_ips]
        destination_ips_numeric = [int(ipaddress.ip_address(ip)) for ip in destination_ips]

        # Encode protocols numerically
        le = LabelEncoder()
        protocols_encoded = le.fit_transform(protocols)

        # Create a numpy array from the processed data
        X = np.array(list(zip(source_ips_numeric, destination_ips_numeric, protocols_encoded)))
    else:
        # Handle the case where network_traffic is None or empty
        X = np.array([])  # Consider returning an appropriate shape or message based on your use case

    return X
def is_ddos_attack_detected(ref, model, preprocess_data, HIGH_TRAFFIC_THRESHOLD):
    """
    Determines if a DDoS attack is detected based on network traffic data.

    Parameters:
    - ref: Reference to the source of network traffic data (e.g., a Firebase reference).
    - model: A pre-trained machine learning model for predicting traffic anomalies.
    - preprocess_data: A function to preprocess the network traffic data for the model.
    - HIGH_TRAFFIC_THRESHOLD: A threshold for simple threshold-based DDoS detection.

    Returns:
    - A boolean indicating if a DDoS attack is detected.
    """

    # Step 1: Retrieve network traffic data from firebase
    network_traffic = ref.get()

    # Step 2: Preprocess the data for the model
    X = preprocess_data(network_traffic)

    # Ensuring X is a 2D array for the model's input.
    # This step checks if X represents a single instance (needing reshape) or is already properly shaped.
    if X.ndim == 1:
        X_reshaped = X.reshape(1, -1)  # Reshape for a single instance with multiple features.
    else:
        X_reshaped = X  # Use as is if X is already a 2D array (e.g., multiple instances).

    # Step 3: Predict anomalies in the traffic data
    anomalies = model.predict(X_reshaped)

   # Determine if the anomalies indicate a DDoS attack
    if isinstance(anomalies, np.ndarray) and anomalies.dtype == 'bool':
        # Binary classification case: counting True values (anomalies)
        total_anomalies = np.sum(anomalies)
    elif isinstance(anomalies, np.ndarray):
        # Probabilistic output: assuming anomalies are probabilities of being anomalous
        # and considering any value above 0.8 as an anomaly
        total_anomalies = np.sum(anomalies > 0.8)
    else:
        # Default to 0 if anomalies output is unexpected
        total_anomalies = 0
    # Example of simple threshold-based detection:
    # (This assumes anomalies count or a similar metric if anomalies is not directly a boolean)
    total_requests = sum(anomalies)  # This line would need adjustment based on your actual model output
    is_attack_detected = total_requests > HIGH_TRAFFIC_THRESHOLD

    return is_attack_detected

# Now, you can use the reshaped data with your model
   # or X_multiple_instances_reshaped, depending on your case
def handle_ddos_attack(data):
    if is_ddos_attack_detected():
        redirect_to_scrubbing_center(data)
        return jsonify({'message': 'Traffic redirected to scrubbing center'}), 200

# Function to predict DDoS attacks
def is_ddos_attack_detected():
    # Implement your DDoS attack detection logic here
    pass

# Function to redirect traffic to a scrubbing center
def redirect_to_scrubbing_center(data):
    # Implement your traffic redirection logic here
    pass
# Function to predict DDoS attacks
def predict_ddos(data):
    # Expecting data to be a list of features
    data = np.array([data]).astype(np.float).reshape(1, -1)
    prediction = model.predict(data)
    return prediction[0]

@sockets.on('/ddos_detection')
def ddos_detection(ws):
    while not ws.closed:
        # Receive data from the client
        message = ws.receive()
        
        # Assuming data is JSON formatted and contains a list of comma-separated values
        try:
            data = json.loads(message)
            data = np.array(data['values'])  # Adjust 'values' based on the actual key in your JSON
        except (ValueError, KeyError):
            # Handle errors if JSON is malformed or 'values' key is missing
            continue  # Skip to the next iteration

        # Predict the attack type
        prediction = predict_ddos(data)

        # If the prediction is 'attack', send an alert message to the client
        if prediction == 'attack':
            ws.send("DDoS attack detected!")
            # Example of appending to a global 'attacks' list; ensure 'attacks' is defined
            attacks.append({
                'timestamp': time.time(),
                # 'request.remote_addr' might not be accessible; consider alternative approaches
                'source_ip': 'unknown',  # Consider capturing IP in an alternative manner
                'attack_type': prediction
            })
@app.route('/alert', methods=['GET'])
def alert():
    message = "DDoS attack detected!"
    return jsonify({'message': message})
            
@app.route('/send_alert')
def send_alert():
    alert_data = {'message': 'DDoS attack detected!'}
    socketio.emit('alert', alert_data, broadcast=True)
    return jsonify({'status': 'alert sent'}), 200
    
@socketio.on('connect')
def handle_connect():
    print('Client connected.')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected.')
@app.route('/attack-report-html', methods=['GET'])
def attack_report_html():
    # Generate the attack report as an HTML table
    html_table = "<table><tr><th>Timestamp</th><th>Source IP</th><th>Attack Type</th></tr>"
    for attack in attacks:
        html_table += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(attack['timestamp'], attack['source_ip'], attack['attack_type'])
    html_table += "</table>"
    return render_template('report.html', html_table=html_table)

@app.route('/attack-report-dataframe')
def attack_report_dataframe():
    attacks_data = [...]  # Retrieve attacks data from your source
    attacks_df = pd.DataFrame(attacks_data)
    return attacks_df.to_html(index=False)

@app.route('/ddos_report')
def ddos_report():
    """Endpoint to display a report of DDoS attacks."""
    df = pd.DataFrame(attacks)
    report = df.to_html()
    return report

@app.route('/attack-report')
def attack_report():
    # Convert list to DataFrame
    df = pd.DataFrame(attacks)

    # Format the timestamp column
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Set the index to the timestamp column
    df.set_index('timestamp', inplace=True)

    # Generate the HTML table
    html_table = df.to_html()

    # Add customization to the table (optional)
    html_table = html_table.replace('border="1"', 'border="0"')
    html_table = html_table.replace('<th>', '<th style="border-top: 2px solid black; border-bottom: 1px solid black;">')
    html_table = html_table.replace('<td>', '<td style="border-bottom: 1px solid black;">')

    return html_table

@app.route('/generate-pdf')
def generate_pdf():
    # Generate the HTML content for the PDF report
    html_content = render_template('pdf_report.html')

    # Convert the HTML content to a PDF using pdfkit
    pdf_path = 'pdf_report.pdf'
    pdfkit.from_string(html_content, pdf_path)
    # Send the generated PDF as a response
    return send_file(pdf_path, as_attachment=True)
     
@app.route('/traffic-data', methods=['GET'])
def traffic_data():
    data = {"source_ips": [1, 2, 3], "destination_ips": [4, 5, 6], "protocols": ["tcp", "udp", "icmp"]}
    return jsonify(data)

@app.route('/monitor', methods=['POST'])
def monitor():
    """Endpoint for real-time traffic monitoring."""
    data = request.json
    prediction = predict(data)
    if prediction == 1:  # Assuming 1 is for suspicious/attack
        log_attack(data, prediction)
        return jsonify({'alert': 'DDoS attack detected!'})
    return jsonify({'status': 'normal'})

@app.route('/Traffic_Monitoring')
def Traffic_Monitoring():
    return render_template('Traffic_Monitoring.html')

@socketio.on('connect', namespace='/traffic')
def handle_connect():
    print("Client connected")
    socketio.emit('request_data', namespace='/traffic')

@socketio.on('disconnect', namespace='/traffic')
def handle_disconnect():
    print("Client disconnected")

@socketio.on('request_data', namespace='/traffic')
def handle_request_data():
    new_data = [random.randint(0, 100) for _ in range(10)]
    socketio.emit('traffic_data', {'data': new_data}, namespace='/traffic')

#conn.close()
@app.route('/traffic-visualization-data', methods=['GET'])
def traffic_visualization_data():
    data = {"source_ips": [1, 2, 3], "destination_ips": [4, 5, 6], "protocols": ["tcp", "udp", "icmp"]}
    return jsonify(data)

@app.route('/traffic-visualization')
def traffic_visualization():
    return render_template('traffic-visualization.html')

@socketio.on('connect')
def handle_connect():
    print("Client connected")
    socketio.emit('traffic_data', {'data': [random.randint(0, 100) for _ in range(10)]}, namespace='/traffic')

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

@socketio.on('request_data')
def handle_request_data():
    new_data = [random.randint(0, 100) for _ in range(10)]
    socketio.emit('traffic_data', {'data': new_data}, namespace='/traffic')

@app.route('/chart-data')
def chart_data():
    def generate_random_data():
        while True:
            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': random.randint(0, 100)})
            yield f"data:{json_data}\n\n"
            time.sleep(1)

    response = Response(stream_with_context(generate_random_data()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response
# Simplified for clarity
@app.route('/ddos_accuracy', methods=['POST'])
def ddos_accuracy():
    """Endpoint for updating model accuracy, simplified for clarity."""
    # Implementation similar to your original code
    return jsonify({'success': True})
def log_attack(data, prediction):
    """Log the details of a DDoS attack."""
    logging.basicConfig(filename='attack_logs.txt', level=logging.WARNING)
    now = datetime.datetime.now()
    log_entry = f"{now}: Suspicious traffic detected. Prediction: {prediction}. Details: {data}"
    logging.warning(log_entry)
    attacks.append({'timestamp': datetime.datetime.now(), 'details': data, 'prediction': prediction})
# Additional routes and WebSocket handlers should be similarly updated
# WebSocket route example (adjust according to your actual WebSocket logic)
def predict(data):
    """Prediction function using the actual model."""
    # Assuming the model is already loaded (as you mentioned in your original code)
    # Replace the line below with your actual prediction logic
    prediction = model.predict([data])[0]
    return prediction
@app.route('/api/data')
def get_data():
    docs = db.collection('collection_name').stream()  # Replace 'collection_name' with your actual collection name
    data = {
        'total_incoming_traffic': 0,
        'total_outgoing_traffic': 0,
        'top_source_ip': "",
        'top_destination_ip': "",
        'top_protocol': ""
    }
    for doc in docs:
        doc_data = doc.to_dict()
        data['total_incoming_traffic'] += doc_data['incoming_traffic']
        data['total_outgoing_traffic'] += doc_data['outgoing_traffic']
        if doc_data['source_ip'] > data['top_source_ip']:
            data['top_source_ip'] = doc_data['source_ip']
    return jsonify(data)
            
 

if __name__ == '__main__':
    socketio.run(application, debug=True)

     
