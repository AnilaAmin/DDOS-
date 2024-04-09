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
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/traffic-visualization')
def traffic_visualization():
    return render_template('traffic-visualization.html')
@app.route('/Traffic_Monitoring')
def Traffic_Monitoring():
    return render_template('Traffic_Monitoring.html')
@app.route('/detect_anomalies')
def detect_anomalies():
    return render_template('detect_anomalies.html')
@app.route('/report')
def report():
    return render_template('report.html')
@app.route('/alert')
def alert():
    return render_template('alert.html')
if __name__ == '__main__':
    app.run(debug=True)