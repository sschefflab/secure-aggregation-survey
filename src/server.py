#!/usr/bin/env python3
from flask import Flask, request, jsonify
import threading
from config import ROUNDS, DEBUG, MAX_CLIENTS, THRESHOLD_CLIENTS, ROUND1_EXTRA_WAIT, THRESHOLD_WAIT
from _server_helper import extract_round_client_id_payload

app = Flask(__name__)

# Initialize empty dictionary to store state
received_data = {r: {} for r in range(1, ROUNDS+1)}
lock = threading.Lock()

@app.route('/round', methods=['POST'])
def handle_round():
	# Get data from the request
	data = request.get_json(force=True)

	(round, client_id, payload) = extract_round_client_id_payload(data)

	with lock:
		received_data[round][client_id] = payload

		# Log received data from client
		print(f"Received from client {client_id} in round {round}: {payload}", flush=True)

		# Build response (response sent outside lock)
		response = {'status': 'ok', 'received': received_data[round]}

	# Send response
	return jsonify(response)

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=5000, debug=False)
