#!/usr/bin/env python3
"""Flask web server for 3 clients, 4 rounds, POST JSON."""
from flask import Flask, request, jsonify
import threading
from SETUP import ROUNDS, DEBUG, MAX_CLIENTS

app = Flask(__name__)

# Initialize empty dictionary to store state
received_data = {r: {} for r in range(1, ROUNDS+1)}
lock = threading.Lock()

@app.route('/round', methods=['POST'])
def handle_round():
	# Get data from the request
	data = request.get_json(force=True)

	# Extract round number from JSON body
	round = data.get('round')
	# Handle errors
	if round is None: return jsonify({'error': 'missing "round" field in JSON body'}), 400
	try: round = int(round)
	except Exception: return jsonify({'error': 'invalid "round" value; must be an integer'}), 400
	if not (1 <= round <= ROUNDS): return jsonify({'error': f'invalid round {round}; must be 1..{ROUNDS}'}), 400

	# Extract client_id from JSON body
	client_id = data.get('client_id')
	# TODO V2: HANDLE AUTHENTICATION! CURRENTLY WE DO NOT CHECK TO ENSURE CLIENT NOT LYING ABOUT ID.
	# Handle errors
	if client_id is None: return jsonify({'error': 'missing "client_id" field in JSON body'}), 400
	try: client_id = int(client_id)
	except Exception: return jsonify({'error': 'invalid "client_id" value; must be an integer'}), 400
	if not (1 <= client_id <= MAX_CLIENTS): return jsonify({'error': f'invalid client_id {client_id}; must be 1..{MAX_CLIENTS}'}), 400

	# Extract payload from JSON body
	payload = data.get('payload')

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
