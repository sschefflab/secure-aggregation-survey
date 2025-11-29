#!/usr/bin/env python3
"""Flask web server for 3 clients, 4 rounds, POST JSON."""
from flask import Flask, request, jsonify
import threading

app = Flask(__name__)

NUM_CLIENTS = 3
ROUNDS = 4
received_data = {r: {} for r in range(1, ROUNDS+1)}
lock = threading.Lock()

@app.route('/round/<int:round_num>', methods=['POST'])
def handle_round(round_num):
	data = request.get_json(force=True)
	client_id = data.get('client_id')
	payload = data.get('payload')
	with lock:
		received_data[round_num][client_id] = payload
		print(f"Received from client {client_id} in round {round_num}: {payload}", flush=True)
		# Optionally, respond with all received so far for this round
		response = {'status': 'ok', 'received': received_data[round_num]}
	return jsonify(response)

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=5000, debug=False)
