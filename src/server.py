#!/usr/bin/env python3
from flask import Flask, request, jsonify
import threading
from config import ROUNDS, DEBUG, MAX_CLIENTS, THRESHOLD_CLIENTS, ROUND1_EXTRA_WAIT, THRESHOLD_WAIT
from _server_helper import extract_round_client_id_payload


class SecureAggregationServer:
	"""Server for secure aggregation protocol."""
	
	def __init__(self):
		"""Initialize the server with empty state and thread lock."""
		self.received_data = {r: {} for r in range(1, ROUNDS+1)}
		self.lock = threading.Lock()
		self.app = Flask(__name__)
		self._setup_routes()
	
	# TODO: Currently, round_num  (sent as argument in POST) is redundant with "round" field sent in JSON body
	def _setup_routes(self):
		"""Set up Flask routes."""
		self.app.route('/round/<int:round_num>', methods=['POST'])(self.handle_round)
	
	def handle_round(self, round_num):
		"""Handle incoming round data from clients."""
		# Get data from the request
		data = request.get_json(force=True)

		(round, client_id, payload) = extract_round_client_id_payload(data)

		with self.lock:
			self.received_data[round][client_id] = payload

			# Log received data from client
			print(f"Received from client {client_id} in round {round}: {payload}", flush=True)

			# Build response (response sent outside lock)
			response = {'status': 'ok', 'received': self.received_data[round]}

		# Send response
		return jsonify(response)
	
	def run(self, host='127.0.0.1', port=5000, debug=False):
		"""Start the Flask server."""
		self.app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
	server = SecureAggregationServer()
	server.run(host='127.0.0.1', port=5000, debug=False)
