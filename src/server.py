#!/usr/bin/env python3
from flask import Flask, request, jsonify
import threading
import time
from config import ROUNDS, DEBUG, MAX_CLIENTS, THRESHOLD_CLIENTS, THRESHOLD_WAIT
from _server_helper import extract_round_client_id_payload, build_keyset_response, response_if_not_r1_responder


class SecureAggregationServer:
	"""Server for secure aggregation protocol."""
	
	def __init__(self):
		"""Initialize the server with empty state and thread lock"""
		self.received_data = {r: {} for r in range(1, ROUNDS+1)} # stores per-round received data
		self.lock = threading.Lock() # locks state while edits being made
		self.app = Flask(__name__) # Flask app instance to receive/send HTTP/POST requests (calls _setup_routes)
		self.round1_responders = set() # Clients that responded (gave keys) in round 1 (at least THRESHOLD_CLIENTS, at most MAX_CLIENTS)
		self.round1_threshold_met = threading.Event() # Event to signal when threshold wait period starts
		self.round1_responders_locked = threading.Event() # Event to signal when threshold wait period ENDS (and responders are locked)
		self.round1_result = None # Computed result after round 1 threshold wait completes # TODO MAYBE REMOVE?
		self._setup_routes() # Set up flask routes (called by Flask app setup)
	
	# TODO: Currently, round_num  (sent as argument in POST) is redundant with "round" field sent in JSON body; we probably don't need both
	def _setup_routes(self):
		"""Boilerplate to set up Flask routes to send/receive HTTP/POST"""
		self.app.route('/round/<int:round_num>', methods=['POST'])(self.handle_round)
		self.app.route('/round1/result', methods=['GET'])(self.get_round1_result)

	
	def handle_round(self, round_num: int):
		"""Handle incoming round data from clients"""
		# Get data from the request
		data = request.get_json(force=True)

		(round, client_id, payload) = extract_round_client_id_payload(data, expected_round=round_num)

		with self.lock:
			self.received_data[round][client_id] = payload

			# Log received data from client
			print(f"Received from client {client_id} in round {round}: {payload}", flush=True)

			# Round 1-specific logic
			if round == 1:
				# If we haven't hit the threshold yet, add this client to responders
				if not self.round1_responders_locked.is_set() and len(self.round1_responders) < MAX_CLIENTS:
					self.round1_responders.add(client_id)
					print(f"Round 1: Client {client_id} added. Responders so far: {len(self.round1_responders)} / Threshold: {THRESHOLD_CLIENTS}", flush=True)
				
					# When we first hit the threshold, mark the event as done and start the wait period.
					if len(self.round1_responders) >= THRESHOLD_CLIENTS:
						print(f"Round 1: Threshold reached ({THRESHOLD_CLIENTS} clients). Starting wait period of {THRESHOLD_WAIT} seconds.", flush=True)
						if not self.round1_threshold_met.is_set():
							self.round1_threshold_met.set()

						# Start thread that will wait and lock responders
						if not self.round1_responders_locked.is_set():
							threshold_wait_thread = threading.Thread(target=self._round1_threshold_wait)
							threshold_wait_thread.daemon = True
							threshold_wait_thread.start()
				
					# Respond immediately; actual result happens in get_round1_result at round1/result
					response = {'status': 'ok', 'message': f'Client {client_id} registered. Waiting for at least {THRESHOLD_CLIENTS-len(self.round1_responders)} more clients.'}

				else: # Responders locked, client is late
					response = response_if_not_r1_responder(client_id)
			elif round == 2:
				# Round 2 logic can go here
				if not self.round1_responders_locked.is_set():
					response = {'status': 'error', 'message': 'Round 2 received before round 1 threshold wait completed.'}
				elif client_id not in self.round1_responders:
					response = response_if_not_r1_responder(client_id)
				else:
					response = {'status': 'ok', 'received': self.received_data[round]}

			else:
				# Other rounds
				response = {'status': 'ok', 'received': self.received_data[round]}

		# Send response
		return jsonify(response)
	
	def _round1_threshold_wait(self):
		"""Wait for THRESHOLD_WAIT seconds after threshold is reached, collecting any additional clients."""
		print("Starting thread waiting for threshold wait period...", flush=True)
		time.sleep(THRESHOLD_WAIT)
		
		with self.lock:
			print(f"Round 1: Wait period complete. Final responders: {self.round1_responders}", flush=True)
				
		# Signal that the event is complete and lock respodners
		self.round1_responders_locked.set()

	def get_round1_result(self):
		"""Clients poll this endpoint to get the round 1 result once threshold wait completes."""
		# Extract client_id from query parameter
		client_id = request.args.get('client_id', type=int)
		
		# Wait until round 1 is complete and result is ready
		self.round1_responders_locked.wait()

		with self.lock:
			if client_id in self.round1_responders:
				response = build_keyset_response(self.received_data, self.round1_responders)
			else:
				response = response_if_not_r1_responder(client_id)
		return jsonify(response)

	def run(self, host='127.0.0.1', port=5000, debug=False):
		"""Start the Flask server"""
		self.app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
	server = SecureAggregationServer()
	server.run(host='127.0.0.1', port=5000, debug=False)
