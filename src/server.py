#!/usr/bin/env python3
from flask import Flask, request, jsonify
import threading
import time
from config import ROUNDS, DEBUG, MAX_CLIENTS, THRESHOLD_CLIENTS, THRESHOLD_WAITS
from _server_helper import extract_round_client_id_payload, response_if_not_responder, build_keyset_response, build_sharekeys_response, build_masked_input_response


class SecureAggregationServer:
	"""Server for secure aggregation protocol."""
	
	def __init__(self):
		"""Initialize the server with empty state and thread lock"""
		self.received_data = {r: {} for r in range(1, ROUNDS+1)} # stores per-round received data
		self.lock = threading.Lock() # locks state while edits being made
		self.app = Flask(__name__) # Flask app instance to receive/send HTTP/POST requests (calls _setup_routes)
		self.roundi_responders = {r: set() for r in range(1, ROUNDS+1)} # Clients that responded in each round
		self.roundi_threshold_met = {r: threading.Event() for r in range(1, ROUNDS+1)} # Event to signal when threshold is reached
		self.roundi_responders_locked = {r: threading.Event() for r in range(1, ROUNDS+1)} # Event to signal when threshold wait period ENDS
		self.roundi_result = {r: None for r in range(1, ROUNDS+1)} # Computed result after each round's threshold wait
		self._setup_routes() # Set up flask routes (called by Flask app setup)
	
	# TODO: Currently, round_num  (sent as argument in POST) is redundant with "round" field sent in JSON body; we probably don't need both
	def _setup_routes(self):
		"""Boilerplate to set up Flask routes to send/receive HTTP/POST"""
		self.app.route('/round/<int:round_num>', methods=['POST'])(self.handle_round)
		self.app.route('/round1/result', methods=['GET'])(self.get_round1_result)
		self.app.route('/round2/result', methods=['GET'])(self.get_round2_result)

	
	def handle_round(self, round_num: int):
		"""Handle incoming round data from clients"""
		# Get data from the request
		data = request.get_json(force=True)

		(round, client_id, payload) = extract_round_client_id_payload(data, expected_round=round_num)

		with self.lock:
			self.received_data[round][client_id] = payload

			# Log received data from client
			print(f"Received from client {client_id} in round {round}: {payload}", flush=True)

			# Run round-specific pre-checks
			pre_check_response = None
			if round == 1:
				pre_check_response = self._check_round1(client_id)
			elif round == 2:
				pre_check_response = self._check_round2(client_id)
			
			# If pre-check failed, return the error response
			if pre_check_response is not None:
				return jsonify(pre_check_response)
			
			# Common threshold-based collection logic
			response = self._collect_round_response(round, client_id, payload)

		# Send response
		return jsonify(response)
	
	def _check_round1(self, client_id: int) -> dict:
		"""Pre-check for round 1. Returns None if checks pass, or error response if they fail."""
		return None  # Round 1 has no special pre-checks
	
	def _check_round2(self, client_id: int) -> dict:
		"""Pre-check for round 2. Returns None if checks pass, or error response if they fail."""
		# Check if client participated in round 1
		if not self.roundi_responders_locked[1].is_set():
			return {'status': 'error', 'message': 'Round 2 received before round 1 threshold wait completed.'}
		elif client_id not in self.roundi_responders[1]:
			return response_if_not_responder(client_id, 1)
		return None
	
	def _collect_round_response(self, round: int, client_id: int, payload) -> dict:
		"""Common logic for collecting clients in a round with threshold-based waiting."""
		max_responders = MAX_CLIENTS if round == 1 else len(self.roundi_responders[round-1])
		
		# If we haven't hit the threshold yet, add this client to responders
		if not self.roundi_responders_locked[round].is_set() and len(self.roundi_responders[round]) < max_responders:
			self.roundi_responders[round].add(client_id)
			print(f"Round {round}: Client {client_id} added. Responders so far: {len(self.roundi_responders[round])} / Threshold: {THRESHOLD_CLIENTS}", flush=True)
		
			# When we first hit the threshold, mark the event and start the wait period
			if len(self.roundi_responders[round]) >= THRESHOLD_CLIENTS:
				print(f"Round {round}: Threshold reached ({THRESHOLD_CLIENTS} clients). Starting wait period of {THRESHOLD_WAITS[round]} seconds.", flush=True)
				if not self.roundi_threshold_met[round].is_set():
					self.roundi_threshold_met[round].set()

				# Start thread that will wait and lock responders
				if not self.roundi_responders_locked[round].is_set():
					threshold_wait_thread = threading.Thread(target=self._threshold_wait, args=(round,))
					threshold_wait_thread.daemon = True
					threshold_wait_thread.start()
		
			# Respond immediately; actual result happens in get_roundN_result
			return {'status': 'ok', 'message': f'Client {client_id} registered. Waiting for at least {max(THRESHOLD_CLIENTS-len(self.roundi_responders[round]), 0)} more clients.'}

		elif self.roundi_responders_locked[round].is_set():
			# Responders locked, client is late
			return response_if_not_responder(client_id, round)
		else:
			# Still collecting responses
			return {'status': 'ok', 'message': f'Client {client_id} registered for round {round}.'}
	
	
	def _threshold_wait(self, round: int):
		"""Wait for threshold wait period after threshold is reached, collecting any additional clients."""
		responders = self.roundi_responders[round]
		lock_event = self.roundi_responders_locked[round]
		
		print(f"Starting thread waiting for round {round} threshold wait period ({THRESHOLD_WAITS[round]}s)...", flush=True)
		time.sleep(THRESHOLD_WAITS[round])
		
		with self.lock:
			print(f"Round {round}: Wait period complete. Final responders: {responders}", flush=True)
				
		# Signal that the event is complete and lock responders
		lock_event.set()

	def get_round1_result(self):
		"""Clients poll this endpoint to get the round 1 result once threshold wait completes."""
		# Extract client_id from query parameter
		client_id = request.args.get('client_id', type=int)
		
		# Wait until round 1 is complete and result is ready
		self.roundi_responders_locked[1].wait()

		with self.lock:
			if client_id in self.roundi_responders[1]:
				response = build_keyset_response(self.received_data, self.roundi_responders[1])
			else:
				response = response_if_not_responder(client_id, 1)
		return jsonify(response)

	def get_round2_result(self):
		"""Clients poll this endpoint to get the round 2 result once threshold wait completes."""
		print("Get round 2 result called", flush=True)
		# Extract client_id from query parameter
		client_id = request.args.get('client_id', type=int)
		
		# Wait until round 2 is complete and result is ready
		self.roundi_responders_locked[2].wait()

		with self.lock:
			if client_id not in self.roundi_responders[1]:
				response = response_if_not_responder(client_id, 1)
			elif client_id not in self.roundi_responders[2]:
				response = response_if_not_responder(client_id, 2)
			else:
				response = build_sharekeys_response(client_id, self.received_data, self.roundi_responders[2])
		return jsonify(response)

	def get_round3_result(self):
		"""Clients poll this endpoint to get the round 3 result once threshold wait completes."""
		print("Get round 3 result called", flush=True)
		# Extract client_id from query parameter
		client_id = request.args.get('client_id', type=int)

		# Wait until round 3 is complete and result is ready
		self.roundi_responders_locked[3].wait()

		with self.lock:
			if client_id not in self.roundi_responders[1]:
				response = response_if_not_responder(client_id, 1)
			elif client_id not in self.roundi_responders[2]:
				response = response_if_not_responder(client_id, 2)
			elif client_id not in self.roundi_responders[3]:
				response = response_if_not_responder(client_id, 3)
			else:
				response = build_masked_input_response(client_id, self.received_data, self.roundi_responders[3])
		return jsonify(response)

	def run(self, host='127.0.0.1', port=5000, debug=False):
		"""Start the Flask server"""
		self.app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
	server = SecureAggregationServer()
	server.run(host='127.0.0.1', port=5000, debug=False)
