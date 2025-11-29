from flask import jsonify
from config import ROUNDS, DEBUG, MAX_CLIENTS

def extract_round_client_id_payload(data):
	# Extract round number from JSON body
	round = data.get('round')
	# Handle errors
	if round is None: 
		return jsonify({'error': 'missing "round" field in JSON body'}), 400
	try: 
		round = int(round)
	except Exception: 
		return jsonify({'error': 'invalid "round" value; must be an integer'}), 400
	if not (1 <= round <= ROUNDS): 
		return jsonify({'error': f'invalid round {round}; must be 1..{ROUNDS}'}), 400

	# Extract client_id from JSON body
	client_id = data.get('client_id')
	# TODO V2: HANDLE AUTHENTICATION! CURRENTLY WE DO NOT CHECK TO ENSURE CLIENT NOT LYING ABOUT ID.
	# Handle errors
	if client_id is None: 
		return jsonify({'error': 'missing "client_id" field in JSON body'}), 400
	try: 
		client_id = int(client_id)
	except Exception: 
		return jsonify({'error': 'invalid "client_id" value; must be an integer'}), 400
	if not (1 <= client_id <= MAX_CLIENTS): 
		return jsonify({'error': f'invalid client_id {client_id}; must be 1..{MAX_CLIENTS}'}), 400
	
	# Extract payload from JSON body
	payload = data.get('payload')
	
	return (round, client_id, payload)