#!/usr/bin/env python3
from flask import jsonify
from config import ROUNDS, DEBUG, MAX_CLIENTS

def extract_round_client_id_payload(data: dict, expected_round: int) -> tuple[int, int, dict]:
	# Extract round number from JSON body
	round = data.get('round')
	# Handle errors
	if round is None: 
		raise ValueError('Error: Missing "round" field in JSON body')
	round = int(round)
	assert(round == expected_round, f"Round number {expected_round} from POST does not match JSON body round number {round}")
	if not (1 <= round <= ROUNDS): 
		raise ValueError(f"Error: Invalid round {round}; must be 1..{ROUNDS}")

	# Extract client_id from JSON body
	client_id = data.get('client_id')
	# TODO V2: HANDLE AUTHENTICATION! CURRENTLY WE DO NOT CHECK TO ENSURE CLIENT NOT LYING ABOUT ID.
	# Handle errors
	if client_id is None: 
		raise ValueError('Error: Missing "client_id" field in JSON body')
	client_id = int(client_id)
	if not (1 <= client_id <= MAX_CLIENTS): 
		raise ValueError(f"Error: Invalid client_id {client_id}; must be 1..{MAX_CLIENTS}")
	
	# Extract payload from JSON body
	payload = data.get('payload')
	
	return (round, client_id, payload)


def build_keyset_response(received_data: dict[int, dict[int, dict]], round1_responders: set[int]) -> dict[int, dict]:
	# received_data format: {round: {client_id: {payload}}}
	round1_data = received_data[1]
	return {client_id: round1_data[client_id] for client_id in round1_responders}

def response_if_not_r1_responder(client_id: int) -> dict:
	return {'status': 'nonparticipant', 'message': f'Client {client_id} responded too late to participate in Round 1.'}