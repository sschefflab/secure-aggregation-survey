#!/usr/bin/env python3
"""HTTP client for Flask server, sends JSON via POST for 4 rounds."""
import requests
import argparse
import time

ROUNDS = 4
SERVER_URL = 'http://127.0.0.1:5000/round/'

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--id', type=int, required=True, help='Client id (1..i for testing)')
	args = parser.parse_args()
	client_id = args.id
	for r in range(1, ROUNDS+1):
		payload = {'client_id': client_id, 'payload': f'Hello from client {client_id} round {r}'}
		resp = requests.post(f'{SERVER_URL}{r}', json=payload)
		print(f"Client {client_id} round {r} sent: {payload}")
		print(f"Client {client_id} round {r} got: {resp.json()}")
		time.sleep(0.2)

if __name__ == '__main__':
	main()
