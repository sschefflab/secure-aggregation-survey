#!/usr/bin/env python3

DEBUG = True

ROUNDS = 4

MAX_CLIENTS = 3 
# for demo only! Should really be more like 200
# n in Bonawitz et al. 2017

THRESHOLD_CLIENTS = 2 
# for demo only! Should really be more like 100
# t in Bonawitz et al. 2017

# Timing parameters (general; overwritten by round-specific params as needed)
THRESHOLD_WAIT_ALL = 1 # Once threshold met, wait this many seconds before finalizing round i
POLL_INTERVAL_ALL = 0.5 # Once a client joins, poll every this many seconds to wait for round i result
MAX_POLLS_ALL = int(POLL_INTERVAL_ALL*20) # How many polls to wait maximum before giving up? TODO: For real world, should be MUCH higher, like 100+.

# Round-specific timing parameters
THRESHOLD_WAITS = {i: THRESHOLD_WAIT_ALL for i in range(1, ROUNDS+1)}
POLL_INTERVALS = {i: POLL_INTERVAL_ALL for i in range(1, ROUNDS+1)}
MAX_POLLS = {i: MAX_POLLS_ALL for i in range(1, ROUNDS+1)}

PRG_SEED_SIZE = 16 
# 128 bits
# size of b_u in Bhowmick et al. 2017

DERIVED_KEY_LENGTH = 32
