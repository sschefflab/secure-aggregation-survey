#!/usr/bin/env python3

DEBUG = True

ROUNDS = 4

MAX_CLIENTS = 3 
# for demo only! Should really be more like 200
# n in Bonawitz et al. 2017

THRESHOLD_CLIENTS = 2 
# for demo only! Should really be more like 100
# t in Bonawitz et al. 2017

# Round 1 timing parameters
R1_THRESHOLD_WAIT = 1 # Once threshold met, wait this many seconds before finalizing round 1
R1_POLL_INTERVAL = 0.5  # Once a client joins, poll every this many seconds to wait for round 1 result
R1_MAX_POLLS = int(R1_POLL_INTERVAL*20)  #How many polls to wait maximum before giving up? TODO: For real world, should be MUCH higher, like 100+. Must be higher than R1_THRESHOLD_WAIT.

R2_SERVER_WAIT = 2 # Once R2 started, wait this many seconds before finalizing round 2
R2_POLL_INTERVAL = 0.5  # Once a client joins, poll every this many seconds to wait for round 1 result
R2_MAX_POLLS = int(R2_POLL_INTERVAL*20)  #How many polls to wait maximum before giving up? TODO: For real world, should be MUCH higher, like 100+.

PRG_SEED_SIZE = 16 
# 128 bits
# size of b_u in Bhowmick et al. 2017

DERIVED_KEY_LENGTH = 32
