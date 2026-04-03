#!/usr/bin/env python3


DEBUG = True
DEBUG_TESTING_DELAY = False
DEBUG_TESTING_DELAY_CLIENT_ID = 1
DEBUG_TESTING_DELAY_ROUND = 1
DEBUG_TESTING_DELAY_TIME = 6

ROUNDS = 5

MAX_CLIENTS = 10
# for demo only! Should really be more like 200
# n in Bonawitz et al. 2017


THRESHOLD_CLIENTS = 5
# for demo only! Should really be more like 100
# t in Bonawitz et al. 2017


# Timing parameters (general; overwritten by round-specific params as needed)
THRESHOLD_WAIT_ALL = (
    1  # Once threshold met, wait this many seconds before finalizing round i
)
POLL_INTERVAL_ALL = (
    0.5  # Once a client joins, poll every this many seconds to wait for round i result
)
MAX_POLLS_ALL = int(
    POLL_INTERVAL_ALL * 20
)  # How many polls to wait maximum before giving up? TODO: For real world, should be MUCH higher, like 100+.


# Round-specific timing parameters
THRESHOLD_WAITS = {i: THRESHOLD_WAIT_ALL for i in range(1, ROUNDS + 1)}
POLL_INTERVALS = {i: POLL_INTERVAL_ALL for i in range(1, ROUNDS + 1)}
MAX_POLLS = {i: MAX_POLLS_ALL for i in range(1, ROUNDS + 1)}


PRG_SEED_SIZE = 16
# 128 bits
# size of b_u in Bhowmick et al. 2017


DERIVED_KEY_LENGTH = 32
# We work on the field defined by prime p = 2^128 - 159, so field elements are 16 bytes long (128 bits)
FIELD_ELEMENT_SIZE = 16
R = 2**128 - 159
