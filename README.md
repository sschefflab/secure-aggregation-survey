# Secure Aggregation Survey

Experimental secure survey software based on cryptography.  Using this setup, researchers see sums/averages of participant responses, but no individualized responses.

### Installing/running instructions
1. Ensure all requirements are met. The expected way to run is in a Python environment .venv
```
python -m venv .venv
source .venv/bin/activate
pip install requirements.txt
```

2. Run `run_all.sh` to run a demo with three clients and a server.  Logs will be placed in `logs/`
```
$ ./run_all.sh 
Starting server, logging to secure-aggregation-survey/log/server.log...
Starting client 1, logging to secure-aggregation-survey/log/client1.log...
Starting client 2, logging to secure-aggregation-survey/log/client2.log...
Starting client 3, logging to secure-aggregation-survey/log/client3.log...
Client 2461289 finished.
Client 2461301 finished.
Client 2461304 finished.
Server 2461280 stopped.
Done.
```

### Detailed information about the cryptography protocol and this implementation

Version 0.1 is a new implementation of the semi-honest version of "Practical Secure Aggregation for Privacy-Preserving Machine Learning" by Bonawitz et al. at CCS'17 [[official link](https://dl.acm.org/doi/pdf/10.1145/3133956.3133982), [open preprint](https://eprint.iacr.org/2017/281)].  The implementation was done by Scheffler in 2025 to support PRESTO research (not affiliated with the original protocol).

