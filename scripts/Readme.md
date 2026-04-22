## Full scan, all defaults (900-960 MHz, all SFs, all BWs, 2s dwell):
python3 worker_dos.py --scan

## Faster scan of a narrower range with pcap capture:
python3 worker_dos.py --scan --scan-start 915000000 --scan-end 928000000 \
    --scan-step 500000 --scan-dwell 0.5 --scan-sf 7,8 \
    --scan-bw 125000,250000 -pcap contest.pcap

## Fixed frequency mode with flag detection (original behavior + flags):
python3 worker_dos.py -f 916000000 -bw 250000 -sf 7
