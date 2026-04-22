scripts/ directory
                 ┌──────────────────────────────┐
                 │                              │
[PlutoSDR] ◄──► │  bridge.py (GNU Radio block)  │
  (SDR HW)      │  ▲ imported by                │
                 │  │                            │
                 │  │  ZMQ :5009 (RX)            │
                 │  │  ZMQ :5007 (TX)            │
                 │  ▼                            │
                 │  worker.py (middleware)        │
                 │                              │
                 └──────────┬───────────────────┘
                            │ TCP :5008
                            ▼
                 ┌──────────────────────────────┐
                 │  GhostLayer C GTK GUI        │
                 │  (built from src/ & include/) │
                 └──────────────────────────────┘
