"""Source-checkout entry point for the packaged read-only fixture recorder."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eth_guard.fixtures.record import Recorder, main

if __name__ == '__main__':
    main()
