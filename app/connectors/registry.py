from app.connectors.otxv2 import OTXConnector

# Add new connectors here — they auto-run in parallel
CONNECTORS = [
    OTXConnector,
]