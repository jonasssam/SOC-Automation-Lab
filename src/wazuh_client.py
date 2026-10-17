import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

WAZUH_HOST = os.getenv("WAZUH_HOST")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

INDEXER_HOST = os.getenv("INDEXER_HOST")
INDEXER_USER = os.getenv("INDEXER_USER")
INDEXER_PASSWORD = os.getenv("INDEXER_PASSWORD")


def get_wazuh_token():
    """Authenticate with the Wazuh API and return an access token."""

    url = f"{WAZUH_HOST}/security/user/authenticate"

    response = requests.post(
        url,
        auth=(WAZUH_USER, WAZUH_PASSWORD),
        verify=False
    )

    response.raise_for_status()

    return response.json()["data"]["token"]


def get_wazuh_alerts(limit=10):
    """Retrieve recent alerts for rules 100100, 100102, and 92057 from the Wazuh Indexer."""

    url = f"{INDEXER_HOST}/wazuh-alerts-*/_search"

    query = {
        "size": limit,
        "query": {
            "bool": {
                "filter": [
                    {
                        "terms": {
                            "rule.id": ["100100", "100102", "92057"]
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    response = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASSWORD),
        json=query,
        verify=False
    )

    response.raise_for_status()

    return response.json()


def parse_alerts(alert_response):
    """Extract useful fields from raw Wazuh alert data."""

    alerts = []

    for hit in alert_response.get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        rule = source.get("rule", {})
        agent = source.get("agent", {})

        win = source.get("data", {}).get("win", {})
        eventdata = win.get("eventdata", {})

        alert = {
            "id": hit.get("_id"),
            "timestamp": source.get("timestamp"),
            "rule_id": rule.get("id"),
            "description": rule.get("description"),
            "level": rule.get("level"),
            "agent": agent.get("name"),
            "source_ip": eventdata.get("ipAddress"),
            "target_user": eventdata.get("targetUserName"),
            "logon_type": eventdata.get("logonType"),
        }

        alerts.append(alert)

    return alerts


def classify_alert(alert):
    """Classify a parsed Wazuh alert by severity."""

    level = alert.get("level") or 0

    if level >= 12:
        return "CRITICAL"
    elif level >= 8:
        return "HIGH"
    elif level >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def decide_action(severity):
    """Determine the appropriate response for an alert."""

    if severity == "CRITICAL":
        return "RESPOND"

    elif severity == "HIGH":
        return "RESPOND"

    elif severity == "MEDIUM":
        return "INVESTIGATE"

    else:
        return "LOG"


def send_active_response(agent_id, alert):
    """Send a custom Active Response command to a Wazuh agent."""

    token = get_wazuh_token()

    url = f"{WAZUH_HOST}/active-response?agents_list={agent_id}"

    # The "!" tells Wazuh to run this script by file name, so it doesn't need
    # an enabled <active-response> block in ossec.conf (Python decides when to block)
    payload = {
        "command": "!block-source-ip.cmd",
        "arguments": [],
        "alert": alert
    }

    response = requests.put(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json=payload,
        verify=False
    )

    response.raise_for_status()

    return response.json()
