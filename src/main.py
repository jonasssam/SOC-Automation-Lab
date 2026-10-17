import time

from wazuh_client import (
    get_wazuh_alerts,
    parse_alerts,
    classify_alert,
    decide_action,
    send_active_response,
)

from audit import is_processed, mark_processed, log_action

POLL_INTERVAL = 5


def main():
    """Continuously monitor Wazuh for new high-severity alerts."""

    print("SOC Automation Engine starting...")

    print("Checking for new alerts...")

    print(f"Polling Wazuh every {POLL_INTERVAL} seconds...")
    print("Press Ctrl+C to stop")

    while True:
        try:
            raw_response = get_wazuh_alerts(10)
            hits = raw_response.get("hits", {}).get("hits", [])

            for hit in reversed(hits):
                alert_id = hit.get("_id")

                if not alert_id:
                    continue

                if is_processed(alert_id):
                    continue

                parsed = parse_alerts({
                    "hits": {
                        "hits": [hit]
                    }
                })[0]

                severity = classify_alert(parsed)
                action = decide_action(severity)

                # Only block when there's an attacker IP to block.
                # Local activity (like encoded PowerShell) gets sent to a person instead.
                if action == "RESPOND" and not parsed["source_ip"]:
                    action = "INVESTIGATE"

                print(
                    f"[{severity}] "
                    f"Action: {action} | "
                    f"Rule {parsed['rule_id']} | "
                    f"Source IP: {parsed['source_ip']} | "
                    f"User: {parsed['target_user']} | "
                    f"Agent: {parsed['agent']}"
                )

                response_result = "Not required"

                if action == "RESPOND":
                    agent_id = hit.get("_source", {}).get("agent", {}).get("id")

                    if agent_id:
                        result = send_active_response(
                            agent_id,
                            hit.get("_source", {})
                        )

                        # Wazuh can return success even when nothing was sent,
                        # so check how many agents actually got the command
                        data = result.get("data", {})

                        if data.get("total_affected_items", 0) > 0:
                            response_result = "Block command sent"
                            print(f"Block command sent to Agent {agent_id}")
                        else:
                            failed = data.get("failed_items", [])
                            response_result = f"FAILED: {failed}"
                            print(f"[FAILED] Block not sent to Agent {agent_id}: {failed}")
                    else:
                        response_result = "No agent ID found, response not sent"

                log_action(
                    alert_id=alert_id,
                    rule_id=parsed["rule_id"],
                    severity=severity,
                    action=action,
                    source_ip=parsed["source_ip"],
                    agent=parsed["agent"],
                    response_result=response_result,
                )

                mark_processed(alert_id)

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\nSOC Automation Engine stopped")
            break

        except Exception as error:
            print(f"[ERROR] {error}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
