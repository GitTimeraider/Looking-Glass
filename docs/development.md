# Development

[← Back to the README](../README.md)

Running Looking Glass from source with the mock servers, tests, architecture and the upstream sources used.

## Running from source

```bash
pip install -r requirements-dev.txt
python -m pytest -q                                   # parser tests
DATABASE_URL=postgresql://... ADMIN_PASSWORD=x python -m lookingglass.main
python tools/simulate.py --port 5514                  # send simulated OPNsense logs (scans, brute force, tunnels…)
python tools/mock_opnsense.py --port 18443            # fake OPNsense API  (Settings › OPNsense: http://127.0.0.1:18443)
python tools/mock_unraid.py --port 18500              # fake Unraid API    (Settings › Unraid: http://127.0.0.1:18500, key test-key)
python tools/mock_unifi.py --port 18600               # fake UniFi console (Settings › UniFi: http://127.0.0.1:18600, key test-key;
                                                      #   --selfhosted: admin / admin-pass, --version 11.0.89, --no-legacy-key)
python tools/mock_backrest.py --port 19898            # fake Backrest     (Settings › Backrest: http://127.0.0.1:19898, admin / admin-pass;
                                                      #   --no-auth, --no-summary = Backrest before 1.6)
python tools/mock_bichon.py --port 15630              # fake Bichon       (Settings › Bichon: http://127.0.0.1:15630, token test-token;
                                                      #   --metrics-only = a "Metrics only" token)
python tools/mock_crowdsec.py --port 18080            # fake CrowdSec LAPI (Settings › SWAG & CrowdSec: http://127.0.0.1:18080,
                                                      #   machine lookingglass / test-pass, bouncer key test-bouncer-key,
                                                      #   metrics http://127.0.0.1:18080/metrics)
TEST_DATABASE_URL=postgresql://... python -m pytest   # also runs every dashboard query against PostgreSQL
```

Architecture: one asyncio Python process (FastAPI web UI, UDP/TCP syslog receiver with RFC 3164/5424 + octet
counting, OPNsense API poller, detection engine, retention) writing to PostgreSQL (`events`, `alerts`, `metrics`,
`snapshots`, `devices`, `reports`, `ai_chats`). Front-end libraries (Chart.js, marked, DOMPurify) are vendored, so the
UI works without internet access.

## Sources used

Integration details were checked against current upstream sources: the OPNsense
[core](https://github.com/opnsense/core), [plugins](https://github.com/opnsense/plugins) and
[docs](https://github.com/opnsense/docs) repositories (API controllers, syslog model, nginx syslog targets, Q-Feeds,
CrowdSec, DHCP leases), the [Unraid API](https://github.com/unraid/api) schema and [Unraid docs](https://github.com/unraid/docs),
UniFi Network controller OpenAPI specs 9.0–11.0 ([beezly/unifi-apis](https://github.com/beezly/unifi-apis)),
[aiounifi](https://github.com/Kane610/aiounifi), [unpoller](https://github.com/unpoller/unifi) and the
[Art-of-WiFi UniFi API client](https://github.com/Art-of-WiFi/UniFi-API-client),
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) and Anthropic's
[OpenAI SDK compatibility](https://platform.claude.com/docs/en/api/openai-sdk) docs.
