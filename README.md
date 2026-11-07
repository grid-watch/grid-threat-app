# Sydney Grid Threat Rating

A household dashboard for a possible multi-day, cyber-caused power outage in Sydney/NSW.
No AI and no accounts needed. It works offline once opened.

- **Gauge and daily reports:** a GitHub Action runs `scripts/update.py` twice a day. It reads
  ASD's ACSC alerts and advisories, AEMO market notices and news headlines, applies fixed
  keyword rules and writes `data/history.json`. You can always override the level in the app.
- **Checklist, household stock, emergency power calculator:** saved on each phone only, never in this repository.

## Rules (edit `scripts/update.py` to tune)

| Level | Triggered by |
| --- | --- |
| Act (red) | AEMO notice of a black system in NSW |
| Prepare (orange) | Two or more reports of a cyber attack on an Australian grid company; an ACSC alert of active exploitation of Australian critical infrastructure; AEMO actual LOR3 or load shedding in NSW |
| Watch (yellow) | Taiwan blockade, quarantine or major exercise headlines; Volt/Salt Typhoon and Australia; a cyber-caused grid outage in an allied country; an ACSC alert mentioning critical infrastructure; AEMO actual LOR2 in NSW |
| Normal (green) | None of the above |

To run the check by hand: **Actions → Daily threat check → Run workflow**.
