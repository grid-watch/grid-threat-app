# Grid Threat Rating

A household dashboard for preparing for a possible multi-day, cyber-caused power outage, anywhere in the world.
No AI and no accounts needed. It works offline once opened.

- **Your location:** each person picks their country (and, in Australia, their state) and types their city.
  This is saved on their own device only.
- **Gauge and daily reports:** a GitHub Action runs `scripts/update.py` twice a day. For each country it reads
  that country's equivalent sources where they exist, applies fixed keyword rules, and rates each country
  Normal, Watch, Prepare or Act. You can always override the level in the app.
- **Checklist, household stock, emergency power calculator:** saved on each device only, never in this repository.

## Sources by country

| Country | National cyber agency feed | Local news search | Grid notices |
| --- | --- | --- | --- |
| Australia | ASD's ACSC alerts and advisories | English | AEMO market notices (per state) |
| United States | CISA advisories, CISA ICS advisories | English | — |
| United Kingdom | NCSC | English | — |
| Canada | Canadian Centre for Cyber Security | English | — |
| EU members | CERT-EU | Local language for DE, AT, FR, BE, NL, ES, PT, IT, PL, SE, FI, DK, IE | — |
| France | CERT-FR alerts and SCADA | French | — |
| Netherlands | NCSC-NL | Dutch | — |
| Spain | INCIBE-CERT alerts and industrial-control alerts | Spanish | — |
| Japan | JPCERT/CC | Japanese | — |
| Ukraine | CERT-UA | Ukrainian | — |
| Poland | CERT Polska | Polish | — |
| Finland | NCSC-FI | Finnish | — |
| Others | — | NZ, IE, IN, SG, ZA, PH (English), CH, NO, KR, TW, BR, MX, AR, CL, IL (local language) | — |

Worldwide searches also watch for Taiwan Strait escalation (affects AU, US, JP, TW, PH, KR, NZ), state hacking groups
(Volt Typhoon, Salt Typhoon, Sandworm) and widespread blackouts.

## Rules (edit `scripts/update.py` to tune)

| Level | Triggered by |
| --- | --- |
| Act (red) | AEMO notice of a black system (Australian state) |
| Prepare (orange) | A national agency alert of active exploitation of energy or industrial systems; two or more news reports of a cyber attack disrupting the grid in that country; a widespread blackout reported twice; AEMO load shedding |
| Watch (yellow) | A national agency advisory about critical infrastructure; one news report of a grid cyber attack, or a failed attempt; Taiwan Strait escalation (Indo-Pacific countries); state hacking group named with the country; AEMO actual LOR2 |
| Normal (green) | None of the above |

To run the check by hand: **Actions → Daily threat check → Run workflow**.
