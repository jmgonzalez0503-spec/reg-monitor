# Regulatory and Legislative Monitor

A small program that checks 33 public federal acquisition sources on weekday mornings and publishes what is new.

**Website:** https://jmgonzalez0503-spec.github.io/reg-monitor/

## What it covers

Federal Register DFARS notices, DFARS class deviations, FAR overhaul rules, DPCAP OT policy, the Guide to Prototype Other Transactions, NDAA bill actions, CRS reports, House Rules Committee announcements, GAO reports, DoD Inspector General reports, OT case law, DIU solicitations, consortium OT activity, SAM.gov OT and CSO solicitations, GAO bid protest decisions, Federal Circuit commentary, Court of Federal Claims opinions, government contracts law blogs, and the DARS open case reports.

## How it works

- `reg_monitor.py` reads each source in `sources.json`, using an official data feed where one exists and a backup route where one is available.
- GitHub Actions runs it on a schedule (`.github/workflows/monitor.yml`) and saves the results to `docs/data/`.
- `docs/index.html` is the website. It reads the saved results.

Every source ends each run with one status: new items, nothing new, could not check, blocked, needs API key, or manual. A source that could not be read is never reported as "nothing new."

The program identifies itself honestly and follows each site's robots.txt on ordinary web pages.

## Optional API keys

Add these as repository secrets (Settings, Secrets and variables, Actions) to enable or improve three sources:

- `CONGRESS_API_KEY` from https://api.data.gov/signup/
- `SAM_API_KEY` from a SAM.gov account
- `COURTLISTENER_TOKEN` from a free CourtListener account

## Limits

Public documents only. This is not legal advice. This is a personal project and is not affiliated with any employer or government agency.
