# SQL User Access Log Analyser

## Problem
Organisations need to detect suspicious login activity — repeated failed logins, 
unusual access times, and weak security controls — before they lead to a breach. 
This project analyses 9,537 real session records to flag exactly these patterns.

## Approach
- Imported a real intrusion-detection dataset into MySQL
- Wrote SQL queries to flag audit-relevant risk patterns
- Visualised key findings in Power BI

## Key Findings
| Finding | Count | % of 9,537 Sessions |
|---|---|---|
| Repeated failed logins (3+) | 1,584 | 16.6% |
| Unusual/off-hours access | 1,430 | 15.0% |
| No encryption + high-risk IP | 368 | 3.9% |
| Confirmed attacks (overall) | 4,264 | 44.7% |

## Tools Used
MySQL, MySQL Workbench, Power BI

## Chart
See `chart_failed_logins.png` — failed login attempts broken down by protocol type.