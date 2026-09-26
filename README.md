# SQL User Access Log Analyser

**Summary:** I used SQL to flag risky login sessions and then tested whether each flag actually predicted attacks. 3+ failed logins was the strongest single flag (100% attack rate vs 33.7%). Off-hours access on its own made almost no difference (45.7% vs 44.5%). Combining flags worked best: sessions hitting 2 or more flags had a 96%+ attack rate.

## Problem
Companies need to spot suspicious logins early, like repeated failed logins, logins at odd hours or sessions with weak security.
In this project I used SQL to look for these patterns in 9,537 simulated login sessions.
I also checked whether each pattern actually led to more attacks.

## What I Did
- Loaded a public intrusion-detection dataset into MySQL
- Checked the data first (blanks, duplicates, value ranges, logic checks)
- Wrote SQL queries to flag risky sessions
- Compared attack rates for flagged and not flagged sessions
- Used the data to pick my thresholds
- Built an exception report of sessions that hit 2 or more flags
- Made charts in Power BI

## Data Checks
| Check | Result |
|---|---|
| Missing values (all 11 columns) | 0 |
| Duplicate session IDs | 0 |
| failed_logins range | 0 to 5 |
| ip_reputation_score range | 0.0025 to 0.924 |
| Failed logins higher than login attempts | 730 (7.7%) |
| Flag columns with values other than 0 or 1 | 0 |

The data had no missing values or duplicates.
The logic check found 730 sessions where failed logins were higher than login attempts, which is not possible in real logs.
I kept these rows so the results cover the full dataset, and I noted this as a limitation.

## Key Findings
| Finding | Count | % of 9,537 Sessions |
|---|---|---|
| Repeated failed logins (3+) | 1,584 | 16.6% |
| Unusual/off-hours access | 1,430 | 15.0% |
| No encryption + high-risk IP | 368 | 3.9% |
| Sessions labelled as attacks in the dataset | 4,264 | 44.7% |

## Do the Flags Predict Attacks?
| Flag | Attack rate if flagged | Attack rate if not flagged | Result |
|---|---|---|---|
| 3+ failed logins | 100.0% | 33.7% | Strong |
| No encryption + high-risk IP | 66.8% | 43.8% | Moderate |
| Off-hours access | 45.7% | 44.5% | Weak |

![Attack rate flagged vs not flagged](chart_indicator_test.png)

## How I Chose the Thresholds
- 3 failed logins: the attack rate was about 34% for 0, 1 and 2 failed logins, then went to 100% at 3.
- IP score above 0.5: the attack rate was about 40% below 0.5, then went up to 63.7% between 0.5 and 0.75, and 100% above 0.75.

![Attack rate by number of failed logins](chart_failed_logins_threshold.png)

## Exception Report
I combined the three flags and counted how many each session hit.

| Flags hit | Sessions | Attack rate |
|---|---|---|
| 0 | 6,507 | 32.6% |
| 1 | 2,687 | 67.5% |
| 2 | 334 | 96.4% |
| 3 | 9 | 100.0% |

The more flags a session hit, the higher the attack rate. 343 sessions hit 2 or more flags. In a real audit, this is the list I would send to the IT team for follow-up.

## What This Means for Audit
These results relate to access controls, which are part of IT general controls (ITGCs).
If this was a real company, I would check:
- Failed logins: do accounts lock after a few failed attempts, and is MFA used? This was the strongest flag.
- No encryption + high-risk IP: is encryption required, and are risky IPs blocked or flagged?
- Off-hours access: this flag alone made almost no difference, so an alert based only on time would give a lot of false alarms. It should be used with other flags.
- Log review: are access logs checked regularly, not only after something goes wrong?

## Limitations
- The data is simulated, so it is cleaner than real logs. The 100% result for 3+ failed logins is probably because of how the data was made.
- 730 sessions (7.7%) have more failed logins than login attempts, so some values in the dataset are not reliable.
- The attack label comes from the dataset. I did not find the attacks myself; I used the label to test my flags.
- There is no user or role data, so I could not check segregation of duties.
- There are no dates or times, so I could not look at trends.

## How to Run
1. Download the dataset from Kaggle (link below).
2. Run Section 1 (Setup) of audit_queries.sql to create the database and table.
3. Import the CSV into session_data using the MySQL Workbench import wizard.
4. Run Sections 2 to 6 in order.

## Files
- audit_queries.sql: all my SQL queries, in 6 sections
- chart_indicator_test.png: attack rate for flagged vs not flagged sessions
- chart_failed_logins_threshold.png: attack rate by number of failed logins

## Tools Used
MySQL 8, MySQL Workbench, Power BI

## Dataset
Cybersecurity Intrusion Detection Dataset (Kaggle):
https://www.kaggle.com/datasets/dnkumars/cybersecurity-intrusion-detection-dataset
