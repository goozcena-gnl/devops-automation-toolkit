# Cloud Budget Guard

## Purpose

Verify Azure and AWS budget coverage, alert thresholds, notification configuration, actual spend, forecasts, daily anomalies, and service concentration.

## Usage

```bash
devops-toolkit budget-guard --provider azure --subscription SUBSCRIPTION_ID
devops-toolkit budget-guard --provider aws --profile billing-audit \
  --required-threshold 50 --required-threshold 80 --required-threshold 100
```

Use `--snapshot FILE` for offline analysis and CI tests.

## Findings

The tool can report missing budgets, invalid limits, missing thresholds, disabled or recipient-less notifications, exceeded budgets, forecasted overspend, rapid daily increases, and excessive cost concentration.

## Safety and limitations

The collector is read-only and does not create budgets or notification recipients. Billing systems can be delayed, and forecast or anomaly findings are explicitly separated from actual spend. Currency and time-window metadata are preserved when supplied by the provider.
