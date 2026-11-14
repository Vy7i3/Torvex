---
name: False positive or rule issue
about: Report a suspicious match or rule problem with a harmless reproducer
title: "[Rule] "
labels: detection
---

## Rule involved

- Rule name:
- Namespace:
- Rules source (bundled demo fixtures or a directory you supplied):
- Rule file, if you can share it:

## File details

- SHA-256:
- Size:
- Reported type:
- How the file was produced or obtained:
- Why you believe the match is incorrect or too broad:

Do **not** attach live malware or private user files. Describe how to recreate a
harmless equivalent, or provide a hash and a minimal safe snippet. If the rule
comes from a third party, include its source and license if known.

## Scan output

Paste the relevant finding or JSON entry. Remove sensitive paths if needed.

```text
```

## Expected behavior

What would a useful result look like? For example: no match, a narrower rule, or
clearer evidence in the report.

## Additional context

Remember that Torvex currently reports rule matches as **suspicious**, not
confirmed malware. False positives and missing detections are tracked as
detection quality issues, not security vulnerabilities.
