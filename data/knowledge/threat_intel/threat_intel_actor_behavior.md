# Threat Actor Behavior & Confidence

## Description
Understanding Threat Actor behavior goes beyond static IOCs (which change rapidly) and focuses on the underlying Tactics, Techniques, and Procedures (TTPs) mapped in frameworks like MITRE ATT&CK.

## SOC Application
1. **Behavioral Profiling:** Recognizing that a sequence of `whoami`, `systeminfo`, and `nltest` is typical reconnaissance behavior, regardless of the malware family.
2. **Attribution:** Associating specific behaviors or custom tools with known groups (e.g., APT29, FIN7).
3. **False Positive Considerations:** Understanding that system administrators also use tools like PsExec and PowerShell. Context (who, what, when, where) is critical for confidence scoring.

## Detection Clues
- Focus on the *chain of events*. A single administrative command might be benign, but five executed in rapid succession by a service account is highly malicious.
- Look for Living off the Land (LotL) techniques where attackers use native OS tools (LOLBins) to avoid dropping custom malware.

## Investigation Guidance
When investigating, ask: "Does this behavior make sense for this user role and this host?" Build hypotheses based on attacker methodologies. If you see credential dumping, assume lateral movement will follow, and proactively hunt for it.
