# Freeze desk roles

Incident response practice separates the person who commands from the person who records. PagerDuty's incident-response documentation (Apache-2.0, https://github.com/PagerDuty/incident-response-docs) is one public write-up of that split. The paragraphs below are original to this project. They are not a copy of that repository.

## Incident commander

A human. Named on the roster with an out-of-band channel: a phone bridge, a radio, a second messenger that is not the chat where the alert arrived. The commander decides whether a freeze starts, whether a draft is sent, and whether a thaw begins.

`perimeterctl roster set` can store the name. The software refuses to treat "Perimeter Sentinel" as the commander.

## Scribe

Perimeter Sentinel. It appends ledger lines, renders drafts, and computes the stopwatch. It does not send, does not approve, and does not flip a vendor switch.

If the scribe is wrong or compromised, the commander still has the out-of-band channel and the systems that actually enforce. That is the point of the split. See [THREAT_MODEL.md](../../THREAT_MODEL.md).

## Everyone else on the roster

Contacts (`cdn`, `issuer-usdc`, `ic3`, and the rest) are destinations for drafts. A filled contact is a phone number or a URL the operator already uses. The channel field is a label. Sending is a human action outside this program.
