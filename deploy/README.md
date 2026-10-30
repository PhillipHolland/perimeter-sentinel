# Deploy

v0.1 is a single static binary. These files are examples. They do not provision a cloud account.

- `systemd/perimeter-sentinel.timer` fires 30 seconds after the previous run finishes. That is inside the 60 second on-chain bar. Point the service at observation files you produce. Do not put a key in the unit.
- `docker-compose.yml` drops all capabilities, sets `no-new-privileges`, and runs as uid 65532. The image is scratch plus the binary.
- `helm/perimeter-sentinel` is a CronJob on a one-minute schedule, which is the long edge of the on-chain bar. Use the systemd timer when you need 30 seconds. The chart does not call a vendor.

The home directory should be mode `0700`. Do not mount a wallet key into any of these units.
