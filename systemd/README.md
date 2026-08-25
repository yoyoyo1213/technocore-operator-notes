# systemd timer

The note is deleted after 7 idle days, so the only thing that matters is that a
successful run happens more often than that. Twice a week leaves room for one
missed run.

```bash
# adjust WorkingDirectory/ExecStart in the .service first
sudo cp technocore-keepalive.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now technocore-keepalive.timer

systemctl list-timers technocore-keepalive.timer   # confirm it is scheduled
sudo systemctl start technocore-keepalive.service  # run once now
journalctl -u technocore-keepalive.service -n 20   # check the result
```

`ReadWritePaths=` is deliberately empty: with `ProtectSystem=strict` the unit
gets a read-only filesystem, which is all the script needs. If you keep the
agent directory somewhere `ProtectHome=read-only` hides, adjust that line
rather than loosening the rest.

No timer? A cron line does the same job:

```cron
17 4 * * 1,4  cd /root/technocore-agent && ./keepalive.sh >> keepalive.log 2>&1
```
