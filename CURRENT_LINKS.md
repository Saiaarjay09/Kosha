# Where Kosha is

Two addresses, doing different jobs. Both run the same application.

## The browser copy — always up

**https://saiaarjay09.github.io/Kosha/**

A static site on GitHub Pages. It needs no server, works offline, and
works with every machine you own switched off. The encrypted vault
lives in that browser's own storage, so it does not sync between
devices and clearing your site data erases it — export a backup from
Settings once there is anything worth keeping.

## The synced copy — while this Mac is awake

**https://haven.taila6d3cb.ts.net:8912**

The same app with a small server behind it, published to your tailnet
only (`tailscale serve`, not `funnel`) — so it is reachable from your
own signed-in devices and invisible to everyone else. Data is shared
across every device you sign in from.

Served by the `com.kosha.server` launchd agent on port 8711, proxied by
Tailscale on 8912. Check it with:

```
launchctl list | grep kosha
curl -s https://haven.taila6d3cb.ts.net:8912/api/health
```

---

Settings → **Export encrypted vault file** moves a vault between the
two. Every byte in that file is already encrypted.

If the tailnet hostname ever changes, run `./deploy/publish-links.sh`,
which re-derives it and updates this file and the Pages site together.
Don't edit the URLs by hand; that script overwrites them.

See [README.md](README.md) for setup and
[ARCHITECTURE.md](ARCHITECTURE.md) for how the code fits together.
