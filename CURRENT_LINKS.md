# Where Kosha is

Two addresses, doing different jobs.

**The app** — https://kosha.taila6d3cb.ts.net

Lives on your tailnet. It opens on any device signed in to that
tailnet and is invisible to everyone else, which is the right default
for a private data store. It is only up while the machine hosting it
is awake and online.

**The always-on page** — https://saiaarjay09.github.io/kosha/

A public, static GitHub Pages site that is up regardless of whether
the server is. It explains what Kosha is and carries the current app
address, so there is one link worth bookmarking even when the app
itself is asleep.

---

If the hostname ever changes — a renamed machine, a new tailnet — run
`./deploy/publish-links.sh`, which re-derives it from Tailscale and
updates both this file and the Pages site in one commit. Don't edit
the URLs here by hand; that script will overwrite them.

See [README.md](README.md) for setup and [ARCHITECTURE.md](ARCHITECTURE.md)
for how the code fits together.
