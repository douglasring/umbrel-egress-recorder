# Deploying on Umbrel with Portainer CE

A step-by-step guide that assumes no prior Docker or Portainer experience. Everything
after publishing the image is done in the Portainer web interface — no SSH required.

Budget about 30 minutes the first time.

**Before you begin:** this container watches network traffic. To do that it must run with
`network_mode: host` and the `NET_RAW` capability, which together are a significant
privilege grant on your node. Read the "Residual risk" section of the
[README](./README.md) and decide you are comfortable with it. If you are not, stop here.

---

## Part 1 — Publish the image (one time, from GitHub's website)

Portainer installs software from a container image. One has to exist before Portainer can
install it. You do not need a terminal for this.

### 1.1 Create a release tag

1. Go to <https://github.com/douglasring/umbrel-egress-recorder>
2. On the right-hand side, click **Releases** (or **Create a new release** if there are none)
3. Click **Draft a new release**
4. Click **Choose a tag**, type `v0.1.0`, then click **Create new tag: v0.1.0 on publish**
5. Title it `v0.1.0`
6. Click **Publish release**

### 1.2 Wait for the build

1. Click the **Actions** tab at the top of the repository
2. You will see a run called **Publish image**. Click it.
3. Wait for a green tick. It builds for both Raspberry Pi (arm64) and Intel/AMD
   (x86_64), so this typically takes 5–10 minutes.
4. Click into the job and open the last step, **Print the digest to pin**

You will see a line like this:

```text
ghcr.io/douglasring/umbrel-egress-recorder@sha256:9f2c4d1e...e41a
```

**Copy that whole line.** That long `sha256:` value is the *digest* — it names one exact
build. You will paste it into Portainer shortly.

> **Why not just use `:latest`?** `latest` is a moving label; whatever it points at today
> could be replaced tomorrow, and your node would silently pull the replacement. For a
> container with this much privilege, you want to run the exact build you chose.

### 1.3 Make the image downloadable

New images are private by default, and Portainer will not be logged in, so it would fail
to download.

1. Go to your GitHub profile → **Packages** tab
2. Click **umbrel-egress-recorder**
3. On the right, click **Package settings**
4. Scroll to **Danger Zone** → **Change visibility** → choose **Public** → confirm

---

## Part 2 — Install it in Portainer

### 2.1 Open Portainer

From your Umbrel dashboard, open the **Portainer** app. If you are asked to create an
admin account on first use, do so and keep the password somewhere safe.

### 2.2 Get to the Stacks screen

1. On the Portainer home screen, click the environment named **local**
2. In the left sidebar, click **Stacks**
3. Click **+ Add stack** (top right)

> A "stack" is just Portainer's word for a group of containers defined by one
> configuration file. Ours defines a single container.

### 2.3 Fill in the stack

1. **Name:** type `umbrel-egress-recorder`
2. **Build method:** leave **Web editor** selected
3. In the big text box, paste the entire contents of
   [`compose.yml`](./compose.yml) from this repository

   (Open the file on GitHub, click the **Copy raw file** button, then paste.)

4. **Now make the one required edit.** Find this line near the top:

   ```yaml
   image: ghcr.io/douglasring/umbrel-egress-recorder:latest
   ```

   Replace it with the digest line you copied in step 1.2:

   ```yaml
   image: ghcr.io/douglasring/umbrel-egress-recorder@sha256:9f2c4d1e...e41a
   ```

   Keep the `image: ` part and the indentation exactly as they were — YAML is fussy about
   spaces.

5. Scroll to the bottom and click **Deploy the stack**

Deployment takes a minute or two while the image downloads. If it fails, see
[When something goes wrong](#when-something-goes-wrong).

### 2.4 Confirm the container is running

1. Left sidebar → **Containers**
2. You should see **umbrel-egress-recorder** with state **running**

A green "running" badge is necessary but **not sufficient** — the next part is the one
that actually matters.

---

## Part 3 — Check it is really recording

This is the step people skip. A container that is running but not capturing looks exactly
like a healthy one, right up until the day you need it.

Portainer gives you a terminal inside the container, so you do not need SSH.

### 3.1 Open the container console

1. Left sidebar → **Containers**
2. Click **umbrel-egress-recorder**
3. In the row of icons near the top, click **>_ Console**
4. **Command:** leave as `/bin/sh`. **User:** leave as `root`.
5. Click **Connect**

You now have a prompt inside the container. Type commands and press Enter.

### 3.2 Run the health check

```sh
status
```

A healthy result looks like this:

```text
umbrel-egress-recorder status
  container UTC now   : 2026-09-01T21:52:58Z
    (compare against your firewall's clock - it likely reports LOCAL time)
  session             : #1 started 2026-09-01T21:52:32Z
  last heartbeat      : 2026-09-01T21:52:56Z
  flows retained      : 143
  oldest observation  : 2026-09-01T21:52:33Z
  retention window    : 24h00m00s
  live bytes / cap    : 36,864 / 67,108,864
  kernel drops        : 0 dropped of 1,204 received (as of 2026-09-01T21:52:58Z)
```

Three things to check:

| Look at | You want |
| --- | --- |
| `last heartbeat` | Within the last minute or so |
| `flows retained` | **Not zero** after a minute of running |
| `STOPPED` line | **Absent.** If present, capture died — read the reason. |

If `flows retained` stays at `0` for several minutes on a node with normal traffic,
something is wrong — see [When something goes wrong](#when-something-goes-wrong).

### 3.3 Look at real traffic

```sh
recent 10
```

```text
FIRST SEEN (UTC)       IFACE            DIR   PROTO SOURCE                   DESTINATION              PKTS
2026-09-01T21:52:40Z   br-151de2baa44b  in    UDP   10.21.21.12:37467        203.0.113.77:9999        40
2026-09-01T21:52:40Z   eth0             out   UDP   192.168.1.50:37467       203.0.113.77:9999        40
```

Notice the same connection appears twice. That is intentional and it is the entire point
of this tool:

- The **`eth0`** row is what your firewall sees — the Umbrel's own address.
- The **`br-...`** row is the Docker bridge, and it still shows the **app's** internal
  address (`10.21.21.12`). This is the row that tells you *which app* was responsible.

If you only ever see `eth0` rows and never `br-...` rows, the pre-NAT attribution is not
working and the tool cannot do its main job — say so and it can be diagnosed.

### 3.4 Check the clock

`status` prints the container's time in **UTC**. Your firewall almost certainly reports
times in your **local** timezone. Note the difference now, while it is calm, so you are
not doing timezone arithmetic during an incident. An hour's error is enough to look in
the wrong window and wrongly conclude nothing happened.

Type `exit` to leave the console.

---

## Part 4 — Using it after a firewall alert

Suppose Firewalla says your Umbrel contacted `203.0.113.42` on port `34567`.

### Step 1: Rule out Tor first

This is the most likely explanation, so check it before anything else. Many Umbrel apps
send traffic through Tor, Tor relays often run on cheap hosting, and that hosting
frequently has a poor reputation score. A "malware" alert on such an address is very
often just a Tor relay doing nothing wrong.

This check needs the Umbrel host (not the container console), so use SSH if you have it:

```bash
./tools/check-tor-relay.sh 203.0.113.42
```

If it reports a match, you are probably done. Do not conclude compromise from a
reputation alert alone.

### Step 2: Look up the address

Back in the Portainer container console (Part 3.1):

```sh
lookup 203.0.113.42 34567
```

**Read the coverage banner before the results.** It appears whether or not there is a
match, and it tells you whether the answer can be trusted:

```text
COVERAGE  continuous 2026-09-01T19:41:02Z .. 2026-09-01T20:41:03Z
          (59m58s of the requested 60m, 0 kernel drops, 0 gaps)
```

That means the recorder was watching the whole time — a "no match" here genuinely means
it did not happen.

```text
NO MATCH for 203.0.113.42
COVERAGE  INCOMPLETE - 12m41s of the last 24h00m00s observed, 1 gap(s), 4,218 kernel drops
          Treat a non-match as "unknown", not "did not happen".
```

That means the recorder was **not** watching the whole time. A "no match" proves nothing.

This distinction is deliberate — an empty result during an incident is very easy to
misread as "we're fine".

### Step 3: Find out which app it was

If you got results, look at the `br-...` row and note its internal address, for example
`10.21.21.12`. On the Umbrel host:

```bash
./tools/map-container-ip.sh 10.21.21.12
```

That prints the container name and image currently holding that address.

**A caution:** this tells you who holds the address *right now*. If the app was updated or
restarted since the observation, the answer may be wrong. To make historical lookups
reliable, install the ledger once (it records the mapping every 15 minutes):

```bash
sudo ./tools/install-ip-ledger.sh
```

### Step 4: Interpret carefully

- If the traffic went via Tor, the internal address will be the **Tor container**, not the
  app behind it. Attribution stops there — that is a real limit, not a bug.
- A reputation hit is **not** proof of malware. Hosting providers serve many customers,
  and reputation feeds produce false positives.
- Treat what you find as evidence to reason about, not a verdict.

### A word of caution about sharing

The output can reveal your Lightning channel peers, Bitcoin peers, Tor guard and bridge
addresses, VPN endpoints, and your internal network layout. **Never paste it into a public
GitHub issue, forum post, or chat.** See [SECURITY.md](./SECURITY.md).

---

## When something goes wrong

**"Failed to deploy a stack" / image cannot be pulled**

The image is still private. Redo step 1.3. You can test by opening the package page while
signed out of GitHub — if you get a 404, it is still private.

**Container keeps restarting**

Containers → click the container → **Logs**. Look at the last few lines.

If you see `Operation not permitted` near a mention of `tcpdump` or `nobody`, the capture
`SETUID` and `SETGID` capabilities are missing from `cap_add`. Debian's tcpdump always
drops privileges at startup and cannot be told not to, so it needs them. Add them back
to the stack and redeploy.

**`status` shows a session but `flows retained: 0`**

Check **Logs** for a tcpdump error. If tcpdump started cleanly and there is simply no
traffic, generate some (load the Umbrel dashboard) and check again.

**`status` shows a `STOPPED` line**

Capture died. The reason is printed on that line. The most common cause is the memory
limit — edit the stack, raise `mem_limit` from `256m` to `512m`, and redeploy.

**`status` shows `DEGRADED`**

The disk is full, so the recorder stopped writing rather than pretending to work. Free
space; it recovers automatically on the next successful write.

---

## Updating later

1. Publish a new release tag (Part 1.1) — for example `v0.1.1`
2. Copy the new digest from **Actions** (Part 1.2)
3. Portainer → **Stacks** → **umbrel-egress-recorder** → **Editor**
4. Change the `image:` line to the new digest
5. Click **Update the stack**

Because you pin a digest, an update only ever happens when you choose it.

## Removing it

Portainer → **Stacks** → **umbrel-egress-recorder** → **Delete this stack**.

The recorded data lives in a separate volume that deliberately survives this. To erase it
too: **Volumes** → find `umbrel-egress-recorder_egress-data` → **Remove**.
