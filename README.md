# Red Flag Desk

Local website for **Spot the Red Flag, Back the Right Company**. Runs on one laptop. Everyone else joins from their phones over the same Wi-Fi or hotspot. No internet, no accounts, no installs, no cost.

## What you need

- One laptop with **Python 3.8 or newer** (`python --version` to check; get it from python.org if missing).
- A network every phone can join with the laptop:
  - **Best:** a portable router, or the laptop's own mobile hotspot.
  - **Phone hotspot** also works for a small event (about 10 to 15 devices).
  - Campus Wi-Fi often blocks phones from reaching each other's devices. Test it before the event, and don't rely on it.
- A projector connected to the laptop (optional but recommended).

## Start it

- **Windows:** double-click `start-windows.bat`. If Windows asks about the firewall, click **Allow** (tick "Private networks").
- **Mac:** double-click `start-mac.command`. If macOS blocks it, right-click, then **Open**.
- **Any system:** open a terminal in this folder and run `python server.py` (or `python3 server.py`).

The window shows something like:

```
On this laptop:     http://localhost:8000
Everyone else:      http://192.168.1.5:8000
Organiser PIN:      482913
```

- Open the **localhost** address on the laptop, go to **Organiser**, and enter the PIN.
- Put the **Everyone else** address on the projector (Projector button shows it during setup and briefing).
- Keep the window open during the event. Closing it stops the site.

## During the event

1. Teams open the address, go to **My team**, and register with a team name and PIN. Teammates log in on their own phones with the same name and PIN.
2. You press one button per step in **Organiser → Run**. Every release locks in flags automatically.
3. In Round 2, announce news bulletins and open or close adjustment windows from the same page.
4. During the break, match flags to the answer key in **Marking**. Judges enter rationale scores in **Judging**.
5. Reveal flags, outcomes and scores. Copy the leaderboard as CSV from **Scores**.

Teams without a phone: add them in **Teams & entry** as paper teams and type in their answer sheets.

## Good to know

- Everything is saved to `event.json` in this folder after every change. If the laptop restarts, run the server again and nothing is lost.
- To start fresh, use **Reset** in the organiser desk, or delete `event.json` while the server is stopped.
- Edit companies, the answer key, news and scoring in **Organiser → Content**. Do this **before** releasing statements.
- Fixed organiser PIN: run `ORG_PIN=1234 python server.py` (Mac/Linux) or `set ORG_PIN=1234` then `python server.py` (Windows). You can also change it in the Run tab.
- Different port: set `PORT=9000` the same way.
- Do a 15-minute dry run with two phones before the real event.
