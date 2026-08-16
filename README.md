# SAM: System Audit Manager

If you've used Linux for a while, you know the drill. You uninstall an app, but bits of it stick around anyway: stray config files in `~/.config`, cache folders in `~/.cache`, leftovers in `~/.local`. None of it gets cleaned up automatically, so your home directory slowly fills up with junk from software you removed months, or years, ago.

SAM is a C++ command-line tool built to fix that. It keeps track of the files created when you install software, scans your system for leftovers from things you've already removed, and helps you clean it all up without touching anything it shouldn't.

It queries your package managers, including `apt`, `snap`, `flatpak`, `pip`, `npm`, `cargo`, `maven`, and `gradle`, to figure out what software is actually installed and where its files live. While an install is happening, it watches for new files in real time using Linux's `inotify`, so it knows exactly what was created or modified. Everything it tracks gets written to a local SQLite database, which it also uses when scanning your home directory for leftovers from apps you've already removed. Throughout all of this it stays cautious by default, refusing to touch system directories like `/usr` or `/etc`, or personal folders like `~/Documents`, `~/Pictures`, or `~/.ssh`.

## Building it yourself

You'll need a C++20 compiler (`g++` or `clang++`), `cmake`, and the dev headers for SQLite3 and OpenSSL.

### On Ubuntu or Debian

Install the dependencies:

```bash
sudo apt update
sudo apt install build-essential cmake libsqlite3-dev libssl-dev
```

Then build:

```bash
git clone https://github.com/Mr-Soubhik/SAM.git
cd SAM
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## Using SAM

**Check what's going on with your system:**

```bash
sam status
```

Gives you a quick summary of what's tracked and what clutter has been found.

**Scan for leftovers:**

```bash
sam scan
```

Goes through your home directory looking for files left behind by software that's no longer installed.

**Track a new install:**

```bash
sam install "pip install pytest"
```

Runs the install command through SAM so it can log every file that gets created along the way.

**Remove an app cleanly:**

```bash
sam remove <app-name>
```

Uninstalls the app and clears out the config and cache folders that belonged to it.

## How SAM keeps you safe

Before it deletes anything, SAM works through a handful of checks. Core system directories such as `/usr`, `/lib`, `/etc`, `/var`, and `/boot` are always off-limits, and so are personal folders like `~/Documents`, `~/Pictures`, `~/Videos`, `~/Music`, `~/.ssh`, and `~/.gnupg`. If another installed application still relies on a file, SAM will warn you before removing it rather than deleting it silently. Anything it isn't confident about gets flagged for you to review by hand instead of being deleted automatically, and in every case, nothing actually gets removed until you confirm it.

## Contributing

Bug reports, feature ideas, and pull requests are all welcome — head over to the GitHub repo to get involved.

## License

This project is licensed under the [MIT License](LICENSE).

