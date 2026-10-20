PLUGGBOX 0.1.0-proto — EXPERIMENTAL OWNER TRIAL

The exact firmware, corresponding source, pinned build receipt, target memory
report and notices are bound by manifest.json and SHA256SUMS. trial.json permits
only the separately validated normal-Jambox-to-Pluggbox installer transition.
Hardware validation remains false. These software checks do not prove power-loss
recovery, physical audio deadlines or every hardware control.

This prototype replaces the running instrument with Pluggbox. Its musical
sessions are temporary; it does not import or overwrite Jambox checkpoints.
Use the guided Chrome/Edge page, not an arbitrary firmware flashing tool.
Nothing in the packaging command connects to, installs on or resets a device.

Rebuild: python3 tools/build_pluggbox_device.py
Repackage: python3 tools/package_pluggbox_device.py --no-build
