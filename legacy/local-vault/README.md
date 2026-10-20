# Preserved Local Vault prototype

This directory contains the previous Tauri prototype source and static UI. It is
kept as a reference for a future explicit migration tool. The active application
uses upstream Dopbase storage and encryption; it does not read or modify the old
`LVLT0001` vault format. No user vault data is stored in this directory.

Any migration must be opt-in, require the old vault password, create a verified
backup, and write imported values through the active Dopbase encryption layer.
