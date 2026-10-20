---
title: "Projects and environments"
description: "How the Admin UI organizes projects, environments, and secrets, and how to navigate between them."
---

# Projects and environments

Projects is the main screen of the Admin UI. It shows the model described
in [projects, environments, and secrets](/guide/projects-environments-secrets):
a list of projects on the left, the selected project's environments, and the
secrets of the selected environment.

## The project rail

The left rail lists projects. The selected project's environments appear as
small tags beneath it; selecting a tag opens that environment's secrets and
runner tokens. When you arrive with nothing selected, Dopbase opens the first
project and its first environment.

- **Create a project** with the new-project control in the rail. Names are
  unique on the server, so pick the application's name: `payment-service`,
  not `backend`.
- **Rename** a project from its menu. Existing links that used the old name
  stop working, because names are part of the address.
- **Delete** a project and Dopbase shows what goes with it (every environment
  and every secret inside) before you confirm. Deletion cannot be undone.
- **Open files** or create a file/folder directly from the project's `…` menu.

## Environments

Selecting a project lists its environments. Each one holds its own set of
secret values, so `DATABASE_URL` in `development` can point somewhere entirely
different from `DATABASE_URL` in `production`.

- **Create** a project-local environment tag with a name such as `dev`, `test`,
  `RC`, or `prod`.
- **Rename** it from its menu.
- **Delete** it and Dopbase counts the affected secrets and runner tokens.
  Files and folders keep their contents; their deleted tag is cleared and they
  inherit from their parent folder where possible.

## Tags on files and folders

Files and folders can use the same project environment tags as secrets. A new
file or folder inherits the nearest tagged parent by default. Choose another
tag to override it, or clear the direct tag to inherit again. Moving a folder
moves its entire subtree, so inherited tags follow the new parent. Untagged
files remain shared across environments.

## Addresses you can share

Selection lives in the URL, not in some hidden app state:

```text
/projects/p/payment-service/e/env_482731
```

The project part uses the name. The environment part uses its immutable ID.
Bookmark a production environment, paste a link to a teammate, or put the URL
in a runbook. The link opens the same place later.

The environment ID in the address is the same ID the CLI accepts. In the UI,
the selected environment is presented by its project tag name.

## Runner tokens

Each environment has a **Tokens** tab next to its secrets. This is where
machine identities come from:

- **Create** a token with a name such as `production-server`. Choose no expiry,
  a preset lifetime, or a custom number of hours or days up to three years. Dopbase shows
  the plaintext token once. Copy it before closing the dialog because Dopbase
  cannot display it again.
- **Check expiry** in the token list. Expired tokens cannot authenticate. Create
  a replacement if you need a different lifetime.
- **Revoke** a token when a server is decommissioned or a token may have
  leaked. Revocation is immediate.

A runner token can read and export the values of its assigned environment.
Use `dopbase run` to inject them or `dopbase export` to write a file. It cannot
change secrets or access another environment. Give each deployed workload its own token. See
[identity and tokens](/reference/identity) for the full rules.
