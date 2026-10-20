# Project Environment Tags

## Goal

Represent each project's environments as tags across the project UI. A tag
selects the environment-specific secret values and also applies to encrypted
files and folders. The UI must not render environments as a nested entity list
under each project.

## Data and behavior

- Preserve the existing environment IDs and environment-scoped secret,
  runner-token, CLI, and runtime behavior. Environment names remain unique per
  project and are shown as compact selectable tags.
- Encrypted files may have a direct environment assignment. A null assignment
  inherits the nearest tagged ancestor folder; if no ancestor has a tag, the
  file is shared. An explicit file assignment overrides the folder tag.
- Folders may have a direct environment assignment. A null assignment
  inherits from the nearest tagged ancestor. Descendants inherit dynamically,
  so moving or retagging a folder updates inherited tags without rewriting
  child rows or encrypted content.
- Creating a folder or file under a tagged folder inherits the tag by default.
  The user can choose an existing project environment or explicitly create a
  new one from the picker. Unknown text never silently creates an environment.
- Environment tags are project-scoped. Deleting one retains existing Dopbase
  environment deletion semantics and confirms the counts of affected secrets
  and runner tokens; file and folder references are cleared by the foreign key.

## Navigation and interaction

- The project rail lists projects only; remove the special `Files` row and
  environment tree.
- A compact project `…` menu exposes Open files, New folder, New file, Rename,
  and Delete.
- Environment selection appears as compact tags in the project content header.
  The selected tag drives the existing secret and token route. Files and
  folders display their effective environment as a small tag.
- Folder and file actions use one compact `…` trigger and a consistent text
  menu. Folder actions include create child folder/file, rename, move, assign
  or inherit environment, and delete. File actions include reveal/hide, copy,
  move, assign or inherit environment, and delete.
- Existing drag-and-drop and the Move to… dialog remain. Moving a folder moves
  its subtree; inherited tags are derived from the new ancestry.
- Project-root file creation must not create a visible synthetic `Project
root` folder.

## Security and compatibility

- Do not move secret values between environments or alter encryption,
  authentication, audit, runner-token, `dopbase run`, or MCP value boundaries.
- Folder and file tag mutation uses the existing project write and browser
  mutation permissions and records an audit event.
- Additive migration only. Existing file environment assignments remain
  direct assignments; folders begin untagged.

## Acceptance

- Project UI has no special Files rail row and no nested environment entity
  tree. Project menu opens files and starts file/folder creation.
- Environment tags are project-local, selectable, and manage existing
  environment-specific secrets and tokens.
- Folder tags inherit through arbitrary nesting; file tags inherit or
  override. Folder moves preserve the subtree and recompute inherited tags.
- Root-level files and folders are accessible without exposing a synthetic
  root folder.
- File/folder actions share a compact visual treatment, labels, and hover/focus
  behavior. Existing reveal/copy and move flows remain available.
- Existing environment APIs, CLI, runner tokens, and runtime targeting retain
  their current IDs and semantics.
