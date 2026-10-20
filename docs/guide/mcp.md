# MCP

`dopbase mcp serve` starts a Model Context Protocol server over standard input
and output. Configure your MCP client to run the Dopbase binary with that
command. The server uses the active Dopbase URL and requires an AI-agent token
through `DOPBASE_TOKEN`.

The tools list project and environment metadata, secret keys and versions, and
the current folder/file tree. A project-scoped token can also create folders
and encrypted files, save new file versions, restore a version as a new version,
and move a file. Moves keep the file ID; the response includes its new folder,
and another `dopbase_list_project_files` call returns the refreshed tree.

MCP tools never reveal, export, or return file content. There are no delete
tools; delete files, versions, and folders in the Admin UI. Server-side
authorization is enforced on every request. Choose a global metadata token to
read across projects or a project token to read and write within one project in
**Users → Get token**.

Create an AI agent in **Users → Add AI agent**, copy its one-time token, and
provide it from a protected credential store:

```sh
export DOPBASE_TOKEN="$AI_AGENT_TOKEN"
dopbase mcp serve
```

For a desktop instance, the Tauri host uses the upstream configured API port,
so CLI and MCP clients connect to the same local Dopbase server.
