---
title: "AI agent access"
description: "Give an AI coding agent access to Dopbase project structure and secret metadata without exposing secret values."
---

# AI agent access

An AI agent account gets a token scoped to either all projects (metadata only)
or one selected project (metadata, runtime use, and version writes). A token
cannot delete data or reset the instance.

Global metadata access is useful when an agent needs configuration context.
One-project access also lets it add and version data in that project.

## When to use an AI agent

Use an AI agent token for tasks such as:

- checking whether variables referenced by the code exist in Dopbase;
- comparing the secret names in development, staging, and production;
- finding a missing or renamed variable without exposing its value
- creating an `.env.example` file with empty placeholders
- reviewing deployment files that refer to environment variables.

Metadata-only tokens cannot run tests that need secrets. A one-project token
can use `dopbase run` for that project's environments and create versions, but
the token can call the scoped runtime endpoint directly. An agent holding it
can therefore read or print those values; CLI injection does not guarantee
“use without being able to read.”

::: warning Metadata is still sensitive
Secret names and project structure can reveal details about your infrastructure.
Global metadata tokens can see every project and environment. One-project
tokens see only the selected project and its metadata. Secret names and project
structure can still be sensitive; create an account only for agents you trust.
:::

## Create an account and token

Root and admin users create AI accounts from the Admin UI:

1. Open **Users** and choose **Add AI agent**.
2. Give the account a name that identifies the tool or job using it.
3. Choose **Get token** beside the new account.
4. Generate the token and copy it when it appears. Token creation uses your
   authenticated Admin UI session and does not ask for your password again.

Choose a global metadata token or select one project. The Admin UI defaults to
30 days and lets you
choose no expiry or a lifetime up to three years in whole hours or days. It
revokes any previous active token for that account. Dopbase shows
the plaintext token once, so put it in a password manager, CI secret store, or
another protected credential store.

Do not commit the token, add it to an `.env` file in the repository, paste it
into an agent prompt, or include it in logs.

## Give the token to an agent

Dopbase reads an agent token from `DOPBASE_TOKEN`. Populate
`AI_AGENT_TOKEN` from your credential store before starting the agent, then set
the server and token in its shell environment:

```bash
export DOPBASE_URL=https://dopbase.example.com
export DOPBASE_TOKEN="$AI_AGENT_TOKEN"

dopbase client status
```

`client status` reports the identity as `ai_agent` without printing the token.
Use `DOPBASE_TOKEN` for agent credentials. `login --token` saves runner tokens
for runtime secrets and pipeline exports.

Run this setup outside the agent conversation so the token never becomes part
of its prompt.

## Inspect configuration metadata

The agent can use normal CLI commands. JSON output is easier for automated
tools to parse:

```bash
dopbase --json project list
dopbase --json project show payment-service
dopbase --json env list payment-service
dopbase --json env show payment-service/staging
dopbase --json secret list payment-service/staging
dopbase --json secret get payment-service/staging DATABASE_URL
```

These commands return identifiers, names, versions, and timestamps. They never
return the value of `DATABASE_URL` or any other secret. The server validates
agent tokens on each metadata request. Invalid, expired, or revoked tokens fail
without using a saved human credential.

For example, ask a coding agent:

```text
Find every environment variable referenced by this repository. Compare those
names with payment-service/staging in Dopbase and report missing or unused
names. Use metadata commands only. Do not attempt to reveal or change secrets.
```

The agent can inspect the repository, call `dopbase secret list`, and compare
the two sets of names. A human can then decide whether any missing secrets
should be added.

## Operations that are denied

Agent tokens cannot use the human reveal, export, delete, or reset controls.
Global metadata tokens also cannot change data. One-project tokens may create
and version data only in their selected project. For a global metadata token,
these actions are denied:

```bash
dopbase secret get payment-service/staging DATABASE_URL --reveal
printf '%s' 'replacement' | \
  dopbase secret set payment-service/staging DATABASE_URL --stdin
```

A one-project token is also denied access to another project and cannot delete
data in its own project. Only the Admin UI can delete secret, file, and folder
records.

Do not replace the agent token with a human session to bypass these checks. If
the task needs to run an application, create a runner token for that specific
environment and follow [Run an application](./run-an-application).

## Revoke access

Return to **Users** and delete the AI account to remove the account and its
tokens. Generating another token from the Admin UI also revokes the account's
previous active token. Revoke access as soon as a token may have been exposed.

See [Identity and tokens](/reference/identity#ai-agents) for the complete
permission matrix.
