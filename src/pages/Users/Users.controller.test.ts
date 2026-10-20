import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPinia, setActivePinia } from "pinia";
import { useUsersController } from "./Users.controller";
import * as usersApi from "~/services/users.api";
import * as serviceAccountsApi from "~/services/service-accounts.api";
import * as projectsApi from "~/services/projects.api";
import { ApiError } from "~/services/http.client";

vi.mock("vue", async (importOriginal) => ({
  ...(await importOriginal<typeof import("vue")>()),
  onMounted: vi.fn(),
}));

vi.mock("vue-router", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ query: {} }),
}));

vi.mock("~/services/users.api");
vi.mock("~/services/service-accounts.api");
vi.mock("~/services/projects.api");

beforeEach(() => {
  setActivePinia(createPinia());
  vi.clearAllMocks();
  vi.mocked(usersApi.fetchUsers).mockResolvedValue([
    {
      id: "usr_root",
      email: "root@example.com",
      role: "root",
      createdAt: "2026-08-01T00:00:00Z",
      updatedAt: "2026-08-01T00:00:00Z",
    },
  ]);
  vi.mocked(serviceAccountsApi.fetchServiceAccounts).mockResolvedValue([]);
  vi.mocked(projectsApi.listProjects).mockResolvedValue([]);
});

function agentFixture(
  overrides: Partial<serviceAccountsApi.ServiceAccount> & {
    id: string;
    name: string;
  },
): serviceAccountsApi.ServiceAccount {
  return {
    role: "ai_agent",
    createdAt: "2026-08-01T00:00:00Z",
    updatedAt: "2026-08-01T00:00:00Z",
    ...overrides,
  };
}

describe("useUsersController", () => {
  it("loads non-revoked agent tokens for the agents list", async () => {
    const agent = agentFixture({ id: "sa_agent_1", name: "indexer-agent" });
    const unavailableAgent = agentFixture({
      id: "sa_agent_2",
      name: "sync-agent",
    });
    vi.mocked(serviceAccountsApi.fetchServiceAccounts).mockResolvedValueOnce([
      agent,
      unavailableAgent,
    ]);
    vi.mocked(serviceAccountsApi.fetchAgentTokens).mockResolvedValueOnce([
      {
        id: "ait_active",
        serviceAccountId: agent.id,
        name: "active-token",
        access: "metadata",
        environmentId: null,
        projectId: null,
        createdAt: "2026-08-01T00:00:00Z",
        expiresAt: "2026-09-01T00:00:00Z",
        lastUsedAt: null,
        revokedAt: null,
      },
      {
        id: "ait_revoked",
        serviceAccountId: agent.id,
        name: "revoked-token",
        access: "metadata",
        environmentId: null,
        projectId: null,
        createdAt: "2026-07-01T00:00:00Z",
        expiresAt: null,
        lastUsedAt: null,
        revokedAt: "2026-07-15T00:00:00Z",
      },
    ]);
    vi.mocked(serviceAccountsApi.fetchAgentTokens).mockRejectedValueOnce(
      new Error("Network error"),
    );

    const c = useUsersController();
    await c.actions.load();

    expect(serviceAccountsApi.fetchAgentTokens).toHaveBeenCalledWith(agent.id);
    expect(c.state.agentTokens[agent.id]?.map((token) => token.id)).toEqual([
      "ait_active",
    ]);
    expect(c.state.serviceAccounts).toEqual([agent, unavailableAgent]);
    expect(c.state.agentTokens[unavailableAgent.id]).toBeNull();
  });

  it("computes canSave correctly for create and edit modes", () => {
    const c = useUsersController();

    // Create mode: initially empty email and password
    c.actions.openCreate();
    expect(c.state.canSave).toBe(false);

    c.state.email = "admin@example.com";
    expect(c.state.canSave).toBe(false);

    c.state.password = "securepassword123";
    expect(c.state.canSave).toBe(true);

    // Edit mode: password is optional
    c.actions.openEdit({
      id: "usr_2",
      email: "member@example.com",
      role: "member",
      createdAt: "",
      updatedAt: "",
    });
    expect(c.state.canSave).toBe(true);

    c.state.email = "   ";
    expect(c.state.canSave).toBe(false);
  });

  it("validates email format and password length client-side", async () => {
    const c = useUsersController();
    c.actions.openCreate();
    c.state.email = "invalid-email";
    c.state.password = "short";

    await c.actions.save();

    expect(c.state.fieldErrors.email).toBe(
      "Please enter a valid email address.",
    );
    expect(c.state.fieldErrors.password).toContain("at least 12 characters");
    expect(usersApi.createUser).not.toHaveBeenCalled();
    expect(c.state.error).toBeNull(); // Page error is untouched
  });

  it("maps server ApiError validation to fieldErrors without polluting page error", async () => {
    const c = useUsersController();
    c.actions.openCreate();
    c.state.email = "valid@example.com";
    c.state.password = "validpassword123";

    vi.mocked(usersApi.createUser).mockRejectedValueOnce(
      new ApiError(400, {
        EMAIL_INVAILD: "Please enter a valid email address.",
      }),
    );

    await c.actions.save();

    expect(c.state.fieldErrors.email).toBe(
      "Please enter a valid email address.",
    );
    expect(c.state.error).toBeNull(); // Did not leak to background page
    expect(c.state.showCreate).toBe(true); // Modal stayed open
  });

  it("maps password errors to fieldErrors.password", async () => {
    const c = useUsersController();
    c.actions.openCreate();
    c.state.email = "valid@example.com";
    c.state.password = "validpassword123";

    vi.mocked(usersApi.createUser).mockRejectedValueOnce(
      new ApiError(400, {
        PASSWORD_TOO_SHORT: "Password must contain at least 12 characters.",
      }),
    );

    await c.actions.save();

    expect(c.state.fieldErrors.password).toBe(
      "Password must contain at least 12 characters.",
    );
    expect(c.state.error).toBeNull();
  });

  it("maps unhandled server errors to formError inside the modal", async () => {
    const c = useUsersController();
    c.actions.openCreate();
    c.state.email = "valid@example.com";
    c.state.password = "validpassword123";

    vi.mocked(usersApi.createUser).mockRejectedValueOnce(
      new ApiError(500, {
        INTERNAL_ERROR: "Database write failed.",
      }),
    );

    await c.actions.save();

    expect(c.state.formError).toBe("Database write failed.");
    expect(c.state.error).toBeNull();
  });

  it("resets form errors on close and openCreate", () => {
    const c = useUsersController();
    c.actions.openCreate();
    c.state.fieldErrors = { email: "Error" };
    c.state.formError = "Form error";

    c.actions.close();
    expect(c.state.fieldErrors).toEqual({});
    expect(c.state.formError).toBeNull();
  });

  it("handles user delete flow via confirmation dialog without browser dialog", async () => {
    window.confirm = vi.fn();
    const c = useUsersController();

    const targetUser: usersApi.User = {
      id: "usr_to_delete",
      email: "delete-me@example.com",
      role: "member",
      createdAt: "2026-08-01T00:00:00Z",
      updatedAt: "2026-08-01T00:00:00Z",
    };

    // Prompt sets target
    c.actions.promptDelete(targetUser);
    expect(c.state.userToDelete).toEqual(targetUser);
    expect(c.state.deleteUserError).toBeNull();

    // Close cancels
    c.actions.closeDeleteUser();
    expect(c.state.userToDelete).toBeNull();

    // Prompt again and confirm
    c.actions.promptDelete(targetUser);
    vi.mocked(usersApi.deleteUser).mockResolvedValueOnce(undefined);

    await c.actions.confirmDeleteUser();

    expect(usersApi.deleteUser).toHaveBeenCalledWith("usr_to_delete");
    expect(c.state.userToDelete).toBeNull();
    expect(window.confirm).not.toHaveBeenCalled();
  });

  it("surfaces delete user error inside confirmation dialog", async () => {
    const c = useUsersController();
    const targetUser: usersApi.User = {
      id: "usr_fail",
      email: "fail@example.com",
      role: "member",
      createdAt: "",
      updatedAt: "",
    };

    c.actions.promptDelete(targetUser);
    vi.mocked(usersApi.deleteUser).mockRejectedValueOnce(
      new ApiError(400, { ERROR: "Cannot delete user." }),
    );

    await c.actions.confirmDeleteUser();

    expect(c.state.deleteUserError).toBe("Cannot delete user.");
    expect(c.state.userToDelete).toEqual(targetUser); // Dialog stays open
  });

  it("handles AI agent delete flow via confirmation dialog without browser dialog", async () => {
    window.confirm = vi.fn();
    const c = useUsersController();

    const targetAgent: serviceAccountsApi.ServiceAccount = {
      id: "sa_to_delete",
      name: "build-agent",
      role: "ai_agent",
      createdAt: "2026-08-01T00:00:00Z",
      updatedAt: "2026-08-01T00:00:00Z",
    };

    // Prompt sets target
    c.actions.promptDeleteAgent(targetAgent);
    expect(c.state.agentToDelete).toEqual(targetAgent);
    expect(c.state.deleteAgentError).toBeNull();

    // Close cancels
    c.actions.closeDeleteAgent();
    expect(c.state.agentToDelete).toBeNull();

    // Prompt again and confirm
    c.actions.promptDeleteAgent(targetAgent);
    vi.mocked(serviceAccountsApi.deleteServiceAccount).mockResolvedValueOnce(
      undefined,
    );

    await c.actions.confirmDeleteAgent();

    expect(serviceAccountsApi.deleteServiceAccount).toHaveBeenCalledWith(
      "sa_to_delete",
    );
    expect(c.state.agentToDelete).toBeNull();
    expect(window.confirm).not.toHaveBeenCalled();
  });

  it("surfaces delete AI agent error inside confirmation dialog", async () => {
    const c = useUsersController();
    const targetAgent: serviceAccountsApi.ServiceAccount = {
      id: "sa_fail",
      name: "failing-agent",
      role: "ai_agent",
      createdAt: "",
      updatedAt: "",
    };

    c.actions.promptDeleteAgent(targetAgent);
    vi.mocked(serviceAccountsApi.deleteServiceAccount).mockRejectedValueOnce(
      new ApiError(400, { ERROR: "Cannot delete AI agent." }),
    );

    await c.actions.confirmDeleteAgent();

    expect(c.state.deleteAgentError).toBe("Cannot delete AI agent.");
    expect(c.state.agentToDelete).toEqual(targetAgent); // Dialog stays open
  });

  it("opens and cancels the agent token configuration dialog", async () => {
    const c = useUsersController();
    const targetAgent = agentFixture({
      id: "sa_agent_1",
      name: "indexer-agent",
    });

    await c.actions.promptGetToken(targetAgent);
    expect(c.state.showTokenDialog).toBe(true);
    expect(c.state.agentForToken).toEqual(targetAgent);
    expect(c.state.tokenError).toBeNull();

    c.actions.closeTokenDialog();
    expect(c.state.showTokenDialog).toBe(false);
    expect(c.state.agentForToken).toBeNull();
  });

  it("requires a selected project and sends that scope when generating a token", async () => {
    vi.mocked(projectsApi.listProjects).mockResolvedValueOnce([
      {
        id: "prj_app",
        name: "app",
        createdAt: "2026-08-01T00:00:00Z",
        updatedAt: "2026-08-01T00:00:00Z",
      },
    ]);
    const c = useUsersController();
    await c.actions.promptGetToken(
      agentFixture({ id: "aia_agent", name: "build-agent" }),
    );
    c.state.tokenAccess = "project";
    await c.actions.confirmTokenGeneration();
    expect(c.state.tokenProjectError).toBe("Select a project for this token.");
    expect(c.state.projects.map((project) => project.name)).toEqual(["app"]);

    c.state.tokenProjectId = "prj_app";
    vi.mocked(serviceAccountsApi.fetchAgentTokens).mockResolvedValueOnce([]);
    vi.mocked(serviceAccountsApi.createAgentToken).mockResolvedValueOnce({
      token: {
        id: "ait_project",
        serviceAccountId: "aia_agent",
        name: "token-project",
        access: "project",
        environmentId: null,
        projectId: "prj_app",
        createdAt: "2026-08-01T00:00:00Z",
        expiresAt: null,
        lastUsedAt: null,
        revokedAt: null,
      },
      plaintextToken: "dpp_project-token",
    });

    await c.actions.confirmTokenGeneration();
    expect(serviceAccountsApi.createAgentToken).toHaveBeenCalledWith(
      "aia_agent",
      expect.stringMatching(/^token-\d+$/),
      undefined,
      "30d",
      "project",
      undefined,
      "prj_app",
    );
  });

  it("surfaces a failed token generation and keeps the dialog open", async () => {
    const c = useUsersController();
    const targetAgent = agentFixture({
      id: "sa_agent_1",
      name: "indexer-agent",
    });

    await c.actions.promptGetToken(targetAgent);
    vi.mocked(serviceAccountsApi.fetchAgentTokens).mockResolvedValueOnce([]);
    vi.mocked(serviceAccountsApi.createAgentToken).mockRejectedValueOnce(
      new ApiError(403, { ERROR: "Token creation denied." }),
    );

    await c.actions.confirmTokenGeneration();

    expect(c.state.tokenError).toBe("Token creation denied.");
    expect(c.state.showTokenDialog).toBe(true);
    expect(c.state.createdAgentToken).toBeNull();
    expect(serviceAccountsApi.createAgentToken).toHaveBeenCalled();
  });

  it("revokes the active token, generates a replacement, and acknowledges it", async () => {
    const c = useUsersController();
    const targetAgent = agentFixture({
      id: "sa_agent_1",
      name: "indexer-agent",
    });

    await c.actions.promptGetToken(targetAgent);
    vi.mocked(serviceAccountsApi.fetchAgentTokens).mockResolvedValueOnce([
      {
        id: "ait_old_active",
        serviceAccountId: "sa_agent_1",
        name: "token-1",
        access: "metadata",
        environmentId: null,
        projectId: null,
        createdAt: "2026-08-01T00:00:00Z",
        expiresAt: "2026-08-31T00:00:00Z",
        lastUsedAt: null,
        revokedAt: null,
      },
      {
        id: "ait_old_revoked",
        serviceAccountId: "sa_agent_1",
        name: "token-0",
        access: "metadata",
        environmentId: null,
        projectId: null,
        createdAt: "2026-07-01T00:00:00Z",
        expiresAt: "2026-07-31T00:00:00Z",
        lastUsedAt: null,
        revokedAt: "2026-07-15T00:00:00Z",
      },
    ]);
    vi.mocked(serviceAccountsApi.revokeAgentToken).mockResolvedValueOnce({
      id: "ait_old_active",
      serviceAccountId: "sa_agent_1",
      name: "token-1",
      access: "metadata",
      environmentId: null,
      projectId: null,
      createdAt: "2026-08-01T00:00:00Z",
      expiresAt: "2026-08-31T00:00:00Z",
      lastUsedAt: null,
      revokedAt: "2026-08-02T00:00:00Z",
    });
    const createdResult: serviceAccountsApi.CreatedAgentToken = {
      token: {
        id: "ait_new",
        serviceAccountId: "sa_agent_1",
        name: "token-new",
        access: "metadata",
        environmentId: null,
        projectId: null,
        createdAt: "2026-08-02T00:00:00Z",
        expiresAt: "2026-09-01T00:00:00Z",
        lastUsedAt: null,
        revokedAt: null,
      },
      plaintextToken: "dpa_abcdef1234567890",
    };
    vi.mocked(serviceAccountsApi.createAgentToken).mockResolvedValueOnce(
      createdResult,
    );

    await c.actions.confirmTokenGeneration();

    expect(serviceAccountsApi.fetchAgentTokens).toHaveBeenCalledWith(
      "sa_agent_1",
    );
    // Only the unrevoked token should be revoked.
    expect(serviceAccountsApi.revokeAgentToken).toHaveBeenCalledTimes(1);
    expect(serviceAccountsApi.revokeAgentToken).toHaveBeenCalledWith(
      "sa_agent_1",
      "ait_old_active",
    );
    expect(serviceAccountsApi.createAgentToken).toHaveBeenCalledWith(
      "sa_agent_1",
      expect.stringMatching(/^token-\d+$/),
      undefined,
      "30d",
      "metadata",
      undefined,
      undefined,
    );
    expect(c.state.showTokenDialog).toBe(false);
    expect(c.state.createdAgentToken).toEqual(createdResult);
    expect(c.state.agentTokens.sa_agent_1).toEqual([createdResult.token]);

    c.actions.acknowledgeCreatedToken();
    expect(c.state.createdAgentToken).toBeNull();
    expect(c.state.agentForToken).toBeNull();
  });

  it("checks custom expiry before revoking an agent token", async () => {
    const c = useUsersController();
    await c.actions.promptGetToken(
      agentFixture({ id: "sa_agent_1", name: "indexer-agent" }),
    );
    c.state.tokenExpiryChoice = "custom";
    c.state.tokenCustomAmount = "1096";
    c.state.tokenCustomUnit = "d";
    await c.actions.confirmTokenGeneration();
    expect(c.state.tokenExpiryError).toContain("1095");
    expect(serviceAccountsApi.revokeAgentToken).not.toHaveBeenCalled();
  });
});
