<script setup lang="ts">
import { ref } from "vue";
import { useProjectsController } from "./Projects.controller";
import ProjectRail from "./components/ProjectRail.vue";
import ProjectFilesPanel from "./components/ProjectFilesPanel.vue";
import NameDialog from "./components/NameDialog.vue";
import { DashboardLayout } from "~/layouts";
import {
  DbButton,
  DbConfirmDialog,
  DbEmptyState,
  DbSkeleton,
} from "~/components/ui";
import { BoxIcon, FolderIcon } from "~/assets/icons";
import type { Environment } from "~/services/environments.api";

/**
 * Projects is the authenticated project and environment screen.
 *
 * Projects open directly into one encrypted file tree. Environment tags
 * organize folders and files inside that tree.
 */
const controller = useProjectsController();
const showCreateProject = ref(false);
const environmentDialog = ref<"create" | "rename" | null>(null);
const environmentEditTarget = ref<Environment | null>(null);
const environmentDelete = ref<Environment | null>(null);
const deleteEnvironmentLoading = ref(false);
const deleteEnvironmentError = ref("");
const environmentAffectedCounts = ref<Array<{ label: string; count: number }>>(
  [],
);
// Destructure so refs auto-unwrap in the template.
const { projects, project, fileCreateRequest } = controller;

async function prepareEnvironmentDelete(
  environment: Environment,
): Promise<void> {
  environmentDelete.value = environment;
  deleteEnvironmentError.value = "";
  environmentAffectedCounts.value = [];
  try {
    environmentAffectedCounts.value =
      await controller.describeEnvironmentDeletion(environment.id);
  } catch {
    // Deletion remains protected by name confirmation if the preview fails.
  }
}

function prepareEnvironmentRename(environment: Environment): void {
  environmentEditTarget.value = environment;
  environmentDialog.value = "rename";
}

async function confirmEnvironmentDelete(): Promise<void> {
  if (!environmentDelete.value) return;
  deleteEnvironmentLoading.value = true;
  deleteEnvironmentError.value = "";
  try {
    await controller.deleteEnvironment(environmentDelete.value.id);
    environmentDelete.value = null;
  } catch (cause) {
    deleteEnvironmentError.value =
      cause instanceof Error
        ? cause.message
        : "The environment tag could not be deleted.";
  } finally {
    deleteEnvironmentLoading.value = false;
  }
}
</script>

<template>
  <DashboardLayout>
    <div class="flex min-h-svh">
      <ProjectRail :controller="controller" />

      <section class="min-w-0 flex-1">
        <!-- No projects yet: explain the model -->
        <div v-if="projects && projects.length === 0" class="p-10">
          <DbEmptyState
            title="No projects yet"
            description="A project keeps environments, secrets, and encrypted files together. Create folders for SSH keys, Kubernetes configs, and other project files.">
            <template #icon>
              <BoxIcon class="h-5 w-5" />
            </template>
            <template #actions>
              <DbButton variant="primary" @click="showCreateProject = true">
                Create project
              </DbButton>
            </template>
          </DbEmptyState>
        </div>

        <!-- Loading projects skeleton -->
        <div
          v-else-if="!projects"
          class="flex flex-col"
          data-testid="projects-page-skeleton">
          <!-- Header skeleton -->
          <div
            class="flex items-center justify-between border-b border-line px-6 py-4">
            <DbSkeleton class="h-4 w-40" />
            <DbSkeleton class="h-7 w-36 rounded-control" />
          </div>
          <!-- Body skeleton -->
          <div class="p-6">
            <div class="mb-4 flex items-center justify-between gap-4">
              <DbSkeleton class="h-8 w-64 rounded-control" />
              <div class="flex gap-2">
                <DbSkeleton class="h-8 w-24 rounded-control" />
                <DbSkeleton class="h-8 w-24 rounded-control" />
              </div>
            </div>
            <div
              class="overflow-x-auto rounded-card border border-line bg-panel">
              <table class="min-w-full text-left text-sm">
                <thead>
                  <tr class="border-b border-line">
                    <th class="px-4 py-2.5"><DbSkeleton class="h-3 w-16" /></th>
                    <th class="px-4 py-2.5"><DbSkeleton class="h-3 w-16" /></th>
                    <th class="px-4 py-2.5"><DbSkeleton class="h-3 w-20" /></th>
                    <th class="px-4 py-2.5 text-right">
                      <DbSkeleton class="ml-auto h-3 w-16" />
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="i in 5"
                    :key="i"
                    class="border-b border-line-soft last:border-b-0">
                    <td class="px-4 py-3"><DbSkeleton class="h-4 w-36" /></td>
                    <td class="px-4 py-3">
                      <DbSkeleton class="h-4 w-10 rounded-control" />
                    </td>
                    <td class="px-4 py-3"><DbSkeleton class="h-4 w-20" /></td>
                    <td class="px-4 py-3 text-right">
                      <div class="flex items-center justify-end gap-1">
                        <DbSkeleton class="h-6 w-16 rounded-control" />
                        <DbSkeleton class="h-6 w-6 rounded-control" />
                        <DbSkeleton class="h-6 w-6 rounded-control" />
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <template v-else-if="project">
          <header
            class="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-6 py-4">
            <nav
              class="flex items-center gap-1.5 font-mono text-sm text-ink-muted">
              <span class="font-medium text-ink-strong">{{
                project.name
              }}</span>
            </nav>
          </header>

          <ProjectFilesPanel
            :project-ref="project.id"
            :create-request="fileCreateRequest"
            @create-request-consumed="controller.clearFileCreateRequest"
            @environment-created="controller.loadEnvironments"
            @environment-create-request="environmentDialog = 'create'"
            @environment-rename-request="prepareEnvironmentRename"
            @environment-delete-request="prepareEnvironmentDelete" />
        </template>

        <!-- Projects page without a selected project -->
        <div v-else class="p-10">
          <DbEmptyState
            title="Select a project"
            description="Pick a project from the rail, or create one to get started.">
            <template #icon>
              <FolderIcon class="h-5 w-5" />
            </template>
          </DbEmptyState>
        </div>
      </section>
    </div>

    <!-- Create project from the zero state -->
    <NameDialog
      :open="showCreateProject"
      title="New project"
      label="Project name"
      submit-label="Create"
      hint="Any name up to 128 characters. Control characters are not allowed."
      :action="controller.createProject"
      @close="showCreateProject = false" />

    <NameDialog
      :open="environmentDialog !== null"
      :title="
        environmentDialog === 'rename'
          ? 'Rename environment tag'
          : 'New environment tag'
      "
      label="Tag name"
      :initial-name="
        environmentDialog === 'rename'
          ? (environmentEditTarget?.name ?? '')
          : ''
      "
      :submit-label="environmentDialog === 'rename' ? 'Rename' : 'Create'"
      hint="Tags belong to this project. Use a name such as dev, test, RC, or prod."
      placeholder="e.g. Dev, Prod (EU), RC 1"
      :action="
        (name: string) =>
          environmentDialog === 'rename' && environmentEditTarget
            ? controller.renameEnvironment(environmentEditTarget.id, name)
            : controller.createEnvironment(name)
      "
      @close="
        environmentDialog = null;
        environmentEditTarget = null;
      " />

    <DbConfirmDialog
      :open="environmentDelete !== null"
      title="Delete environment tag"
      :description="`Deleting '${environmentDelete?.name}' removes data scoped to this tag. Files and folders keep their contents but lose the tag and inherit from their parent.`"
      :confirm-word="environmentDelete?.name"
      confirm-label="Delete tag"
      :affected-counts="environmentAffectedCounts"
      :loading="deleteEnvironmentLoading"
      :error="deleteEnvironmentError"
      @confirm="confirmEnvironmentDelete"
      @close="environmentDelete = null" />
  </DashboardLayout>
</template>
