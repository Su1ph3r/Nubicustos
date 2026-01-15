<template>
  <div class="enumerate-iam-view">
    <div class="page-header">
      <div class="header-content">
        <h1>enumerate-iam</h1>
        <p class="subtitle">
          IAM permission enumeration results
        </p>
      </div>
      <div class="header-actions">
        <Button
          v-if="!isRunning"
          v-tooltip.left="!hasAwsCredentials ? 'Select AWS profile in Credentials first' : ''"
          label="Run Enumeration"
          icon="pi pi-play"
          :loading="store.loading"
          :disabled="!hasAwsCredentials"
          @click="runEnumeration"
        />
        <Button
          v-else
          label="Stop"
          icon="pi pi-stop"
          severity="danger"
          @click="stopExecution"
        />
      </div>
    </div>

    <!-- Execution Status Panel -->
    <ExecutionProgressPanel
      :execution="store.currentExecution"
      tool-name="IAM enumeration"
      description="Testing AWS API permissions. This may take 5-15 minutes depending on the number of API calls."
      :logs="executionLogs"
      @dismiss="dismissExecution"
      @view-results="store.fetchResults()"
    />

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_principals }}
        </div>
        <div class="card-label">
          Total Principals
        </div>
      </div>
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.admin_capable }}
        </div>
        <div class="card-label">
          Admin Capable
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.privesc_capable }}
        </div>
        <div class="card-label">
          Privesc Capable
        </div>
      </div>
      <div class="summary-card medium">
        <div class="card-value">
          {{ store.summary.data_access_capable }}
        </div>
        <div class="card-label">
          Data Access
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Button
        :label="showHighRiskOnly ? 'Show All' : 'Show High Risk'"
        :icon="showHighRiskOnly ? 'pi pi-list' : 'pi pi-exclamation-triangle'"
        @click="toggleHighRisk"
      />
    </div>

    <DataTable
      :value="store.results"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="principal_name"
        header="Principal"
      />
      <Column
        field="principal_type"
        header="Type"
      />
      <Column
        field="permission_count"
        header="Permissions"
      />
      <Column
        field="privesc_capable"
        header="Privesc"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.privesc_capable ? 'danger' : 'success'"
            :value="data.privesc_capable ? 'Yes' : 'No'"
          />
        </template>
      </Column>
      <Column
        field="admin_capable"
        header="Admin"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.admin_capable ? 'danger' : 'success'"
            :value="data.admin_capable ? 'Yes' : 'No'"
          />
        </template>
      </Column>
      <Column
        field="data_access_capable"
        header="Data Access"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.data_access_capable ? 'warning' : 'success'"
            :value="data.data_access_capable ? 'Yes' : 'No'"
          />
        </template>
      </Column>
      <Column header="Actions">
        <template #body="{ data }">
          <Button
            icon="pi pi-eye"
            text
            @click="viewPermissions(data.id)"
          />
        </template>
      </Column>
    </DataTable>

    <Paginator
      v-if="store.pagination.total > store.pagination.pageSize"
      :rows="store.pagination.pageSize"
      :total-records="store.pagination.total"
      :first="(store.pagination.page - 1) * store.pagination.pageSize"
      @page="onPageChange"
    />

    <!-- Permissions Detail Dialog -->
    <Dialog
      v-model:visible="showPermissionsDialog"
      :header="selectedPermissions?.principal_name || 'Permission Details'"
      :style="{ width: '800px', maxWidth: '95vw' }"
      :modal="true"
      :dismissable-mask="true"
    >
      <div
        v-if="selectedPermissions"
        class="permissions-dialog"
      >
        <div class="principal-info">
          <div class="info-row">
            <span class="info-label">Principal ARN:</span>
            <code class="info-value">{{ selectedPermissions.principal_arn || 'N/A' }}</code>
          </div>
          <div class="info-row">
            <span class="info-label">Total Confirmed:</span>
            <Tag
              :value="String(selectedPermissions.total_confirmed)"
              severity="info"
            />
          </div>
        </div>

        <div class="capabilities-row">
          <Tag
            :severity="selectedPermissions.capabilities?.admin_capable ? 'danger' : 'success'"
            :value="selectedPermissions.capabilities?.admin_capable ? 'Admin Capable' : 'No Admin'"
            class="capability-tag"
          />
          <Tag
            :severity="selectedPermissions.capabilities?.privesc_capable ? 'danger' : 'success'"
            :value="selectedPermissions.capabilities?.privesc_capable ? 'Privesc Capable' : 'No Privesc'"
            class="capability-tag"
          />
          <Tag
            :severity="selectedPermissions.capabilities?.data_access_capable ? 'warning' : 'success'"
            :value="selectedPermissions.capabilities?.data_access_capable ? 'Data Access' : 'No Data Access'"
            class="capability-tag"
          />
        </div>

        <TabView>
          <TabPanel :header="`Confirmed (${selectedPermissions.confirmed_permissions?.length || 0})`">
            <div class="permissions-list">
              <div
                v-for="perm in selectedPermissions.confirmed_permissions"
                :key="perm"
                class="permission-item confirmed"
              >
                <i class="pi pi-check-circle" />
                <code>{{ perm }}</code>
              </div>
              <div
                v-if="!selectedPermissions.confirmed_permissions?.length"
                class="no-permissions"
              >
                No confirmed permissions found
              </div>
            </div>
          </TabPanel>
          <TabPanel :header="`High Risk (${selectedPermissions.high_risk_permissions?.length || 0})`">
            <div class="permissions-list">
              <div
                v-for="perm in selectedPermissions.high_risk_permissions"
                :key="perm"
                class="permission-item high-risk"
              >
                <i class="pi pi-exclamation-triangle" />
                <code>{{ perm }}</code>
              </div>
              <div
                v-if="!selectedPermissions.high_risk_permissions?.length"
                class="no-permissions"
              >
                No high-risk permissions found
              </div>
            </div>
          </TabPanel>
          <TabPanel :header="`Denied (${selectedPermissions.denied_permissions?.length || 0})`">
            <div class="permissions-list">
              <div
                v-for="perm in selectedPermissions.denied_permissions"
                :key="perm"
                class="permission-item denied"
              >
                <i class="pi pi-times-circle" />
                <code>{{ perm }}</code>
              </div>
              <div
                v-if="!selectedPermissions.denied_permissions?.length"
                class="no-permissions"
              >
                No denied permissions recorded
              </div>
            </div>
          </TabPanel>
          <TabPanel :header="`Errors (${selectedPermissions.error_permissions?.length || 0})`">
            <div class="permissions-list">
              <div
                v-for="perm in selectedPermissions.error_permissions"
                :key="perm"
                class="permission-item error"
              >
                <i class="pi pi-info-circle" />
                <code>{{ perm }}</code>
              </div>
              <div
                v-if="!selectedPermissions.error_permissions?.length"
                class="no-permissions"
              >
                No error permissions recorded
              </div>
            </div>
          </TabPanel>
        </TabView>
      </div>
      <div
        v-else
        class="loading-permissions"
      >
        <i class="pi pi-spin pi-spinner" />
        Loading permissions...
      </div>
    </Dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useEnumerateIamStore } from '../stores/enumerateIam'
import { useExecutionsStore } from '../stores/executions'
import { useCredentialsStore } from '../stores/credentials'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Paginator from 'primevue/paginator'
import Dialog from 'primevue/dialog'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import ExecutionProgressPanel from '../components/executions/ExecutionProgressPanel.vue'

const store = useEnumerateIamStore()
const executionsStore = useExecutionsStore()
const credentialsStore = useCredentialsStore()
const toast = useToast()
const showHighRiskOnly = ref(false)
const executionLogs = ref(null)
const showPermissionsDialog = ref(false)
const selectedPermissions = ref(null)

const hasAwsCredentials = computed(() => {
  return credentialsStore.sessionCredentials?.aws !== null
})

const isRunning = computed(() =>
  store.currentExecution?.status === 'running',
)

function toggleHighRisk() {
  showHighRiskOnly.value = !showHighRiskOnly.value
  if (showHighRiskOnly.value) {
    store.fetchHighRisk()
  } else {
    store.fetchResults()
  }
}

async function viewPermissions(id) {
  selectedPermissions.value = null
  showPermissionsDialog.value = true
  try {
    const perms = await store.fetchPermissions(id)
    selectedPermissions.value = perms
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load permissions', life: 3000 })
    showPermissionsDialog.value = false
  }
}

async function runEnumeration() {
  if (!hasAwsCredentials.value) {
    toast.add({ severity: 'warn', summary: 'No Credentials', detail: 'Select an AWS profile in Credentials first', life: 3000 })
    return
  }
  executionLogs.value = null
  try {
    await store.runEnumeration({})
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: e.message, life: 5000 })
  }
}

async function stopExecution() {
  await store.stopCurrentExecution()
}

function dismissExecution() {
  store.currentExecution = null
  executionLogs.value = null
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  if (showHighRiskOnly.value) {
    store.fetchHighRisk()
  } else {
    store.fetchResults()
  }
}

onMounted(() => {
  store.fetchResults()
  store.fetchSummary()
})

onUnmounted(() => {
  // Stop any polling when leaving the view
  if (store.currentExecution?.execution_id) {
    executionsStore.stopPolling(store.currentExecution.execution_id)
  }
})
</script>

<style scoped>
.enumerate-iam-view { padding: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.summary-card {
  padding: 1rem;
  border-radius: 8px;
  background: var(--surface-card);
  border-left: 4px solid;
}
.summary-card.info { border-left-color: var(--blue-500); }
.summary-card.critical { border-left-color: var(--red-500); }
.summary-card.high { border-left-color: var(--orange-500); }
.summary-card.medium { border-left-color: var(--yellow-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { margin-bottom: 1rem; }

/* Permissions Dialog */
.permissions-dialog { display: flex; flex-direction: column; gap: 1rem; }
.principal-info {
  background: var(--surface-ground);
  padding: 1rem;
  border-radius: 8px;
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
}
.info-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.info-label {
  font-weight: 600;
  color: var(--text-color-secondary);
}
.info-value {
  background: var(--surface-card);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.85rem;
  word-break: break-all;
}
.capabilities-row {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.capability-tag { font-size: 0.85rem; }
.permissions-list {
  max-height: 400px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.permission-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem;
  border-radius: 4px;
  background: var(--surface-ground);
}
.permission-item code {
  font-size: 0.85rem;
  word-break: break-all;
}
.permission-item.confirmed i { color: var(--green-500); }
.permission-item.high-risk { background: rgba(239, 68, 68, 0.1); }
.permission-item.high-risk i { color: var(--red-500); }
.permission-item.denied i { color: var(--red-400); }
.permission-item.error i { color: var(--yellow-500); }
.no-permissions {
  text-align: center;
  padding: 2rem;
  color: var(--text-color-secondary);
}
.loading-permissions {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 2rem;
  color: var(--text-color-secondary);
}
</style>
