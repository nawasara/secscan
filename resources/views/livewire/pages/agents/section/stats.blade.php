<div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
    <x-nawasara-ui::stat-card compact
        icon="shield"
        label="Total Agents"
        :value="$totalAgents"
        color="neutral" />

    <x-nawasara-ui::stat-card compact
        icon="wifi"
        label="Online"
        :value="$onlineAgents"
        color="success" />

    <x-nawasara-ui::stat-card compact
        icon="wifi-off"
        label="Offline"
        :value="$offlineAgents"
        color="danger" />

    <x-nawasara-ui::stat-card compact
        icon="alert-triangle"
        label="Critical Hari Ini"
        :value="$criticalToday"
        color="danger" />

    <x-nawasara-ui::stat-card compact
        icon="alert-circle"
        label="High Hari Ini"
        :value="$highToday"
        color="warning" />
</div>
