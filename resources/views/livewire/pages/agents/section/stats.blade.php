<div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
    <x-nawasara-ui::stat-card compact
        icon="shield"
        label="Total agen"
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
        label="Kritis hari ini"
        :value="$criticalToday"
        color="danger" />

    <x-nawasara-ui::stat-card compact
        icon="alert-circle"
        label="Tinggi hari ini"
        :value="$highToday"
        color="warning" />
</div>
