{{-- Inner content only — wrapped by nawasara-notification::mail.layout.
     Inline styles only; mail clients ignore <style>/classes. --}}
@php
    $sevColor = [
        'critical' => '#b91c1c',
        'high'     => '#c2410c',
        'medium'   => '#b45309',
        'low'      => '#0369a1',
        'info'     => '#475569',
    ];
    $typeLabel = fn ($t) => ucwords(str_replace('_', ' ', $t));
@endphp

{{-- $label is the human window description passed by the job (e.g. "24 jam terakhir"). --}}
<p style="margin:0 0 4px 0;">Ringkasan keamanan <strong>{{ $label }}</strong></p>
<p style="margin:0 0 16px 0;font-size:13px;color:#71717a;">
    Periode: {{ $start->format('d M Y H:i') }} – {{ $end->format('d M Y H:i') }} WIB
</p>

{{-- Headline number --}}
<table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:18px;">
    <tr>
        <td style="padding:14px 16px;border:1px solid #e4e4e7;border-radius:8px;background:#fafafa;">
            <div style="font-size:32px;font-weight:700;line-height:1;color:{{ $total > 0 ? '#b91c1c' : '#15803d' }};">
                {{ $total }}
            </div>
            <div style="font-size:13px;color:#52525b;margin-top:4px;">insiden keamanan terdeteksi</div>
        </td>
    </tr>
</table>

@if ($total === 0)
    <p style="padding:12px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;color:#15803d;">
        Tidak ada insiden pada periode ini. Semua terpantau normal.
    </p>
@else

    {{-- Per severity --}}
    @if (!empty($bySeverity))
        <p style="margin:0 0 6px 0;font-weight:600;font-size:14px;">Berdasarkan Tingkat</p>
        <table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:16px;border:1px solid #e4e4e7;border-radius:8px;">
            @foreach ($bySeverity as $sev => $n)
                <tr>
                    <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;font-size:14px;">
                        <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{{ $sevColor[$sev] ?? '#71717a' }};margin-right:8px;"></span>
                        {{ ucfirst($sev) }}
                    </td>
                    <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;text-align:right;font-weight:600;font-size:14px;">{{ $n }}</td>
                </tr>
            @endforeach
        </table>
    @endif

    {{-- Per type --}}
    @if (!empty($byType))
        <p style="margin:0 0 6px 0;font-weight:600;font-size:14px;">Jenis Serangan Teratas</p>
        <table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:16px;border:1px solid #e4e4e7;border-radius:8px;">
            @foreach ($byType as $type => $n)
                <tr>
                    <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;font-size:14px;">{{ $typeLabel($type) }}</td>
                    <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;text-align:right;font-weight:600;font-size:14px;">{{ $n }}</td>
                </tr>
            @endforeach
        </table>
    @endif

    {{-- Targeted hosts (subdomain) --}}
    @if (!empty($topHosts))
        <p style="margin:0 0 6px 0;font-weight:600;font-size:14px;">Situs / Subdomain yang Diserang</p>
        <table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:16px;border:1px solid #e4e4e7;border-radius:8px;">
            @foreach ($topHosts as $host => $n)
                <tr>
                    <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;font-family:monospace;font-size:13px;">{{ $host }}</td>
                    <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;text-align:right;font-weight:600;font-size:14px;">{{ $n }}</td>
                </tr>
            @endforeach
        </table>
    @endif

    {{-- Top attacker IPs --}}
    @if (!empty($topIps))
        <p style="margin:0 0 6px 0;font-weight:600;font-size:14px;">IP Penyerang Teratas</p>
        <table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:16px;border:1px solid #e4e4e7;border-radius:8px;">
            <tr style="background:#fafafa;">
                <td style="padding:6px 14px;font-size:12px;color:#71717a;">IP</td>
                <td style="padding:6px 14px;font-size:12px;color:#71717a;text-align:right;">Insiden</td>
                <td style="padding:6px 14px;font-size:12px;color:#71717a;text-align:right;">Skor</td>
            </tr>
            @foreach ($topIps as $row)
                <tr>
                    <td style="padding:8px 14px;border-top:1px solid #f4f4f5;font-family:monospace;font-size:13px;">{{ $row['ip'] }}</td>
                    <td style="padding:8px 14px;border-top:1px solid #f4f4f5;text-align:right;font-size:14px;">{{ $row['count'] }}</td>
                    <td style="padding:8px 14px;border-top:1px solid #f4f4f5;text-align:right;font-size:14px;">{{ $row['score'] }}</td>
                </tr>
            @endforeach
        </table>
    @endif
@endif

{{-- Defence summary --}}
<p style="margin:0 0 6px 0;font-weight:600;font-size:14px;">Pertahanan &amp; Agent</p>
<table cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:18px;border:1px solid #e4e4e7;border-radius:8px;">
    <tr>
        <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;font-size:14px;">IP di-block periode ini</td>
        <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;text-align:right;font-weight:600;font-size:14px;">{{ $blocked }}</td>
    </tr>
    <tr>
        <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;font-size:14px;">Total block aktif di Cloudflare</td>
        <td style="padding:8px 14px;border-bottom:1px solid #f4f4f5;text-align:right;font-weight:600;font-size:14px;">{{ $blockedActive }}</td>
    </tr>
    <tr>
        <td style="padding:8px 14px;font-size:14px;">Agent online</td>
        <td style="padding:8px 14px;text-align:right;font-weight:600;font-size:14px;">
            <span style="color:{{ $agentsOnline < $agentsTotal ? '#b45309' : '#15803d' }};">{{ $agentsOnline }}</span> / {{ $agentsTotal }}
        </td>
    </tr>
</table>

<p style="margin:18px 0;">
    <a href="{{ $dashboardUrl }}/nawasara-secscan/incidents"
       style="display:inline-block;background:#16a34a;color:#ffffff;text-decoration:none;padding:11px 22px;border-radius:6px;font-weight:600;font-size:14px;">
        Buka Dashboard Keamanan
    </a>
</p>

<p style="font-size:12px;color:#71717a;margin-top:16px;">
    Laporan otomatis dari Nawasara Security Scan. Ubah penerima lewat
    <code style="font-family:monospace;">SECSCAN_DIGEST_RECIPIENTS</code> di konfigurasi server.
</p>
