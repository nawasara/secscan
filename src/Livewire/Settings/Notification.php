<?php

namespace Nawasara\Secscan\Livewire\Settings;

use Illuminate\Support\Facades\Gate;
use Livewire\Component;
use Nawasara\Core\Models\Setting;
use Nawasara\Secscan\Jobs\SendDailyDigestJob;
use Nawasara\Toaster\Concerns\HasToaster;

/**
 * Settings page for security notifications — who receives the daily digest and
 * the real-time alerts, and when the digest goes out.
 *
 * Values live in nawasara_settings (DB) so an operator can change them from the
 * UI without touching .env or redeploying. The config keys still read env as
 * the fallback default, so an untouched deployment behaves as before.
 */
class Notification extends Component
{
    use HasToaster;

    /** Comma/newline separated e-mail list for the daily digest. */
    public string $digestRecipients = '';

    public bool $digestEnabled = true;

    /** HH:MM, server time. */
    public string $digestAt = '07:00';

    public bool $digestSendWhenEmpty = true;

    /** Extra e-mails added to every real-time alert, on top of role groups. */
    public string $alertRecipients = '';

    public function mount(): void
    {
        Gate::authorize('secscan.settings.manage');

        $this->digestRecipients = $this->listToText(
            Setting::get('secscan.digest.recipients', config('nawasara-secscan.digest.recipients', []))
        );
        $this->digestEnabled = (bool) Setting::get('secscan.digest.enabled', config('nawasara-secscan.digest.enabled', true));
        $this->digestAt = (string) Setting::get('secscan.digest.at', config('nawasara-secscan.digest.at', '07:00'));
        $this->digestSendWhenEmpty = (bool) Setting::get('secscan.digest.send_when_empty', config('nawasara-secscan.digest.send_when_empty', true));
        $this->alertRecipients = $this->listToText(
            Setting::get('alerting.extra_recipients', config('nawasara-alerting.extra_recipients.all', []))
        );
    }

    public function save(): void
    {
        Gate::authorize('secscan.settings.manage');

        $digest = $this->parseEmails($this->digestRecipients);
        $alerts = $this->parseEmails($this->alertRecipients);

        $this->validate([
            'digestAt' => ['required', 'regex:/^([01]?\d|2[0-3]):[0-5]\d$/'],
        ], [
            'digestAt.regex' => 'Format jam harus HH:MM (mis. 07:00).',
        ]);

        if ($invalid = $this->invalidEmails($this->digestRecipients)) {
            $this->addError('digestRecipients', 'Email tidak valid: '.implode(', ', $invalid));

            return;
        }
        if ($invalid = $this->invalidEmails($this->alertRecipients)) {
            $this->addError('alertRecipients', 'Email tidak valid: '.implode(', ', $invalid));

            return;
        }

        Setting::set('secscan.digest.recipients', $digest);
        Setting::set('secscan.digest.enabled', $this->digestEnabled);
        Setting::set('secscan.digest.at', $this->digestAt);
        Setting::set('secscan.digest.send_when_empty', $this->digestSendWhenEmpty);
        Setting::set('alerting.extra_recipients', $alerts);

        $this->alert('success', 'Pengaturan notifikasi disimpan.');
    }

    /** Send the digest right now to the saved recipients — proves the setup works. */
    public function sendTest(): void
    {
        Gate::authorize('secscan.settings.manage');

        if (empty($this->parseEmails($this->digestRecipients))) {
            $this->alert('warning', 'Isi dulu email penerima laporan, lalu simpan.');

            return;
        }

        SendDailyDigestJob::dispatch();
        $this->alert('success', 'Laporan uji dikirim — cek inbox dalam 1–2 menit.');
    }

    /** @return list<string> */
    protected function parseEmails(string $raw): array
    {
        return collect(preg_split('/[\s,;]+/', $raw) ?: [])
            ->map(fn ($e) => trim($e))
            ->filter(fn ($e) => $e !== '' && filter_var($e, FILTER_VALIDATE_EMAIL))
            ->unique()
            ->values()
            ->all();
    }

    /** @return list<string> entries that are non-empty but not valid e-mails */
    protected function invalidEmails(string $raw): array
    {
        return collect(preg_split('/[\s,;]+/', $raw) ?: [])
            ->map(fn ($e) => trim($e))
            ->filter(fn ($e) => $e !== '' && ! filter_var($e, FILTER_VALIDATE_EMAIL))
            ->values()
            ->all();
    }

    protected function listToText(mixed $value): string
    {
        if (is_string($value)) {
            $value = array_filter(array_map('trim', explode(',', $value)));
        }

        return implode(', ', (array) $value);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.settings.notification')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
