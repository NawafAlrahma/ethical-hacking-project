<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ShodanService
{
    protected string $key;

    public function __construct()
    {
        $this->key = config('services.shodan.key', '');
    }

    /**
     * Only Shodan lookup (IP or domain)
     */
    public function hostInfo(string $value): array
    {
        // Resolve domain to IP if needed
        $ip = $this->isIp($value) ? $value : $this->resolveDomain($value);

        if (!$ip) {
            return $this->emptyResult($value, 'Could not resolve domain to IP.');
        }

        // Query Shodan only
        return $this->queryShodan($ip);
    }

    /**
     * Query Shodan API
     */
    protected function queryShodan(string $ip): array
    {
        if (empty($this->key)) {
            Log::warning('Shodan: No API key', ['target' => $ip]);
            return $this->generateMockShodanData($ip);
        }

        try {
            $url = "https://api.shodan.io/shodan/host/{$ip}?key={$this->key}";
            $response = Http::timeout(15)->get($url);

            if ($response->failed()) {
                $body = $response->json();
                $error = $body['error'] ?? $response->body() ?? 'Unknown error';

                // If Shodan requires membership, fallback to mock
                if (str_contains(strtolower($error), 'requires membership')) {
                    Log::warning("Shodan membership required for IP: $ip");
                    return $this->generateMockShodanData($ip);
                }

                Log::error('Shodan query failed', ['ip' => $ip, 'error' => $error]);
                return $this->emptyResult($ip, $error);
            }

            return $response->json() ?? [];

        } catch (\Exception $e) {
            Log::error('Shodan request exception', [
                'target' => $ip,
                'error' => $e->getMessage()
            ]);

            return $this->emptyResult($ip, $e->getMessage());
        }
    }

    /**
     * Mock Shodan data if access denied
     */
    protected function generateMockShodanData(string $ip): array
    {
        return [
            'ip_str' => $ip,
            'ip' => $ip,
            'ports' => [80, 443, 22],
            'data' => [
                ['port' => 80, 'service' => 'http'],
                ['port' => 443, 'service' => 'https'],
                ['port' => 22, 'service' => 'ssh'],
            ],
            'org' => 'Example ISP',
            'isp' => 'Example ISP',
            'city' => 'Example City',
            'country_name' => 'Example Country',
            '_note' => 'Mock Shodan data (membership required)'
        ];
    }

    protected function isIp(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }

    protected function resolveDomain(string $domain): ?string
    {
        $resolved = gethostbyname($domain);

        if ($resolved === $domain) {
            Log::warning("DNS resolve failed: {$domain}");
            return null;
        }

        return $resolved;
    }

    protected function emptyResult(string $target, string $reason): array
    {
        return [
            'ip_str' => $target,
            'ip' => null,
            'ports' => [],
            'data' => [],
            'org' => null,
            'isp' => null,
            'city' => null,
            'country_name' => null,
            '_note' => $reason
        ];
    }
}
