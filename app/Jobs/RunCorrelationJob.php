<?php

namespace App\Jobs;

use App\Models\Correlation;
use App\Models\Target;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Foundation\Bus\Dispatchable;

class RunCorrelationJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $targetId;

    public function __construct(int $targetId)
    {
        $this->targetId = $targetId;
    }

    public function handle(): void
    {
        $target = Target::with('findings')->find($this->targetId);

        if (!$target) {
            return;
        }

        $added = []; // prevent duplicates

        foreach ($target->findings as $finding) {

            $raw = $finding->raw_data;

            if (!isset($raw['data'])) {
                continue;
            }

            foreach ($raw['data'] as $service) {

                $port = $service['port'] ?? null;

                /*
                |--------------------------------------------------------------------------
                | 1) DNS Recursion Enabled
                |--------------------------------------------------------------------------
                */
                if (isset($service['dns']['recursive']) && $service['dns']['recursive'] === true) {

                    $key = "dns_rec_$port";
                    if (!isset($added[$key])) {

                        Correlation::create([
                            'target_id' => $target->id,
                            'vuln_name' => 'DNS Recursion Enabled',
                            'cve_id' => 'CVE-1999-0024',
                            'severity' => 'medium',
                            'score' => 5.8,
                            'evidence' => "Recursive DNS resolver on port $port",
                            'description' => 'DNS resolvers with recursion enabled can be abused for amplification attacks.',
                            'recommendation' => 'Disable recursion or restrict it using ACLs.',
                            'ai_exploit_pseudo_code' => $this->generatePseudoCode('DNS Recursion Enabled'),
                        ]);

                        $added[$key] = true;
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 2) Weak SSL/TLS Protocols
                |--------------------------------------------------------------------------
                */
                if (isset($service['ssl']['versions'])) {

                    foreach ($service['ssl']['versions'] as $ver) {

                        if (str_contains($ver, 'SSLv') || $ver === 'TLSv1') {

                            $key = "weakssl_{$port}_{$ver}";

                            if (!isset($added[$key])) {

                                Correlation::create([
                                    'target_id' => $target->id,
                                    'vuln_name' => 'Weak TLS/SSL Version Supported',
                                    'cve_id' => 'N/A',
                                    'severity' => 'medium',
                                    'score' => 6.0,
                                    'evidence' => "Insecure protocol: $ver",
                                    'description' => 'Outdated TLS/SSL protocols are vulnerable to downgrade and MITM attacks.',
                                    'recommendation' => 'Disable SSLv2, SSLv3, TLS1.0; enforce TLS1.2 or TLS1.3.',
                                    'ai_exploit_pseudo_code' => $this->generatePseudoCode('Weak TLS/SSL Version Supported'),
                                ]);

                                $added[$key] = true;
                            }
                        }
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 3) Missing X-Frame-Options Header
                |--------------------------------------------------------------------------
                */
                $headers = strtolower(json_encode($service['http']['headers'] ?? ''));

                if (!str_contains($headers, 'x-frame-options')) {

                    $key = "xfo_$port";

                    if (!isset($added[$key])) {

                        Correlation::create([
                            'target_id' => $target->id,
                            'vuln_name' => 'Missing X-Frame-Options Header',
                            'cve_id' => 'N/A',
                            'severity' => 'low',
                            'score' => 3.0,
                            'evidence' => 'Header missing from HTTP response.',
                            'description' => 'Lack of the header allows clickjacking attacks.',
                            'recommendation' => 'Add header: X-Frame-Options: SAMEORIGIN or DENY.',
                            'ai_exploit_pseudo_code' => $this->generatePseudoCode('Missing X-Frame-Options Header'),
                        ]);

                        $added[$key] = true;
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 4) High-Risk Open Ports
                |--------------------------------------------------------------------------
                */
                $dangerous = [21, 23, 25, 445, 3306, 3389];

                foreach (($raw['ports'] ?? []) as $p) {

                    if (in_array($p, $dangerous)) {

                        $key = "danger_port_$p";

                        if (!isset($added[$key])) {

                            Correlation::create([
                                'target_id' => $target->id,
                                'vuln_name' => 'High-Risk Open Port',
                                'cve_id' => 'N/A',
                                'severity' => 'medium',
                                'score' => 5.0,
                                'evidence' => "Open port: $p",
                                'description' => 'This port is commonly targeted for brute-force, malware or exploitation.',
                                'recommendation' => 'Close unused ports or restrict using firewall rules.',
                                'ai_exploit_pseudo_code' => $this->generatePseudoCode('High-Risk Open Port'),
                            ]);

                            $added[$key] = true;
                        }
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 5) Outdated Web Server Versions
                |--------------------------------------------------------------------------
                */
                if (isset($service['http']['server'])) {
                    $server = strtolower($service['http']['server']);
                    $outdatedServers = ['apache/2.2', 'apache/2.0', 'nginx/1.0', 'iis/6', 'iis/7'];

                    foreach ($outdatedServers as $oldServer) {
                        if (str_contains($server, $oldServer)) {
                            $key = "outdated_server_{$port}_{$oldServer}";
                            if (!isset($added[$key])) {
                                Correlation::create([
                                    'target_id' => $target->id,
                                    'vuln_name' => 'Outdated Web Server Version',
                                    'cve_id' => 'CVE-2009-3555',
                                    'severity' => 'high',
                                    'score' => 7.5,
                                    'evidence' => "Server: $server on port $port",
                                    'description' => 'Outdated web server versions contain known vulnerabilities that can be exploited for remote code execution or privilege escalation.',
                                    'recommendation' => 'Update to the latest stable version of the web server and apply all security patches.',
                                    'ai_exploit_pseudo_code' => $this->generatePseudoCode('Outdated Web Server Version'),
                                ]);
                                $added[$key] = true;
                            }
                        }
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 6) Missing Security Headers
                |--------------------------------------------------------------------------
                */
                if (isset($service['http']['headers'])) {
                    $headers = array_map('strtolower', array_keys($service['http']['headers']));
                    $requiredHeaders = ['strict-transport-security', 'x-content-type-options', 'x-xss-protection'];

                    foreach ($requiredHeaders as $header) {
                        if (!in_array($header, $headers)) {
                            $key = "missing_header_{$port}_{$header}";
                            if (!isset($added[$key])) {
                                $severity = $header === 'strict-transport-security' ? 'high' : 'medium';
                                $score = $header === 'strict-transport-security' ? 6.5 : 4.5;

                                Correlation::create([
                                    'target_id' => $target->id,
                                    'vuln_name' => 'Missing Security Header: ' . ucfirst(str_replace('-', ' ', $header)),
                                    'cve_id' => 'N/A',
                                    'severity' => $severity,
                                    'score' => $score,
                                    'evidence' => "Header missing from HTTP response on port $port",
                                    'description' => "The $header header is not present. This header helps protect against various web-based attacks.",
                                    'recommendation' => "Add the $header header to all HTTP responses.",
                                    'ai_exploit_pseudo_code' => $this->generatePseudoCode('Missing Security Header'),
                                ]);
                                $added[$key] = true;
                            }
                        }
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 7) Weak Cipher Suites
                |--------------------------------------------------------------------------
                */
                if (isset($service['ssl']['ciphers'])) {
                    $weakCiphers = ['MD5', 'DES', 'RC4', 'NULL', 'EXPORT', 'anon'];
                    foreach ($service['ssl']['ciphers'] as $cipher) {
                        foreach ($weakCiphers as $weak) {
                            if (str_contains(strtoupper($cipher), $weak)) {
                                $key = "weak_cipher_{$port}_{$cipher}";
                                if (!isset($added[$key])) {
                                    Correlation::create([
                                        'target_id' => $target->id,
                                        'vuln_name' => 'Weak SSL/TLS Cipher Suite',
                                        'cve_id' => 'N/A',
                                        'severity' => 'high',
                                        'score' => 7.0,
                                        'evidence' => "Weak cipher: $cipher on port $port",
                                        'description' => 'Weak cipher suites can be exploited to decrypt SSL/TLS communications.',
                                        'recommendation' => 'Disable weak ciphers and use only strong cipher suites (AES-GCM, ChaCha20-Poly1305).',
                                        'ai_exploit_pseudo_code' => $this->generatePseudoCode('Weak SSL/TLS Cipher Suite'),
                                    ]);
                                    $added[$key] = true;
                                }
                            }
                        }
                    }
                }

                /*
                |--------------------------------------------------------------------------
                | 8) Self-Signed or Expired Certificates
                |--------------------------------------------------------------------------
                */
                if (isset($service['ssl']['cert'])) {
                    $cert = $service['ssl']['cert'];
                    if (isset($cert['self_signed']) && $cert['self_signed'] === true) {
                        $key = "self_signed_cert_{$port}";
                        if (!isset($added[$key])) {
                            Correlation::create([
                                'target_id' => $target->id,
                                'vuln_name' => 'Self-Signed SSL/TLS Certificate',
                                'cve_id' => 'N/A',
                                'severity' => 'medium',
                                'score' => 5.5,
                                'evidence' => "Self-signed certificate detected on port $port",
                                'description' => 'Self-signed certificates are not trusted by browsers and can enable MITM attacks.',
                                'recommendation' => 'Obtain a certificate from a trusted Certificate Authority (CA).',
                                'ai_exploit_pseudo_code' => $this->generatePseudoCode('Self-Signed SSL/TLS Certificate'),
                            ]);
                            $added[$key] = true;
                        }
                    }
                }

            } // end foreach service
        } // end foreach finding

        /*
        |--------------------------------------------------------------------------
        | AI-Based Classification and Remediation (Pseudo-code)
        |--------------------------------------------------------------------------
        | This section demonstrates how AI/LLM integration would work:
        | 1. Collect all correlations for the target
        | 2. Send to LLM for intelligent classification and prioritization
        | 3. Generate contextual remediation recommendations
        |
        | Example pseudo-code (would require OpenAI API key):
        |
        | $correlations = Correlation::where('target_id', $target->id)->get();
        | $findings_summary = $correlations->map(function($c) {
        |     return $c->vuln_name . ': ' . $c->description;
        | })->join('; ');
        |
        | // Call AI service for enhanced classification
        | try {
        |     $client = new OpenAI(['api_key' => config('services.openai.key')]);
        |     $response = $client->chat()->create([
        |         'model' => 'gpt-4-mini',
        |         'messages' => [[
        |             'role' => 'system',
        |             'content' => 'You are a cybersecurity expert. Analyze vulnerabilities and provide prioritized remediation steps.',
        |         ], [
        |             'role' => 'user',
        |             'content' => "Analyze these vulnerabilities and provide priority-based remediation: $findings_summary",
        |         ]],
        |     ]);
        |
        |     $ai_recommendations = $response->choices[0]->message->content;
        |
        |     // Update correlations with AI-enhanced recommendations
        |     foreach ($correlations as $corr) {
        |         $corr->update([
        |             'recommendation' => $ai_recommendations . ' [AI-Enhanced]'
        |         ]);
        |     }
        | } catch (\Exception $e) {
        |     // Log AI service errors but continue with standard recommendations
        |     \Log::warning('AI service unavailable: ' . $e->getMessage());
        | }
        |--------------------------------------------------------------------------
        */

        $target->update(['status' => 'correlated']);
    }

    /**
     * Generate non-executable pseudo-code for a given vulnerability.
     * Re-written using switch statement for compatibility with older PHP versions.
     */
    private function generatePseudoCode(string $vulnName): string
    {
        switch ($vulnName) {
            case 'DNS Recursion Enabled':
                return <<<CODE
# Pseudo-code for DNS Amplification Attack
# Target: \$target_ip:\$port

function check_recursion(\$target_ip) {
    send_dns_query(\$target_ip, "ANY example.com", RECURSION_DESIRED=True)
    if response_size > query_size:
        return "VULNERABLE"
    else:
        return "NOT VULNERABLE"
}

function amplify_attack(\$target_ip, \$victim_ip) {
    for i in range(1000):
        send_dns_query(\$target_ip, "ANY large_record.com", SOURCE_IP=\$victim_ip)
    print("Sent 1000 amplified queries to victim")
}

# This code is for demonstration only and is non-executable.
CODE;

            case 'Weak TLS/SSL Version Supported':
                return <<<CODE
# Pseudo-code for Downgrade Attack (e.g., POODLE)
# Target: \$target_ip:\$port

function check_weak_tls(\$target_ip, \$port) {
    try:
        connect_ssl(\$target_ip, \$port, PROTOCOL="SSLv3")
        print("Connection successful with SSLv3")
        return "VULNERABLE"
    except:
        return "NOT VULNERABLE"
}

# This code is for demonstration only and is non-executable.
CODE;

            case 'Missing X-Frame-Options Header':
                return <<<CODE
# Pseudo-code for Clickjacking Attack
# Target: \$target_url

html_payload = <<<HTML
<html>
  <head>
    <title>Clickjacking Demo</title>
  </head>
  <body>
    <iframe src="\$target_url" style="opacity:0.001; position:absolute; top:0; left:0; width:100%; height:100%;"></iframe>
    <button style="position:absolute; top:100px; left:100px;">Click Me to Exploit</button>
  </body>
</html>
HTML;
save_to_file("clickjack_demo.html", html_payload)
print("Clickjacking HTML payload generated.")

# This code is for demonstration only and is non-executable.
CODE;

            case 'High-Risk Open Port':
                return <<<CODE
# Pseudo-code for Brute-Force Attack (e.g., SSH on port 22)
# Target: \$target_ip:\$port

usernames = load_wordlist("users.txt")
passwords = load_wordlist("passwords.txt")

for user in usernames:
    for password in passwords:
        if attempt_login(\$target_ip, \$port, user, password):
            print("SUCCESS: {user}:{password}")
            return
print("Brute-force attempt finished.")

# This code is for demonstration only and is non-executable.
CODE;

            case 'Outdated Web Server Version':
                return <<<CODE
# Pseudo-code for Remote Code Execution (RCE) via known exploit
# Target: \$target_url

exploit_module = load_exploit("CVE-2009-3555_apache_rce")
payload = "system('whoami')"

exploit_module.set_target(\$target_url)
exploit_module.set_payload(payload)
result = exploit_module.execute()

print("Exploit result: {result}")

# This code is for demonstration only and is non-executable.
CODE;

            case 'Missing Security Header':
                return <<<CODE
# Pseudo-code for Cross-Site Scripting (XSS) or Man-in-the-Middle (MITM)
# Target: \$target_url

if header == "Strict-Transport-Security" is missing:
    print("Target is vulnerable to SSL Stripping/MITM attacks.")
    # MITM code simulation...

if header == "X-Content-Type-Options" is missing:
    print("Target is vulnerable to MIME-type sniffing attacks.")
    # MIME-sniffing code simulation...

# This code is for demonstration only and is non-executable.
CODE;

            case 'Weak SSL/TLS Cipher Suite':
                return <<<CODE
# Pseudo-code for Cipher Exploitation (e.g., Sweet32)
# Target: \$target_ip:\$port

function check_weak_cipher(\$target_ip, \$port) {
    cipher_list = get_supported_ciphers(\$target_ip, \$port)
    if "3DES" in cipher_list or "RC4" in cipher_list:
        print("Weak cipher detected. Data can be decrypted.")
        return "VULNERABLE"
    else:
        return "NOT VULNERABLE"
}

# This code is for demonstration only and is non-executable.
CODE;

            case 'Self-Signed SSL/TLS Certificate':
                return <<<CODE
# Pseudo-code for Man-in-the-Middle (MITM) Attack
# Target: \$target_ip:\$port

function mitm_attack(\$target_ip, \$port) {
    # Set up a proxy server
    proxy = start_proxy_server()

    # Generate a fake certificate signed by the self-signed cert
    fake_cert = generate_fake_cert(\$target_ip)

    # Intercept traffic and present fake certificate
    intercept_traffic(\$target_ip, \$port, fake_cert)

    print("MITM proxy is running. User must ignore certificate warning.")
}

# This code is for demonstration only and is non-executable.
CODE;

            default:
                return "# Pseudo-code not available for this vulnerability: $vulnName";
        }
    }
}
