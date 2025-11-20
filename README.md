# OSINT Automated Collection, Correlation & Safe Verification System
### ITSS451 — Ethical Hacking and Network Defense
### Final Project — Fall 2025 / CEIT

## Overview
This project implements a fully automated platform for collecting, correlating, and safely verifying OSINT (Open-Source Intelligence) related to Internet-exposed assets. The system accepts multiple target types (IP addresses, domains) and processes them through a complete, non-destructive cybersecurity workflow.

## Key Features
- Add and manage OSINT targets
- Automated OSINT ingestion from Shodan
- Correlation engine for identifying potential vulnerabilities
- AI-assisted scoring, classification & pseudo-code generation (non-executable)
- Safe verification (read-only)
- Historical comparison & re-check
- Full audit trail (verification logs + raw findings)
- Clean and responsive UI

## System Architecture
### Frontend
- index.blade.php
- show.blade.php
- compare.blade.php
- create.blade.php
- app.blade.php

### OSINT Collection
- ShodanService.php
- CollectOsintJob.php

### Correlation Engine
- RunCorrelationJob.php
- Correlation.php

### Safe Verification
- VerifyFindingsJob.php
- VerificationLog.php

### Models
- Target.php
- Finding.php
- Correlation.php
- VerificationLog.php

### Routing
- routes/web.php

## Workflow
1. Add Target
2. OSINT Ingestion via Shodan
3. Correlation engine identifies vulnerabilities
4. AI module generates pseudo-code and recommendations
5. Safe verification
6. Re-check and comparison
7. Display results

## AI Module (Non-Executable)
Generates:
- Severity explanation
- Conceptual pseudo-code (text only)
- Remediation recommendations

## Safety Rules
- No aggressive scanning
- No exploitation payloads
- Shodan API only
- All verification is safe & read-only

## Installation
### Requirements
- PHP 8.2+
- Laravel 12
- Composer
- MySQL 8+
- Shodan API Key

### Setup
```
git clone <repo-url>
composer install
cp .env.example .env
php artisan migrate
php artisan db:seed --class=UserSeeder
php artisan queue:work
php artisan serve
```

## Legal Disclaimer
This system is strictly for academic use under ITSS451. Unauthorized testing is prohibited.

## Credits
Course: ITSS451 — Ethical Hacking & Network Defense
Academic Year: 2025–2026
