@extends('layouts.app', ['title' => 'Target Details'])

@section('content')

<div class="card p-4 shadow-sm mb-4">
    <h4>Target #{{ $target->id }}</h4>
    <p><strong>Value:</strong> {{ $target->value }}</p>
    <p><strong>Type:</strong> {{ strtoupper($target->type) }}</p>
    <p><strong>Status:</strong> <span class="badge bg-info">{{ $target->status }}</span></p>
    <p><strong>Verify:</strong> <span class="badge bg-secondary">{{ $target->verify_status }}</span></p>
    <p><strong>Recheck:</strong> <span class="badge bg-secondary">{{ $target->recheck_status }}</span></p>

    <div class="d-flex gap-2 mt-3">
        <a href="{{ route('targets.recheck', $target->id) }}" class="btn btn-warning">Re-check</a>
        <a href="{{ route('targets.compare', $target->id) }}" class="btn btn-dark">Correlation Insights</a>
    </div>
</div>

{{-- Correlations --}}
<div class="card p-4 shadow-sm mb-4">
    <h5>Correlation Findings (Vulnerabilities)</h5>

    @if($correlations->isEmpty())
        <p class="text-muted">No vulnerabilities found yet.</p>
    @else
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Score</th>
	                    <th>Recommendation</th>
	                    <th>Exploit Pseudo-Code</th>
                </tr>
            </thead>
            <tbody>
                @foreach($correlations as $corr)
                    <tr>
                        <td><strong>{{ $corr->vuln_name }}</strong> <br><small class="text-muted">{{ $corr->cve_id }}</small></td>
                        <td><span class="badge bg-{{ $corr->severity == 'high' ? 'danger' : ($corr->severity == 'medium' ? 'warning' : 'success') }}">{{ strtoupper($corr->severity) }}</span></td>
                        <td>{{ $corr->score }}</td>
	                        <td>{{ $corr->recommendation }}</td>
	                        <td><pre class="bg-dark text-white p-2 rounded" style="font-size: 0.7rem;">{{ $corr->ai_exploit_pseudo_code }}</pre></td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    @endif
</div>

{{-- Findings --}}
<div class="card p-4 shadow-sm mb-4">
    <h5>OSINT Raw Findings ({{ $findings->count() }} Records)</h5>

    @foreach($findings as $item)
        <div class="accordion mb-3" id="acc{{ $item->id }}">
            <div class="accordion-item">
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#collapse{{ $item->id }}">
                        Finding #{{ $item->id }} - Collected at {{ $item->created_at }}
                    </button>
                </h2>
                <div id="collapse{{ $item->id }}" class="accordion-collapse collapse">
                    <div class="accordion-body">
                        <pre class="bg-light p-3">{{ json_encode($item->raw_data, JSON_PRETTY_PRINT) }}</pre>
                    </div>
                </div>
            </div>
        </div>
    @endforeach

</div>

{{-- Logs --}}
<div class="card p-4 shadow-sm">
    <h5>Verification Logs</h5>

    <table class="table table-striped">
        <thead>
            <tr>
                <th>Time</th>
                <th>Result</th>
                <th>Details</th>
            </tr>
        </thead>

        <tbody>
        @foreach($logs as $log)
            <tr>
                <td>{{ $log->created_at }}</td>
                <td>{{ $log->result['status'] ?? $log->result }}</td>
                <td>{{ $log->details }}</td>
            </tr>
        @endforeach
        </tbody>
    </table>
</div>

@endsection
