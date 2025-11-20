@extends('layouts.app', ['title' => 'Correlation Insights'])

@section('content')

<div class="card p-4 shadow-sm mb-4">
    <h4>Correlation Insights for Target #{{ $target->id }}</h4>
    <p><strong>Value:</strong> {{ $target->value }}</p>
    <p class="text-muted">Comparing the two latest OSINT findings to detect changes and potential vulnerabilities.</p>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card p-3 shadow-sm">
            <h5>Latest Finding (New)</h5>
            <pre class="bg-light p-3" style="max-height: 500px; overflow: auto;">{{ json_encode($new, JSON_PRETTY_PRINT) }}</pre>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card p-3 shadow-sm">
            <h5>Previous Finding (Old)</h5>
            <pre class="bg-light p-3" style="max-height: 500px; overflow: auto;">{{ json_encode($old, JSON_PRETTY_PRINT) }}</pre>
        </div>
    </div>
</div>

<div class="card p-4 shadow-sm mt-4">
    <h5>Change Analysis (Manual or AI-Driven)</h5>
    <p>
        **Note:** A proper change analysis requires a dedicated library (like a JSON diff tool) or an AI service to interpret the difference between the two large JSON objects (`$new` and `$old`).
    </p>
    <p>
        For the purpose of this project, the comparison is primarily used to demonstrate the ability to **store historical findings** and **identify changes** (e.g., a new open port, a change in server version, or a new vulnerability tag).
    </p>
    <p>
        **Example Insight:** If a new port (e.g., 3389/RDP) appears in the `$new` finding but not in the `$old` finding, this indicates a new high-risk exposure. This change would trigger a new correlation and a high-priority re-verification.
    </p>
    <a href="{{ route('targets.show', $target->id) }}" class="btn btn-secondary mt-3">Back to Target Details</a>
</div>

<div class="card p-4 shadow-sm mt-4">
    <h5>Exploit Pseudo-Code Examples (Based on Current Correlations)</h5>
    <p class="text-muted">These are non-executable examples of how the discovered vulnerabilities could be exploited, as required for the report.</p>

    @foreach($target->correlations as $corr)
        <div class="mb-3">
            <h6>{{ $corr->vuln_name }}</h6>
            <pre class="bg-dark text-white p-2 rounded" style="font-size: 0.7rem;">{{ $corr->ai_exploit_pseudo_code }}</pre>
        </div>
    @endforeach
</div>

@endsection
