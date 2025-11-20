@extends('layouts.app', ['title' => 'Targets List'])

@section('content')

<div class="card p-4 shadow-sm">
    <div class="d-flex justify-content-between mb-3">
        <h4>Targets</h4>
        <a href="{{ route('targets.create') }}" class="btn btn-primary">+ Add Target</a>
    </div>

    @if($targets->count() == 0)
        <p class="text-muted">No targets yet.</p>
    @else
    <table class="table table-bordered table-hover">
        <thead class="table-dark">
        <tr>
            <th>ID</th>
            <th>Value</th>
            <th>Type</th>
            <th>Status</th>
            <th>Verify</th>
            <th>Actions</th>
        </tr>
        </thead>

        <tbody>
        @foreach($targets as $t)
            <tr>
                <td>{{ $t->id }}</td>
                <td>{{ $t->value }}</td>
                <td>{{ strtoupper($t->type) }}</td>
                <td>
                    <span class="badge bg-info">{{ $t->status }}</span>
                </td>
                <td>
                    <span class="badge bg-secondary">{{ $t->verify_status }}</span>
                </td>
                <td>
                    <a href="{{ route('targets.show', $t->id) }}" class="btn btn-sm btn-primary">View</a>

                    <form action="{{ route('targets.destroy', $t->id) }}" method="POST" class="d-inline">
                        @csrf @method('DELETE')
                        <button onclick="return confirm('Delete target?')" class="btn btn-sm btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
        @endforeach
        </tbody>

    </table>
    @endif
</div>

@endsection
