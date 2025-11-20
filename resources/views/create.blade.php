@extends('layouts.app', ['title' => 'Add Target'])

@section('content')

<div class="card p-4 shadow-sm">
    <h4 class="mb-3">Add New Target</h4>

    <form action="{{ route('targets.store') }}" method="POST">
        @csrf

        <div class="mb-3">
            <label>Target Type</label>
            <select name="type" id="targetType" class="form-control">
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
            </select>
        </div>

        <div class="mb-3">
            <label>Target Value</label>
            <input type="text" name="value" id="valueField" class="form-control">
        </div>

        <button class="btn btn-success w-100">Save</button>

    </form>

</div>

@endsection

@section('scripts')
<script>
document.getElementById('targetType').addEventListener('change', function () {
    let type = this.value;
    let field = document.getElementById('valueField');

    if (type === 'ip') {
        field.placeholder = "Enter IPv4 (e.g., 8.8.8.8)";
    } else {
        field.placeholder = "Enter domain (e.g., example.com)";
    }
});
</script>
@endsection
