<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ $title ?? 'OSINT Scanner' }}</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

    <style>
        body { background: #f8f9fa; }
        .card { border-radius: 12px; }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container">
        <a class="navbar-brand" href="{{ route('targets.index') }}">OSINT Scanner</a>

        <div class="d-flex">
            @auth
                <a class="btn btn-outline-light me-2" href="{{ route('targets.create') }}">+ New Target</a>
                <form method="POST" action="{{ route('logout') }}">
                    @csrf
                    <button class="btn btn-danger">Logout</button>
                </form>
            @endauth
        </div>
    </div>
</nav>

<div class="container">
    @yield('content')
</div>

<footer class="text-center mt-5 mb-3 text-muted">
    <small>© 2025 OSINT Scanner</small>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

@yield('scripts')

</body>
</html>
