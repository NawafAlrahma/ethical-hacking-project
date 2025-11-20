<?php

namespace App\Http\Controllers;

use App\Models\Target;
use App\Models\Finding;
use App\Models\VerificationLog;
use Illuminate\Http\Request;
use App\Jobs\CollectOsintJob;
use App\Jobs\RecheckJob;
use Illuminate\Support\Facades\Validator;

class TargetController extends Controller
{

    // ---------------- INDEX ----------------
    public function index()
    {
        $targets = Target::latest()->get();
        return view('index', compact('targets'));
    }

    // ---------------- CREATE ----------------
    public function create()
    {
        return view('create');
    }

    // ---------------- STORE ----------------
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'value' => 'required|string|max:255',
            'type'  => 'required|in:ip,domain'
        ]);

        if ($validator->fails()) {
            return back()->withErrors($validator)->withInput();
        }

        $target = Target::create([
            'value' => $request->value,
            'type'  => $request->type,
            'status' => 'pending'
        ]);

        CollectOsintJob::dispatch($target->id);

        return redirect()->route('targets.index')
            ->with('success', 'Target added and OSINT collection started.');
    }

    // ---------------- SHOW ----------------
    public function show($id)
    {
        $target = Target::findOrFail($id);
        $findings = Finding::where('target_id', $id)->latest()->get(); // Get all findings for display
        $correlations = $target->correlations()->latest()->get(); // Get all correlations
        $logs = VerificationLog::where('target_id', $id)->latest()->get();

        return view('show', compact('target', 'findings', 'correlations', 'logs'));
    }

    // ---------------- DELETE ----------------
    public function destroy($id)
    {
        $target = Target::findOrFail($id);
        $target->delete();

        return redirect()->route('targets.index')->with('success', 'Target deleted.');
    }

    // ---------------- RECHECK ----------------
    public function recheck($id)
    {
        $target = Target::findOrFail($id);

        // Dispatch the RecheckJob which will handle status update and OSINT collection
        RecheckJob::dispatch($target->id);

        return back()->with('success', 'Recheck started. Status will update shortly.');
    }

    // ---------------- COMPARE ----------------
    public function compare($id)
    {
        $target = Target::findOrFail($id);

        $findings = Finding::where('target_id', $id)
            ->orderBy('created_at', 'desc')
            ->take(2)
            ->get();

        if ($findings->count() < 2) {
            return back()->with('error', 'Not enough findings to compare.');
        }

        $new = $findings[0]->raw_data;
        $old = $findings[1]->raw_data;

        return view('compare', compact('target', 'new', 'old'));
    }
}
