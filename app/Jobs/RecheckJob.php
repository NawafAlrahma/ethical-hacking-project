<?php

namespace App\Jobs;

use App\Models\Target;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Foundation\Bus\Dispatchable;

class RecheckJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $targetId;

    public function __construct(int $targetId)
    {
        $this->targetId = $targetId;
    }

    public function handle(): void
    {
        $target = Target::find($this->targetId);

        if (!$target) return;

        // Reset status
        $target->update(['recheck_status' => 'running', 'status' => 'pending', 'verify_status' => 'pending']);

        // Dispatch the main OSINT collection job
        dispatch(new CollectOsintJob($target->id));
    }
}
