<?php

namespace App\Jobs;

use App\Models\Target;
use App\Models\Finding;
use App\Models\VerificationLog;
use App\Services\ShodanService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Foundation\Bus\Dispatchable;

class CollectOsintJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $targetId;
    public $tries = 3;
    public $timeout = 25;

    public function __construct(int $targetId)
    {
        $this->targetId = $targetId;
    }

    public function handle(ShodanService $shodan): void
    {
        $target = Target::findOrFail($this->targetId);

        // Update: collecting
        $target->update(['status' => 'collecting']);



        try {
            // Shodan request
            $data = $shodan->hostInfo($target->value);

            // Check for resolution error from ShodanService
            if (isset($data['_note']) && str_contains($data['_note'], 'Could not resolve domain to IP')) {
                throw new \Exception($data['_note']);
            }

            // Save Finding
            Finding::create([
                'target_id' => $target->id,
                'raw_data'  => $data
            ]);

            VerificationLog::create([
                'target_id' => $target->id,
                'result'    => 'ok',
                'details'   => 'OSINT collected successfully.'
            ]);

        } catch (\Exception $e) {

            $this->storeDummyFinding($target, $e->getMessage());

            VerificationLog::create([
                'target_id' => $target->id,
                'result'    => 'error',
                'details'   => "OSINT failed: ".$e->getMessage()
            ]);
        }
        $target->update(['status' => 'collected']);

       
        dispatch(new RunCorrelationJob($target->id));
        dispatch(new VerifyFindingsJob($target->id));
    }


    private function storeDummyFinding(Target $target, string $note): void
    {
        Finding::create([
            'target_id' => $target->id,
            'raw_data' => [
                'ip_str' => $target->value,
                'ports' => [],
                'data' => [],
                '_note' => $note
            ]
        ]);
    }
}
