<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class VerificationLog extends Model
{
    use HasFactory;

    protected $fillable = [
        'target_id',
        'result',
        'details'
    ];

    protected $casts = [
        'result' => 'array',
    ];

    public function target()
    {
        return $this->belongsTo(Target::class);
    }
}
