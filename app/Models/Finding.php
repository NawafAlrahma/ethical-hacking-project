<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Finding extends Model
{
    use HasFactory;

    protected $fillable = [
        'target_id',
        'raw_data',
        'verification_status'
    ];

    protected $casts = [
        'raw_data' => 'array',
    ];

    public function target()
    {
        return $this->belongsTo(Target::class);
    }
}
