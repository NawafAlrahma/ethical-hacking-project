<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Target extends Model
{
    use HasFactory;

    protected $fillable = [
        'type',
        'value',
        'status',
        'verify_status',
        'recheck_status',
    ];

    public function findings()
    {
        return $this->hasMany(Finding::class);
    }

    public function correlations()
    {
        return $this->hasMany(Correlation::class);
    }

    public function logs()
    {
        return $this->hasMany(VerificationLog::class);
    }
}
