<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Correlation extends Model
{
    use HasFactory;

    protected $fillable = [
        'target_id',
        'vuln_name',
        'cve_id',
        'severity',
        'score',
        'evidence',
        'description',
        'recommendation',
    ];

    public function target()
    {
        return $this->belongsTo(Target::class);
    }
}
