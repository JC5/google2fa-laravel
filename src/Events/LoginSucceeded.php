<?php
declare(strict_types=1);

namespace PragmaRX\Google2FALaravel\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Class LoginSucceeded
 */
class LoginSucceeded
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;
    public $user;

    /**
     * Create a new event instance.
     *
     * @param $user
     */
    public function __construct($user)
    {
        $this->user = $user;
    }
}
