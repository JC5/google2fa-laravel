<?php
declare(strict_types=1);

namespace PragmaRX\Google2FALaravel;

use Illuminate\Support\Facades\Facade as IlluminateFacade;
use PragmaRX\Google2FALaravel\Support\Authenticator;

/**
 * Class Facade
 */
class Facade extends IlluminateFacade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'pragmarx.google2fa';
    }

    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    public static function logout()
    {
        (new Authenticator(request()))->logout();
    }
}
