<?php

namespace PragmaRX\Google2FALaravel;

use Closure;
use Illuminate\Http\Response;
use PragmaRX\Google2FALaravel\Support\Authenticator;
use PragmaRX\Google2FALaravel\Support\Constants;

class Middleware
{
    public function handle($request, Closure $next)
    {
        /** @var Authenticator $authenticator */
        $authenticator = app(Authenticator::class)->boot($request);
        $cookieResult  = $authenticator->hasValidCookieToken();
        $authResult    = $authenticator->isAuthenticated();
        /** @var Response $response */
        $response = $next($request);

        // auth but no cookie? place one:
        if (false === $cookieResult && true === $authResult) {

            // set cookie with token:
            $cookieName = config('google2fa.cookie_name') ?? 'google2fa_token';
            $lifetime   = (int)(config('google2fa.cookie_lifetime') ?? 8035200);
            $lifetime   = $lifetime > 8035200 ? 8035200 : $lifetime;
            $token      = $authenticator->sessionGet(Constants::SESSION_TOKEN);
            $response->withCookie(cookie()->make($cookieName, $token, $lifetime / 60));
        }
        if (true === $cookieResult) {
            return $response;
        }

        if (true === $authResult) {
            return $response;
        }

        return $authenticator->makeRequestOneTimePasswordResponse();
    }
}
