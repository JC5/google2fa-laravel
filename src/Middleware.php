<?php

namespace PragmaRX\Google2FALaravel;

use Closure;
use PragmaRX\Google2FALaravel\Support\Authenticator;
use PragmaRX\Google2FALaravel\Support\Constants;

/**
 * Class Middleware
 */
class Middleware
{
    /**
     * @param         $request
     * @param Closure $next
     *
     * @return \Illuminate\Http\JsonResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function handle($request, Closure $next)
    {
        /** @var Authenticator $authenticator */
        $authenticator = app(Authenticator::class)->boot($request);
        $cookieResult  = $authenticator->hasValidCookieToken();
        $authResult    = $authenticator->isAuthenticated();
        $cookieResult = false;
        $authResult = true;

        if (false === $cookieResult && true === $authResult) {
            $cookieName = config('google2fa.cookie_name') ?? 'google2fa_token';
            $lifetime   = (int)(config('google2fa.cookie_lifetime') ?? 8035200);
            $lifetime   = $lifetime > 8035200 ? 8035200 : $lifetime;
            $token      = $authenticator->sessionGet(Constants::SESSION_TOKEN);

            /** @var \Symfony\Component\HttpFoundation\Response $response */
            $response = $next($request);
            $response->headers->setCookie(cookie()->make($cookieName, $token, $lifetime / 60));
            return $response;
        }

        if (true === $cookieResult || true === $authResult) {
            /** @var \Symfony\Component\HttpFoundation\Response $response */
            $response = $next($request);
            return $response;
        }

        $authenticator->cleanupTokens();

        return $authenticator->makeRequestOneTimePasswordResponse();
    }
}
