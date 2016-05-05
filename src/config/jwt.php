<?php

return [
    
    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Don't forget to set this, as it will be used to sign your tokens.
    | A helper command is provided for this: `php artisan jwt:generate`
    |
    */
    'secret' => env('JWT_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token will be valid for.
    | Defaults to 1 hour
    |
    */
    'ttl' => 60,

    /*
    |--------------------------------------------------------------------------
    | Refreshable
    |--------------------------------------------------------------------------
    |
    | Allow token to be able to refresh itself given it is not expired yet
    |
    */
    'refreshable' => false,

    /*
    |--------------------------------------------------------------------------
    | Refresh time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token can be refreshed
    | within. I.E. The user can refresh their token within a 2 week window of
    | the original token being created until they must re-authenticate.
    | Defaults to 1 week. This only come to effect when refreshable is
    | set to true
    |
    */
    'refresh_ttl' => 10080,

    /*
    |--------------------------------------------------------------------------
    | Leeway is set in case of clock skew
    |--------------------------------------------------------------------------
    |
    | To allow extra time (in seconds) when compare expiration, not before
    | and not after time in case for clock skew. Recommended to be no
    | more than a few minutes
    |
    */
    'leeway' => 0,

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    |
    | Specify the hashing algorithm that will be used to sign the token.
    |
    | Possible hash algorithms are: HS256, HS384, HS512, RS256
    |
    */
    'algo' => 'HS256',

    /*
    |--------------------------------------------------------------------------
    | JWT Claim table
    |--------------------------------------------------------------------------
    |
    | This will be the name of the table that is used for storing white list
    | JWT tokens for users
    |
    */
    'claim_table_name' => 'jwt_claims',

];