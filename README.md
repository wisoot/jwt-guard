## Jwt Guard

[![Author][ico-author]][link-author]
[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE)
[![Quality Score][ico-code-quality]][link-code-quality]
[![Total Downloads][ico-downloads]][link-downloads]

Jwt Guard is alternative Laravel 5.2 Guard Driver which is implemented using JSON Web Token (JWT)

The MIT License (MIT). Please see [License File](LICENSE) for more information.

### Install

To install this package you will need:

*   Laravel 5.2
*   PHP 5.6+

Via Composer

``` bash
$ composer require wisoot/jwt-guard
```

#### Add the Service Provider

Open `config/app.php` and, to your `providers` array at the bottom, add:

```php
WWON\JwtGuard\Providers\JwtGuardServiceProvider::class
```

#### Publish config file and database migration

``` bash
php artisan vendor:publish --provider="WWON\JwtGuard\Providers\JwtGuardServiceProvider"
```

Update `jwt.php` config to suit your project, run the migration, then you are good to go.

### Usage

In `config/auth.php` config file you have access to `jwt` driver.

[ico-author]: http://img.shields.io/badge/author-@wisootwong-blue.svg?style=flat-square
[ico-version]: https://img.shields.io/packagist/v/wisoot/jwt-guard.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/wisoot/jwt-guard.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/wisoot/jwt-guard.svg?style=flat-square

[link-author]: https://twitter.com/wisootwong
[link-packagist]: https://packagist.org/packages/wisoot/jwt-guard
[link-code-quality]: https://scrutinizer-ci.com/g/wisoot/jwt-guard
[link-downloads]: https://packagist.org/packages/wisoot/jwt-guard
[link-contributors]: ../../contributors
