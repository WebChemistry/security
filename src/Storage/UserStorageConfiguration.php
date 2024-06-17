<?php declare(strict_types = 1);

namespace WebChemistry\Security\Storage;

class UserStorageConfiguration
{

	public function __construct(
		public readonly string $expiration,
		public readonly string $cookieName = 'sessid',
		public readonly ?string $cookieDomain = null,
		public readonly ?bool $cookieSecure = null,
	)
	{
	}

}
