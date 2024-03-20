<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

use DateTimeImmutable;

final class ValueToEncode
{

	public function __construct(
		public readonly mixed $value,
		public readonly string $expiration,
	)
	{
	}

	public function getExpiration(): DateTimeImmutable
	{
		return new DateTimeImmutable(sprintf('+ %s', $this->expiration));
	}

}
