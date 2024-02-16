<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

final class Decoded
{

	public function __construct(
		public readonly string $value,
		public readonly bool $needsRefresh = false,
	)
	{
	}

}
