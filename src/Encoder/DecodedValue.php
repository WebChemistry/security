<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

final class DecodedValue
{

	public function __construct(
		public readonly mixed $value,
		public readonly bool $needsRefresh = false,
	)
	{
	}

}
