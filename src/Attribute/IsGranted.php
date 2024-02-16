<?php declare(strict_types = 1);

namespace WebChemistry\Security\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final class IsGranted
{

	public function __construct(
		public readonly string $attribute,
		public readonly mixed $object = null,
	)
	{
	}

}
