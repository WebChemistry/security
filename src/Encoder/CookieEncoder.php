<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

interface CookieEncoder
{

	public const ValueClaim = 'val';

	/**
	 * @param mixed[] $context
	 */
	public function encode(ValueToEncode $value, array $context = []): string;

	/**
	 * @param mixed[] $context
	 */
	public function decode(string $value, array $context = []): ?DecodedValue;

	/**
	 * @param mixed[] $context
	 * @return mixed[]
	 */
	public function decodeToClaims(string $value, array $context = []): array;

}
