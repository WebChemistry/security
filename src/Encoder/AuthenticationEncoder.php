<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

interface AuthenticationEncoder
{

	public function encode(string $id, string $expiration): string;

	public function decode(string $value): ?Decoded;

}
