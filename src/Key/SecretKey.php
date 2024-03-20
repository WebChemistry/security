<?php declare(strict_types = 1);

namespace WebChemistry\Security\Key;

interface SecretKey
{

	/**
	 * @param mixed[] $context
	 */
	public function getKey(array $context = []): string;

}
