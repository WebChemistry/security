<?php declare(strict_types = 1);

namespace WebChemistry\Security\Key;

/**
 * @template TValue
 */
final class SecretKeyAssocMap
{

	/** @var array<string, TValue> */
	private array $map = [];

	/**
	 * @return TValue|null
	 */
	public function get(string $key): mixed
	{
		return $this->map[$key] ?? null;
	}

	/**
	 * @param TValue $value
	 */
	public function set(string $key, mixed $value): void
	{
		$this->map[$key] = $value;
	}

}
