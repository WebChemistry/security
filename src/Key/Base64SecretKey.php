<?php declare(strict_types = 1);

namespace WebChemistry\Security\Key;

use InvalidArgumentException;
use SensitiveParameter;

final class Base64SecretKey implements SecretKey
{

	private string $default;

	/** @var array<string, string> */
	private array $others;

	/**
	 * @param array<string, string> $others source => key
	 */
	public function __construct(
		#[SensitiveParameter]
		string $default,
		#[SensitiveParameter]
		array $others = [],
	)
	{
		$this->default = $this->decodeBase64($default);
		$this->others = array_map($this->decodeBase64(...), $others);
	}

	public function getKey(array $context = []): string
	{
		$source = $context['source'] ?? null;

		if (!is_string($source)) {
			return $this->default;
		} else {
			return $this->others[$source] ?? $this->default;
		}
	}

	private function decodeBase64(string $input): string
	{
		$decoded = base64_decode($input, true);

		if ($decoded === false) {
			throw new InvalidArgumentException('Invalid base64 input.');
		}

		return $decoded;
	}

}
