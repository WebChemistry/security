<?php declare(strict_types = 1);

namespace WebChemistry\Security\Cache;

use WeakMap;

final class VoterCache
{

	/** @var array<string|int, array<string, int>> */
	private array $scalarCache = [];

	/** @var WeakMap<object, array<string, int>> */
	private WeakMap $objectCache;

	/** @var array<string, int> */
	private array $nullCache = [];

	public function __construct()
	{
		$this->objectCache = new WeakMap();
	}

	public function fallback(object|int|string|null $subject, string $attribute, callable $fallback): int
	{
		if (is_object($subject)) {
			if (!isset($this->objectCache[$subject])) {
				$this->objectCache[$subject] = [];
			}

			return $this->objectCache[$subject][$attribute] ??= $fallback();
		}

		if ($subject === null) {
			return $this->nullCache[$attribute] ??= $fallback();
		}

		if (!isset($this->scalarCache[$subject])) {
			$this->scalarCache[$subject] = [];
		}

		return $this->scalarCache[$subject][$attribute] ??= $fallback();
	}

}
