<?php declare(strict_types = 1);

namespace WebChemistry\Security\Voter;

use Nette\Utils\Strings;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class DebugVoter implements VoterInterface
{

	public function __construct()
	{
	}

	/**
	 * @param mixed[] $attributes
	 */
	public function vote(TokenInterface $token, mixed $subject, array $attributes): int
	{
		trigger_error(
			sprintf(
				'No voter found for subject %s and attributes %s',
				$this->getDebugValue($subject),
				$this->getDebugValue($attributes),
			),
			E_USER_WARNING,
		);

		return self::ACCESS_ABSTAIN;
	}

	private function getDebugValue(mixed $value): string
	{
		if (is_array($value)) {
			return sprintf('[%s]', implode(', ', array_map(fn($value) => $this->getDebugValue($value), $value)));
		}

		if (is_string($value)) {
			return sprintf('"%s"', Strings::truncate($value, 20));
		}

		if (is_bool($value)) {
			return $value ? 'true' : 'false';
		}

		if (is_scalar($value)) {
			return (string) $value;
		}

		return get_debug_type($value);
	}

}
