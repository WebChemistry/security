<?php declare(strict_types = 1);

namespace Webchemistry\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Webchemistry\Security\Cache\VoterCache;

/**
 * @internal
 */
final class PersistentVoterImpl implements CacheableVoterInterface
{

	private const SubjectTypes = ['NULL' => true, 'object' => true, 'integer' => true, 'string' => true];

	/** @var array<string, VoterCache> */
	private array $cache;

	public function __construct(
		private PersistentVoter $voter,
	)
	{
	}

	public function supportsAttribute(string $attribute): bool
	{
		return $this->voter->supportsAttribute($attribute);
	}

	public function supportsType(string $subjectType): bool
	{
		return $this->voter->supportsType($subjectType);
	}

	/**
	 * @param TokenInterface $token
	 * @param string[] $attributes
	 */
	public function vote(TokenInterface $token, mixed $subject, array $attributes): int
	{
		if (isset(self::SubjectTypes[gettype($subject)])) {
			$cache = $this->cache[$token->getUserIdentifier()] ??= new VoterCache();

			if (!$attributes) {
				return self::ACCESS_ABSTAIN;
			}

			foreach ($attributes as $attribute) {
				$result = $cache->fallback($subject, $attribute, fn () => $this->voter->vote($token, $subject, [$attribute])); // @phpstan-ignore-line

				if ($result === self::ACCESS_GRANTED) {
					return self::ACCESS_GRANTED;
				}
			}

			return self::ACCESS_DENIED;
		}

		return $this->voter->vote($token, $subject, $attributes);
	}

}
