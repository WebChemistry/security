<?php declare(strict_types = 1);

namespace WebChemistry\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use WebChemistry\Security\Cache\VoterCache;

final class PersistentVoter implements CacheableVoterInterface, AccessDecisionManagerAware
{

	private const SubjectTypes = ['NULL' => true, 'object' => true, 'integer' => true, 'string' => true];

	/** @var array<string, VoterCache> */
	private array $cache;

	public function __construct(
		private VoterInterface $voter,
	)
	{
	}

	public function setAccessDecisionManager(AccessDecisionManagerInterface $accessDecisionManager): void
	{
		if ($this->voter instanceof AccessDecisionManagerAware) {
			$this->voter->setAccessDecisionManager($accessDecisionManager);
		}
	}

	public function supportsAttribute(string $attribute): bool
	{
		return !$this->voter instanceof CacheableVoterInterface || $this->voter->supportsAttribute($attribute);
	}

	public function supportsType(string $subjectType): bool
	{
		return !$this->voter instanceof CacheableVoterInterface || $this->voter->supportsType($subjectType);
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
