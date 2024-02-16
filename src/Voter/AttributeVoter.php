<?php declare(strict_types = 1);

namespace WebChemistry\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;

abstract class AttributeVoter implements CacheableVoterInterface
{

	/** @var array<string, true> */
	private array $attributeIndex;

	/** @var array<string, array<string, true>> */
	private array $attributeCache;

	/**
	 * @return array<string|null, string[]>
	 */
	abstract protected function getAttributes(): array;

	/**
	 * @return array<string|null, array<string, true>>
	 */
	private function getCachedAttributes(): array
	{
		if (!isset($this->attributeCache)) {
			$this->attributeCache = [];

			foreach ($this->getAttributes() as $subject => $attributes) {
				foreach ($attributes as $attribute) {
					$this->attributeCache[$subject][$attribute] = true;
				}
			}
		}

		return $this->attributeCache;
	}

	/**
	 * @return array<string, true>
	 */
	private function getAttributeIndex(): array
	{
		if (!isset($this->attributeIndex)) {
			$this->attributeIndex = [];

			foreach ($this->getAttributes() as $attributes) {
				foreach ($attributes as $attribute) {
					$this->attributeIndex[$attribute] = true;
				}
			}
		}

		return $this->attributeIndex;
	}

	public function supportsAttribute(string $attribute): bool
	{
		return isset($this->getAttributeIndex()[$attribute]);
	}

	public function supportsType(string $subjectType): bool
	{
		return $subjectType === 'null' || $subjectType === 'string';
	}

	/**
	 * @param string[] $attributes
	 */
	final public function vote(TokenInterface $token, mixed $subject, array $attributes): int
	{
		// abstain vote by default in case none of the attributes are supported
		$vote = self::ACCESS_ABSTAIN;

		foreach ($attributes as $attribute) {
			$result = $this->tryVote($token, $subject, $attribute);

			if ($result === self::ACCESS_GRANTED) {
				return self::ACCESS_GRANTED;
			} else if ($result === self::ACCESS_DENIED) {
				$vote = self::ACCESS_DENIED;
			}
		}

		return $vote;
	}

	protected function tryVote(TokenInterface $token, mixed $subject, string $attribute): int
	{
		if (($subject === null || is_string($subject)) && isset($this->getCachedAttributes()[$subject][$attribute])) {
			return $this->voteOnAttribute($attribute, $subject, $token) ? self::ACCESS_GRANTED : self::ACCESS_DENIED;
		}

		return self::ACCESS_ABSTAIN;
	}

	abstract protected function voteOnAttribute(string $attribute, ?string $subject, TokenInterface $token): bool;

}
