<?php declare(strict_types = 1);

namespace Webchemistry\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * @template TClass of object
 */
abstract class ClassVoter extends AttributeVoter
{

	/** @var array<string, true> */
	private array $classAttributeIndex;

	/**
	 * @return class-string<TClass>
	 */
	abstract protected function getClassName(): string;

	/**
	 * @return string[]
	 */
	abstract protected function getClassAttributes(): array;

	/**
	 * @return array<string, true>
	 */
	private function getClassAttributeIndex(): array
	{
		if (!isset($this->classAttributeIndex)) {
			$this->classAttributeIndex = [];

			foreach ($this->getClassAttributes() as $attribute) {
				$this->classAttributeIndex[$attribute] = true;
			}
		}

		return $this->classAttributeIndex;
	}

	public function supportsAttribute(string $attribute): bool
	{
		return parent::supportsAttribute($attribute) || isset($this->getClassAttributeIndex()[$attribute]);
	}

	public function supportsType(string $subjectType): bool
	{
		return parent::supportsType($subjectType) || is_a($subjectType, $this->getClassName(), true);
	}

	protected function tryVote(TokenInterface $token, mixed $subject, string $attribute): int
	{
		if (is_object($subject) && is_a($subject, $this->getClassName())) {
			if (!isset($this->getClassAttributeIndex()[$attribute])) {
				return self::ACCESS_ABSTAIN;
			}

			return $this->voteOnClass($subject, $attribute, $token) ? self::ACCESS_GRANTED : self::ACCESS_DENIED;
		}

		return parent::tryVote($token, $subject, $attribute);
	}

	/**
	 * @param TClass $subject
	 */
	abstract protected function voteOnClass(object $subject, string $attribute, TokenInterface $token): bool;

}
