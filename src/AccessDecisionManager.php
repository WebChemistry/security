<?php declare(strict_types = 1);

namespace WebChemistry\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager as SymfonyAccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use WebChemistry\Security\Voter\AccessDecisionManagerAware;
use WebChemistry\Security\Voter\DebugVoter;

final class AccessDecisionManager implements AccessDecisionManagerInterface
{

	private SymfonyAccessDecisionManager $decorated;

	/**
	 * @param VoterInterface[] $voters
	 */
	public function __construct(array $voters, bool $strict = false)
	{
		foreach ($voters as $voter) {
			if ($voter instanceof AccessDecisionManagerAware) {
				$voter->setAccessDecisionManager($this);
			}
		}

		if ($strict) {
			$voters[] = new DebugVoter();
		}

		$this->decorated = new SymfonyAccessDecisionManager($voters);
	}

	/**
	 * @param mixed[] $attributes
	 */
	public function decide(TokenInterface $token, array $attributes, mixed $object = null): bool
	{
		return $this->decorated->decide($token, $attributes, $object);
	}

}
