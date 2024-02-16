<?php declare(strict_types = 1);

namespace Webchemistry\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager as SymfonyAccessDecisionManager;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Webchemistry\Security\Voter\AccessDecisionManagerAware;
use Webchemistry\Security\Voter\PersistentVoter;
use Webchemistry\Security\Voter\PersistentVoterImpl;

final class AccessDecisionManager implements AccessDecisionManagerInterface
{

	private SymfonyAccessDecisionManager $decorated;

	/**
	 * @param VoterInterface[] $voters
	 */
	public function __construct(array $voters)
	{
		foreach ($voters as $index => $voter) {
			if ($voter instanceof AccessDecisionManagerAware) {
				$voter->setAccessDecisionManager($this);
			}

			if ($voter instanceof PersistentVoter) {
				$voters[$index] = new PersistentVoterImpl($voter);
			}
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
