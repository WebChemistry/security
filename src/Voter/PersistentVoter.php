<?php declare(strict_types = 1);

namespace WebChemistry\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;

interface PersistentVoter extends CacheableVoterInterface
{

	/**
	 * @param mixed[] $attributes
	 */
	public function isPersistent(TokenInterface $token, mixed $subject, array $attributes): bool;

}
