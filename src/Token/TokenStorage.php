<?php declare(strict_types = 1);

namespace Webchemistry\Security\Token;

use LogicException;
use Nette\Security\User;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Webchemistry\Security\Identity\UserIdentity;

final class TokenStorage implements TokenStorageInterface
{

	public function __construct(
		private User $user,
	)
	{
	}

	public function getToken(): ?TokenInterface
	{
		if (!$this->user->isLoggedIn()) {
			return null;
		}

		$identity = $this->user->getIdentity();

		if (!$identity) {
			return null;
		}

		assert($identity instanceof UserIdentity);

		return new AuthenticatedToken($identity->getEntity());
	}

	public function setToken(?TokenInterface $token): void
	{
		throw new LogicException('Not implemented');
	}

}
