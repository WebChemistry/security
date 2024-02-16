<?php declare(strict_types = 1);

namespace Webchemistry\Security\Latte;

use Nette\Security\IIdentity;
use Nette\Security\User;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Webchemistry\Security\Identity\UserIdentity;
use Webchemistry\Security\Token\AuthenticatedToken;

final class LatteFunctions
{

	public function __construct(
		private AccessDecisionManagerInterface $accessDecisionManager,
		private User $user,
	)
	{
	}

	public function isGranted(string|object $subject, ?string $operation = null, ?UserInterface $user = null): bool
	{
		$user ??= $this->user->isLoggedIn() ? $this->getEntity($this->user->getIdentity()) : null;
		$token = $user ? new AuthenticatedToken($user) : new NullToken();

		if (is_string($subject) && $operation === null) {
			return $this->accessDecisionManager->decide($token, [$subject]);
		} else {
			return $this->accessDecisionManager->decide($token, [$operation ?? 'default'], $subject);
		}
	}

	private function getEntity(?IIdentity $identity): UserInterface
	{
		assert($identity instanceof UserIdentity);

		return $identity->getEntity();
	}

}
