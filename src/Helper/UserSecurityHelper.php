<?php declare(strict_types = 1);

namespace Webchemistry\Security\Helper;

use Nette\Security\User;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Webchemistry\Security\Identity\UserIdentity;
use Webchemistry\Security\Token\AuthenticatedToken;

final class UserSecurityHelper
{

	public static function createTokenFromUser(User $user): TokenInterface
	{
		if (!$user->isLoggedIn()) {
			return new NullToken();
		}

		$identity = $user->getIdentity();

		assert($identity instanceof UserIdentity);

		return new AuthenticatedToken($identity->getEntity());
	}

}
