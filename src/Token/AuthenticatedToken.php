<?php declare(strict_types = 1);

namespace Webchemistry\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

final class AuthenticatedToken extends AbstractToken
{

	public function __construct(UserInterface $user)
	{
		parent::__construct($user->getRoles());

		$this->setUser($user);
	}

}
