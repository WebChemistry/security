<?php declare(strict_types = 1);

namespace Webchemistry\Security\Identity;

use Nette\Security\IIdentity;
use Symfony\Component\Security\Core\User\UserInterface;

final class UserIdentity implements IIdentity
{

	public function __construct(
		private UserInterface $user,
	)
	{
	}

	public function getId(): string
	{
		return $this->user->getUserIdentifier();
	}

	/**
	 * Returns the roles granted to the user.
	 *
	 *     public function getRoles()
	 *     {
	 *         return ['ROLE_USER'];
	 *     }
	 *
	 * Alternatively, the roles might be stored in a ``roles`` property,
	 * and populated in any number of different ways when the user object
	 * is created.
	 *
	 * @return string[]
	 */
	public function getRoles(): array
	{
		return $this->user->getRoles();
	}

	public function getEntity(): UserInterface
	{
		return $this->user;
	}

}
