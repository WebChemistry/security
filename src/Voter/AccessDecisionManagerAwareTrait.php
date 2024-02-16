<?php declare(strict_types = 1);

namespace WebChemistry\Security\Voter;

use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;

trait AccessDecisionManagerAwareTrait
{

	private AccessDecisionManagerInterface $accessDecisionManager;

	public function setAccessDecisionManager(AccessDecisionManagerInterface $accessDecisionManager): void
	{
		$this->accessDecisionManager = $accessDecisionManager;
	}

}
