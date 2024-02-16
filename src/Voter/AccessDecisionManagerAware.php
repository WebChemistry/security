<?php declare(strict_types = 1);

namespace WebChemistry\Security\Voter;

use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;

interface AccessDecisionManagerAware
{

	public function setAccessDecisionManager(AccessDecisionManagerInterface $accessDecisionManager): void;

}
