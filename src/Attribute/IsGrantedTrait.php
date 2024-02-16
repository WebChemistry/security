<?php declare(strict_types = 1);

namespace WebChemistry\Security\Attribute;

trait IsGrantedTrait
{

	use IsGrantedStandaloneTrait;

	public function checkRequirements($element): void
	{
		$this->checkRequirementIsGranted($element);

		parent::checkRequirements($element);
	}

}
