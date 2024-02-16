<?php declare(strict_types = 1);

namespace Webchemistry\Security\Attribute;

use ReflectionClass;
use ReflectionMethod;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Webchemistry\Security\Exception\PermissionDeniedException;
use Webchemistry\Security\Helper\UserSecurityHelper;

trait IsGrantedStandaloneTrait
{

	private AccessDecisionManagerInterface $_adm;

	final public function injectIsGranted(AccessDecisionManagerInterface $accessDecisionManager): void
	{
		$this->_adm = $accessDecisionManager;
	}

	public function checkRequirementIsGranted($element): void
	{
		if (!$element instanceof ReflectionClass && !$element instanceof ReflectionMethod) {
			return;
		}

		$attributes = $element->getAttributes(IsGranted::class);

		if (!$attributes) {
			return;
		}

		$granted = false;
		foreach ($attributes as $attribute) {
			/** @var IsGranted $object */
			$object = $attribute->newInstance();

			if ($this->_adm->decide(UserSecurityHelper::createTokenFromUser($this->getUser()), [$object->attribute], $object->object)) {
				$granted = true;

				break;
			}
		}

		if (!$granted) {
			throw new PermissionDeniedException();
		}
	}

}
