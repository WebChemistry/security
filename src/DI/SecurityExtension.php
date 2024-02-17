<?php declare(strict_types = 1);

namespace WebChemistry\Security\DI;

use Nette\Bridges\ApplicationLatte\LatteFactory;
use Nette\DI\CompilerExtension;
use Nette\DI\Definitions\FactoryDefinition;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use stdClass;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\RoleHierarchyVoter;
use Symfony\Component\Security\Core\Authorization\Voter\RoleVoter;
use Symfony\Component\Security\Core\Role\RoleHierarchy;
use WebChemistry\Security\AccessDecisionManager;
use WebChemistry\Security\Latte\LatteFunctions;
use WebChemistry\Security\Token\TokenStorage;

final class SecurityExtension extends CompilerExtension
{

	public function getConfigSchema(): Schema
	{
		return Expect::structure([
			'strict' => Expect::bool(false),
			'roleHierarchy' => Expect::arrayOf(Expect::arrayOf(Expect::string()), Expect::string()),
			'role' => Expect::structure([
				'prefix' => Expect::string('ROLE_'),
			]),
		]);
	}

	public function loadConfiguration(): void
	{
		$builder = $this->getContainerBuilder();
		/** @var stdClass $config */
		$config = $this->getConfig();

		$builder->addDefinition($this->prefix('accessDecisionManager'))
			->setType(AccessDecisionManagerInterface::class)
			->setFactory(AccessDecisionManager::class, ['strict' => $config->strict]);

		$builder->addDefinition($this->prefix('tokenStorage'))
			->setType(TokenStorageInterface::class)
			->setFactory(TokenStorage::class);

		$builder->addDefinition($this->prefix('authorizationChecker'))
			->setType(AuthorizationCheckerInterface::class)
			->setFactory(AuthorizationChecker::class);

		$builder->addDefinition($this->prefix('roleVoter'))
			->setFactory(RoleVoter::class, [$config->role->prefix]);

		if ($config->roleHierarchy) {
			$service = $builder->addDefinition($this->prefix('roleHierarchy'))
				->setFactory(RoleHierarchy::class, [$config->roleHierarchy]);

			$builder->addDefinition($this->prefix('roleHierarchyVoter'))
				->setFactory(RoleHierarchyVoter::class, [$service, $config->role->prefix]);
		}

		$builder->addDefinition($this->prefix('latte.functions'))
			->setFactory(LatteFunctions::class);
	}

	public function beforeCompile(): void
	{
		$builder = $this->getContainerBuilder();

		$latte = $builder->getDefinitionByType(LatteFactory::class);

		assert($latte instanceof FactoryDefinition);

		$latte->getResultDefinition()
				->addSetup('addFunction', ['isGranted', [$builder->getDefinition($this->prefix('latte.functions')), 'isGranted']]);
	}

}
