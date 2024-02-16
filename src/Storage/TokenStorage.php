<?php declare(strict_types = 1);

namespace WebChemistry\Security\Storage;

use Nette\Security\UserStorage;

interface TokenStorage extends UserStorage
{

	public function tryGetId(string $value): ?string;

}
