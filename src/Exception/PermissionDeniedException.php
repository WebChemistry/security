<?php declare(strict_types = 1);

namespace Webchemistry\Security\Exception;

use Nette\Application\BadRequestException;
use Throwable;

final class PermissionDeniedException extends BadRequestException
{

	public function __construct(string $message = 'Permission denied.', int $httpCode = 403, ?Throwable $previous = null)
	{
		parent::__construct($message, $httpCode, $previous);
	}

}
