<?php declare(strict_types = 1);

namespace WebChemistry\Security\Storage;

use LogicException;
use Nette\Http\IRequest;
use Nette\Http\IResponse;
use Nette\Security\IIdentity;
use WebChemistry\Security\Encoder\AuthenticationEncoder;
use WebChemistry\Security\Identity\UserIdentifierIdentity;

final class DefaultTokenStorage implements TokenStorage
{

	private ?string $expiration;

	public function __construct(
		private UserStorageConfiguration $configuration,
		private AuthenticationEncoder $encoder,
		private IResponse $response,
		private IRequest $request,
	)
	{
	}

	public function saveAuthentication(IIdentity $identity): void
	{
		if (!is_scalar($id = $identity->getId())) {
			throw new LogicException(sprintf('Identity id must be scalar, %s given.', get_debug_type($id)));
		}

		$this->saveId((string) $id);
	}

	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->response->deleteCookie($this->configuration->cookieName);
	}

	/**
	 * Returns user authenticated state, identity and logout reason.
	 *
	 * @return array{bool, ?UserIdentifierIdentity, null}
	 */
	public function getState(): array
	{
		$value = $this->request->getCookie($this->configuration->cookieName);

		if (!is_string($value)) {
			return [false, null, null];
		}

		$decoded = $this->encoder->decode($value);

		if ($decoded === null) {
			return [false, null, null];
		}

		$identity = new UserIdentifierIdentity($decoded->value);

		if ($decoded->needsRefresh) {
			$this->saveAuthentication($identity);
		}

		return [true, $identity, null];
	}

	public function tryGetId(string $value): ?string
	{
		return $this->encoder->decode($value)?->value;
	}

	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
		$this->expiration = $expire;
	}

	private function saveId(string $id): void
	{
		$expiration = $this->expiration ?? $this->configuration->expiration;

		$this->response->setCookie(
			$this->configuration->cookieName,
			$this->encoder->encode($id, $expiration),
			sprintf('+ %s', $expiration),
		);
	}

}
