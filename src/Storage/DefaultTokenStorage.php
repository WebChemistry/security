<?php declare(strict_types = 1);

namespace WebChemistry\Security\Storage;

use LogicException;
use Nette\Http\IRequest;
use Nette\Http\IResponse;
use Nette\Security\IIdentity;
use WebChemistry\Security\Encoder\CookieEncoder;
use WebChemistry\Security\Encoder\ValueToEncode;
use WebChemistry\Security\Identity\UserIdentifierIdentity;

final class DefaultTokenStorage implements TokenStorage
{

	private ?string $expiration;

	public function __construct(
		private UserStorageConfiguration $configuration,
		private CookieEncoder $encoder,
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

		$decoded = $this->encoder->decode($value, ['source' => 'auth']);

		if ($decoded === null || !is_string($decoded->value) || $decoded->value === '') {
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
		$decoded = $this->encoder->decode($value, ['source' => 'auth'])?->value;

		if (!is_string($decoded) || $decoded === '') {
			return null;
		}

		return $decoded;
	}

	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
		$this->expiration = $expire;
	}

	private function saveId(string $id): void
	{
		$expiration = $this->expiration ?? $this->configuration->expiration;
		$value = new ValueToEncode($id, $expiration);

		$this->response->setCookie(
			$this->configuration->cookieName,
			$this->encoder->encode($value, ['source' => 'auth']),
			(int) $value->getExpiration()->format('U'),
		);
	}

}
