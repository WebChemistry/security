<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use SensitiveParameter;
use Throwable;

final class JwtEncoder implements AuthenticationEncoder
{

	private Configuration $configuration;

	/**
	 * @param non-empty-string $publicKey
	 * @param non-empty-string $privateKey
	 * @param non-empty-string $issuer
	 */
	public function __construct(
		#[SensitiveParameter]
		string $publicKey,
		#[SensitiveParameter]
		string $privateKey,
		private string $issuer,
		bool $base64 = false,
		private string $idKey = 'id',
	)
	{
		$this->configuration = Configuration::forAsymmetricSigner(
			new Eddsa(),
			InMemory::plainText($base64 ? base64_decode($privateKey) : $privateKey), // @phpstan-ignore-line
			InMemory::plainText($base64 ? base64_decode($publicKey) : $publicKey), // @phpstan-ignore-line
		);
	}

	/**
	 * @param non-empty-string $value
	 */
	public function decode(string $value): ?Decoded
	{
		try {
			$token = $this->configuration->parser()->parse($value);
		} catch (Throwable) {
			return null;
		}

		$valid = $this->configuration->validator()->validate(
			$token,
			new IssuedBy($this->issuer),
			new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
		);

		if (!$valid) {
			return null;
		}

		assert($token instanceof Plain);

		$id = $token->claims()->get($this->idKey);

		if (!is_string($id) || $id === '') {
			return null;
		}

		return new Decoded($id);
	}

	public function encode(string $id, string $expiration): string
	{
		$token = $this->configuration->builder()
			->issuedBy($this->issuer)
			->issuedAt(new DateTimeImmutable())
			->expiresAt(new DateTimeImmutable(sprintf('+ %s', $expiration)))
			->canOnlyBeUsedAfter(new DateTimeImmutable())
			->withClaim($this->idKey, $id)
			->getToken($this->configuration->signer(), $this->configuration->signingKey());

		return $token->toString();
	}

}
