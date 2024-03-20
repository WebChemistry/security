<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use SensitiveParameter;
use Throwable;
use WebChemistry\Security\Key\SecretKey;
use WebChemistry\Security\Key\SecretKeyAssocMap;

final class JwtEncoder implements CookieEncoder
{

	/** @var SecretKeyAssocMap<Configuration> */
	private SecretKeyAssocMap $configurationMap;

	/**
	 */
	public function __construct(
		#[SensitiveParameter]
		private SecretKey $publicKey,
		#[SensitiveParameter]
		private SecretKey $privateKey,
		private string $issuer,
	)
	{
		$this->configurationMap = new SecretKeyAssocMap();
	}

	public function decode(string $value, array $context = []): ?DecodedValue
	{
		$claims = $this->decodeToClaims($value, $context);

		return isset($claims[self::ValueClaim]) ? new DecodedValue($claims[self::ValueClaim]) : null;
	}

	public function decodeToClaims(string $value, array $context = []): array
	{
		$configuration = $this->getConfiguration($context);
		try {
			$token = $configuration->parser()->parse($value);
		} catch (Throwable) {
			return [];
		}

		$valid = $configuration->validator()->validate(
			$token,
			new IssuedBy($this->issuer),
			new StrictValidAt(new FrozenClock(new DateTimeImmutable())),
		);

		if (!$valid) {
			return [];
		}

		assert($token instanceof Plain);

		return $token->claims()->all();
	}

	public function encode(ValueToEncode $value, array $context = []): string
	{
		$configuration = $this->getConfiguration($context);

		$token = $configuration->builder()
			->issuedBy($this->issuer)
			->issuedAt(new DateTimeImmutable())
			->expiresAt($value->getExpiration())
			->canOnlyBeUsedAfter(new DateTimeImmutable())
			->withClaim(self::ValueClaim, $value->value)
			->getToken($configuration->signer(), $configuration->signingKey());

		return $token->toString();
	}

	/**
	 * @param mixed[] $context
	 */
	private function getConfiguration(array $context = []): Configuration
	{
		$publicKey = $this->publicKey->getKey($context);
		$privateKey = $this->privateKey->getKey($context);

		$configuration = $this->configurationMap->get($hash = $publicKey . $privateKey);

		if ($configuration) {
			return $configuration;
		}

		$this->configurationMap->set($hash, $configuration = Configuration::forAsymmetricSigner(
			new Eddsa(),
			InMemory::plainText($publicKey), // @phpstan-ignore-line
			InMemory::plainText($privateKey), // @phpstan-ignore-line
		));

		return $configuration;
	}

}
