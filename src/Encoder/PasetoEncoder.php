<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Rules\IssuedBy;
use ParagonIE\Paseto\Rules\ValidAt;
use SensitiveParameter;
use WebChemistry\Security\Key\SecretKey;
use WebChemistry\Security\Key\SecretKeyAssocMap;

final class PasetoEncoder implements CookieEncoder
{

	private ProtocolInterface $protocol;

	/** @var SecretKeyAssocMap<Parser> */
	private SecretKeyAssocMap $parsers;

	public function __construct(
		#[SensitiveParameter]
		private SecretKey $sharedKey,
		private string $issuer,
		?ProtocolInterface $protocol = null,
	)
	{
		$this->protocol = $protocol ?? new Version4();
		$this->parsers = new SecretKeyAssocMap();
	}

	public function encode(ValueToEncode $value, array $context = []): string
	{
		$sharedKey = new SymmetricKey($this->sharedKey->getKey($context));

		$builder = (new Builder())
			->setKey($sharedKey)
			->setVersion($this->protocol)
			->setPurpose(Purpose::local())
			->setIssuer($this->issuer)
			->setIssuedAt()
			->setNotBefore()
			->setExpiration($value->getExpiration())
			->set(self::ValueClaim, $value->value);

		return $builder->toString();
	}

	public function decode(string $value, array $context = []): ?DecodedValue
	{
		$claims = $this->decodeToClaims($value, $context);

		return isset($claims[self::ValueClaim]) ? new DecodedValue($claims[self::ValueClaim]) : null;
	}

	public function decodeToClaims(string $value, array $context = []): array
	{
		try {
			$token = $this->getParser($this->sharedKey->getKey($context))->parse($value);
		} catch (PasetoException) {
			return [];
		}

		return $token->getClaims();
	}

	private function getParser(string $key): Parser
	{
		$parser = $this->parsers->get($key);

		if ($parser) {
			return $parser;
		}

		$parser = Parser::getLocal(new SymmetricKey($key), new ProtocolCollection($this->protocol))
			->addRule(new ValidAt())
			->addRule(new IssuedBy($this->issuer));

		$this->parsers->set($key, $parser);

		return $parser;
	}

}
