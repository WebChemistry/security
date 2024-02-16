<?php declare(strict_types = 1);

namespace WebChemistry\Security\Encoder;

use DateTimeImmutable;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Rules\IssuedBy;
use ParagonIE\Paseto\Rules\ValidAt;
use SensitiveParameter;

final class PasetoEncoder implements AuthenticationEncoder
{

	private SymmetricKey $sharedKey;

	private ProtocolInterface $protocol;

	private Parser $parser;

	public function __construct(
		#[SensitiveParameter]
		 string $base64SharedKey,
		private string $issuer,
		?ProtocolInterface $protocol = null,
		private string $idKey = 'id',
	)
	{
		$this->sharedKey = new SymmetricKey(base64_decode($base64SharedKey));
		$this->protocol = $protocol ?? new Version2();
	}

	public function encode(string $id, string $expiration): string
	{
		$builder = (new Builder())
			->setKey($this->sharedKey)
			->setVersion($this->protocol)
			->setPurpose(Purpose::local())
			->setIssuer($this->issuer)
			->setIssuedAt()
			->setNotBefore()
			->setExpiration(new DateTimeImmutable(sprintf('+ %s', $expiration)))
			->set($this->idKey, $id);

		return $builder->toString();
	}

	public function decode(string $value): ?Decoded
	{
		try {
			$token = $this->getParser()->parse($value);
		} catch (PasetoException) {
			return null;
		}

		$id = $token->get($this->idKey);

		if (!is_string($id) || $id === '') {
			return null;
		}

		return new Decoded($id);
	}

	private function getParser(): Parser
	{
		return $this->parser ??= Parser::getLocal($this->sharedKey, new ProtocolCollection($this->protocol))
			->addRule(new ValidAt())
			->addRule(new IssuedBy($this->issuer));
	}

}
