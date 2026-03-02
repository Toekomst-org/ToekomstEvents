<?php

declare(strict_types=1);

namespace HiEvents\Services\Domain\Auth\DTO;

readonly class SsoUserData
{
    public function __construct(
        public string $email,
        public string $firstName,
        public string $lastName,
        public ?string $orgName = null,
        public ?string $orgId = null,
    ) {}

    public function getFullName(): string
    {
        return trim($this->firstName . ' ' . $this->lastName) ?: $this->email;
    }
}
