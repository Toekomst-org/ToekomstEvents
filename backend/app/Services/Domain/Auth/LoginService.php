<?php

namespace HiEvents\Services\Domain\Auth;

use HiEvents\DomainObjects\AccountDomainObject;
use HiEvents\DomainObjects\AccountUserDomainObject;
use HiEvents\DomainObjects\Enums\Role;
use HiEvents\DomainObjects\Status\UserStatus;
use HiEvents\DomainObjects\UserDomainObject;
use HiEvents\Exceptions\UnauthorizedException;
use HiEvents\Helper\IdHelper;
use HiEvents\Models\Account;
use HiEvents\Models\AccountUser;
use HiEvents\Models\User;
use HiEvents\Repository\Eloquent\Value\Relationship;
use HiEvents\Repository\Interfaces\AccountUserRepositoryInterface;
use HiEvents\Services\Domain\Auth\DTO\LoginResponse;
use HiEvents\Services\Domain\Auth\DTO\SsoUserData;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use PHPOpenSourceSaver\JWTAuth\JWTAuth;
use Psr\Log\LoggerInterface;

readonly class LoginService
{
    public function __construct(
        private JWTAuth                        $jwtAuth,
        private LoggerInterface                $logger,
        private AccountUserRepositoryInterface $accountUserRepository,
    ) {}

    /**
     * @throws UnauthorizedException
     */
    public function authenticate(string $email, string $password, ?int $requestedAccountId): LoginResponse
    {
        // todo - refactor this so we don't have to call the jwtAuth twice
        $token = $this->jwtAuth->attempt([
            'email' => strtolower($email),
            'password' => $password,
        ]);

        if (!$token) {
            throw new UnauthorizedException(__('Username or Password are incorrect'));
        }

        /** @var UserDomainObject $user */
        $user = UserDomainObject::hydrateFromModel($this->jwtAuth->user());

        $userAccounts = $this->accountUserRepository
            ->loadRelation(new Relationship(domainObject: AccountDomainObject::class, name: 'account'))
            ->findWhere([
                'user_id' => $user->getId(),
            ]);

        $accounts = $userAccounts->map(fn($accountUser) => $accountUser->getAccount());

        $accountId = $this->getAccountId($accounts, $requestedAccountId);

        if ($accountId) {
            $this->validateUserStatus($accountId, $userAccounts);
        }

        $userRole = $this->getUserRole($accountId, $userAccounts);

        return new LoginResponse(
            accounts: $accounts,
            token: $this->getToken(
                accounts: $accounts,
                email: $email,
                password: $password,
                requestedAccountId: $requestedAccountId,
                userRole: $userRole,
            ),
            user: $user,
            accountId: $accountId,
        );
    }

    private function getAccountId(Collection $accounts, ?int $requestedAccountId): ?int
    {
        if ($accounts->count() === 1) {
            return $accounts->first()->getId();
        }

        if ($requestedAccountId) {
            $verifiedAccount = $accounts->firstWhere(fn(AccountDomainObject $account) => $account->getId() === $requestedAccountId);

            if ($verifiedAccount === null) {
                throw new UnauthorizedException(__('Account not found'));
            }

            return $verifiedAccount->getId();
        }

        return null;
    }

    private function getToken(
        Collection $accounts,
        string     $email,
        string     $password,
        ?int       $requestedAccountId,
        ?Role      $userRole,
    ): ?string {
        $accountId = $this->getAccountId($accounts, $requestedAccountId);

        // if there's no account, we can't generate a token. The user will be prompted to select an account
        if ($accountId === null) {
            return null;
        }

        $claims = ['account_id' => $accountId];

        if ($userRole !== null) {
            $claims['role'] = $userRole->value;
        }

        $token = $this->jwtAuth->claims($claims)->attempt([
            'email' => strtolower($email),
            'password' => $password,
        ]);

        if (!$token) {
            throw new UnauthorizedException(__('Username or Password are incorrect'));
        }

        return $token;
    }

    private function validateUserStatus(int $accountId, Collection $userAccounts): void
    {
        /** @var AccountUserDomainObject $currentAccount */
        $currentAccount = $userAccounts
            ->first(fn(AccountUserDomainObject $userAccount) => $userAccount->getAccountId() === $accountId);

        if ($currentAccount->getStatus() !== UserStatus::ACTIVE->name) {
            $this->logger->info(__('Attempt to log in to a non-active account'), $currentAccount->toArray());

            throw new UnauthorizedException(__('User account is not active'));
        }
    }

    private function getUserRole(?int $accountId, Collection $userAccounts): ?Role
    {
        if ($accountId === null) {
            return null;
        }

        /** @var AccountUserDomainObject $currentAccount */
        $currentAccount = $userAccounts
            ->first(fn(AccountUserDomainObject $userAccount) => $userAccount->getAccountId() === $accountId);

        return Role::from($currentAccount?->getRole());
    }

    /**
     * @throws UnauthorizedException
     */
    public function authenticateOidc(
        string $email,
        ?int $requestedAccountId = null,
        ?SsoUserData $ssoUserData = null,
    ): LoginResponse {
        $userModel = User::where('email', strtolower($email))->first();

        // Auto-provision user if enabled and user doesn't exist
        if (!$userModel && $ssoUserData !== null && config('app.sso_auto_provision_enabled')) {
            $userModel = $this->autoProvisionSsoUser($ssoUserData);
        }

        if (!$userModel) {
            throw new UnauthorizedException(__('User not found'));
        }

        if (!$userModel->email_verified_at) {
            $userModel->email_verified_at = now();
            $userModel->save();
        }

        /** @var UserDomainObject $user */
        $user = UserDomainObject::hydrateFromModel($userModel);

        $userAccounts = $this->accountUserRepository
            ->loadRelation(new Relationship(domainObject: AccountDomainObject::class, name: 'account'))
            ->findWhere([
                'user_id' => $user->getId(),
            ]);

        $accounts = $userAccounts->map(fn($accountUser) => $accountUser->getAccount());

        $accountId = $this->getAccountId($accounts, $requestedAccountId);

        if ($accountId) {
            $this->validateUserStatus($accountId, $userAccounts);
        }

        $userRole = $this->getUserRole($accountId, $userAccounts);

        $token = null;

        if ($accountId !== null) {
            $claims = ['account_id' => $accountId];

            if ($userRole !== null) {
                $claims['role'] = $userRole->value;
            }

            $token = $this->jwtAuth->claims($claims)->fromUser($userModel);

            AccountUser::where('user_id', $user->getId())
                ->where('account_id', $accountId)
                ->update(['last_login_at' => now()]);

            auth()->login($userModel);
        }

        return new LoginResponse(
            accounts: $accounts,
            token: $token,
            user: $user,
            accountId: $accountId,
        );
    }

    /**
     * Auto-provision a user from SSO data
     * Creates user and associates with account based on organization name
     */
    private function autoProvisionSsoUser(SsoUserData $ssoUserData): User
    {
        return DB::transaction(function () use ($ssoUserData) {
            // Find or create account based on org name
            $account = $this->findOrCreateAccountForSso($ssoUserData);

            // Create the user
            $user = User::create([
                'email' => strtolower($ssoUserData->email),
                'first_name' => $ssoUserData->firstName ?: 'User',
                'last_name' => $ssoUserData->lastName ?: '',
                'password' => bcrypt(bin2hex(random_bytes(32))), // Random password, SSO users don't use it
                'email_verified_at' => now(),
                'timezone' => config('app.default_timezone'),
            ]);

            // Check if this is the first user for this account (will be admin/owner)
            $existingAccountUsers = AccountUser::where('account_id', $account->id)->count();
            $isFirstUser = $existingAccountUsers === 0;

            // Determine role
            $role = $isFirstUser
                ? Role::ADMIN->name
                : (config('app.sso_auto_provision_default_role') ?: Role::ORGANIZER->name);

            // Associate user with account
            AccountUser::create([
                'user_id' => $user->id,
                'account_id' => $account->id,
                'role' => $role,
                'status' => UserStatus::ACTIVE->name,
                'is_account_owner' => $isFirstUser,
            ]);

            $this->logger->info('SSO auto-provisioned user', [
                'user_id' => $user->id,
                'email' => $ssoUserData->email,
                'account_id' => $account->id,
                'account_name' => $account->name,
                'org_name' => $ssoUserData->orgName,
                'role' => $role,
                'is_first_user' => $isFirstUser,
            ]);

            return $user;
        });
    }

    /**
     * Find existing account by org name, or create a new one
     */
    private function findOrCreateAccountForSso(SsoUserData $ssoUserData): Account
    {
        $orgName = $ssoUserData->orgName ?: $ssoUserData->getFullName();

        // Try to find existing account by name
        $account = Account::where('name', $orgName)->first();

        if ($account) {
            return $account;
        }

        // Create new account
        $account = Account::create([
            'name' => $orgName,
            'email' => strtolower($ssoUserData->email),
            'short_id' => IdHelper::shortId(IdHelper::ACCOUNT_PREFIX),
            'timezone' => config('app.default_timezone'),
            'currency_code' => config('app.default_currency_code'),
            'account_verified_at' => config('app.saas_mode_enabled') ? null : now(),
            'account_configuration_id' => $this->getDefaultAccountConfigurationId(),
            'account_messaging_tier_id' => config('app.is_hi_events') ? 1 : 3,
        ]);

        $this->logger->info('SSO auto-created account', [
            'account_id' => $account->id,
            'account_name' => $orgName,
            'org_name' => $ssoUserData->orgName,
        ]);

        return $account;
    }

    private function getDefaultAccountConfigurationId(): int
    {
        $config = \HiEvents\Models\AccountConfiguration::where('is_system_default', true)->first();
        return $config?->id ?? 1;
    }
}
