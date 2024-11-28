<?php

namespace App\Filament\Admin\Pages\Auth;

use Exception;
use Filament\Forms\Form;
use Illuminate\Support\Str;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Actions\ActionGroup;
use Illuminate\Auth\SessionGuard;
use Filament\Events\Auth\Registered;
use Illuminate\Support\Facades\Hash;
use Illuminate\Database\Eloquent\Model;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Validation\Rules\Password;
use Illuminate\Contracts\Support\Htmlable;
use Filament\Notifications\Auth\VerifyEmail;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use DanHarrin\LivewireRateLimiting\WithRateLimiting;
use Filament\Pages\Concerns\InteractsWithFormActions;
use Filament\Pages\Concerns\CanUseDatabaseTransactions;
use Filament\Http\Responses\Auth\Contracts\RegistrationResponse;
use DanHarrin\LivewireRateLimiting\Exceptions\TooManyRequestsException;
use Filament\Pages\Auth\Register as BaseRegister;
use Filament\Forms\Components\Component;


class Register extends BaseRegister
{
    use CanUseDatabaseTransactions;
    use InteractsWithFormActions;
    use WithRateLimiting;

    /**
     * @var view-string
     */
    protected static string $view = 'filament-panels::pages.auth.register';

    /**
     * @var array<string, mixed> | null
     */
    public ?array $data = [];

    protected string $userModel;

    public function mount(): void
    {
        if (Filament::auth()->check()) {
            redirect()->intended(Filament::getUrl());
        }

        $this->callHook('beforeFill');

        $this->form->fill();

        $this->callHook('afterFill');
    }

    public function register(): ?RegistrationResponse
    {
        try {
            $this->rateLimit(2);
        } catch (TooManyRequestsException $exception) {
            $this->getRateLimitedNotification($exception)?->send();

            return null;
        }

        $user = $this->wrapInDatabaseTransaction(function () {
            $this->callHook('beforeValidate');

            $data = $this->form->getState();

            $this->callHook('afterValidate');

            $data = $this->mutateFormDataBeforeRegister($data);

            $this->callHook('beforeRegister');

            $user = $this->handleRegistration($data);

            $this->form->model($user)->saveRelationships();

            $this->callHook('afterRegister');

            return $user;
        });

        event(new Registered($user));

        $this->sendEmailVerificationNotification($user);

        Filament::auth()->login($user);

        session()->regenerate();

        return app(RegistrationResponse::class);
    }

    protected function getRateLimitedNotification(TooManyRequestsException $exception): ?Notification
    {
        return Notification::make()
            ->title(__('filament-panels::pages/auth/register.notifications.throttled.title', [
                'seconds' => $exception->secondsUntilAvailable,
                'minutes' => $exception->minutesUntilAvailable,
            ]))
            ->body(array_key_exists('body', __('filament-panels::pages/auth/register.notifications.throttled') ?: []) ? __('filament-panels::pages/auth/register.notifications.throttled.body', [
                'seconds' => $exception->secondsUntilAvailable,
                'minutes' => $exception->minutesUntilAvailable,
            ]) : null)
            ->danger();
    }

    /**
     * @param  array<string, mixed>  $data
     */
    protected function handleRegistration(array $data): Model
    {
        return $this->getUserModel()::create($data);
    }

    protected function sendEmailVerificationNotification(Model $user): void
    {
        if (! $user instanceof MustVerifyEmail) {
            return;
        }

        if ($user->hasVerifiedEmail()) {
            return;
        }

        if (! method_exists($user, 'notify')) {
            $userClass = $user::class;

            throw new Exception("Model [{$userClass}] does not have a [notify()] method.");
        }

        $notification = app(VerifyEmail::class);
        $notification->url = Filament::getVerifyEmailUrl($user);

        $user->notify($notification);
    }

    public function form(Form $form): Form
    {
        return $form;
    }

    /**
     * @return array<int | string, string | Form>
     */
    protected function getForms(): array
    {
        return [
            'form' => $this->form(
                $this->makeForm()
                    ->schema([
                        $this->getNameFormComponent(),
                        $this->getEmailFormComponent(),
                        $this->getPasswordFormComponent(),
                        $this->getPasswordConfirmationFormComponent(),
                        $this->getPasswordStrengthFormComponent(),
                    ])
                    ->statePath('data'),
            ),
        ];
    }

    protected function getNameFormComponent(): Component
    {
        // return TextInput::make('name')
        //     ->label(__('filament-panels::pages/auth/register.form.name.label'))
        //     ->required()
        //     ->maxLength(255)
        //     ->autofocus();
        return TextInput::make('name')
        ->label('Full name')
        ->required()
        ->maxLength(255)
        ->autofocus();


    }

    protected function getEmailFormComponent(): Component
    {
        return TextInput::make('email')
            ->label(__('filament-panels::pages/auth/register.form.email.label'))
            ->email()
            ->required()
            ->maxLength(255)
            ->unique($this->getUserModel());
    }

    protected function getPasswordFormComponent(): Component
    {
        // return TextInput::make('password')
        //     ->label(__('filament-panels::pages/auth/register.form.password.label'))
        //     ->password()
        //     ->revealable(filament()->arePasswordsRevealable())
        //     ->required()
        //     ->rule(Password::default())
        //     ->dehydrateStateUsing(fn ($state) => Hash::make($state))
        //     ->same('passwordConfirmation')
        //     ->validationAttribute(__('filament-panels::pages/auth/register.form.password.validation_attribute'));

            return TextInput::make('password')
            ->label(__('filament-panels::pages/auth/register.form.password.label'))
            ->password()
            ->revealable(filament()->arePasswordsRevealable())
            ->required()
            ->helperText(fn (?string $state) => $this->getPasswordValidationMessage($state ?? ''))
             ->reactive()
            ->rules(['required', 'string', 'min:8', 'regex:/[a-z]/', 'regex:/[A-Z]/', 'regex:/[0-9]/', 'regex:/[\W]/'])
            ->afterStateUpdated(function ($state, callable $set) {
                $strength = $this->calculatePasswordStrength($state);
                $set('password_strength', $strength);
                $set('password_strength_color', $this->getStrengthColor($strength));
            })

            ->same('passwordConfirmation')
            ->validationAttribute(__('filament-panels::pages/auth/register.form.password.validation_attribute'));


    }

    protected function getPasswordConfirmationFormComponent(): Component
    {
        return TextInput::make('passwordConfirmation')
            ->label(__('filament-panels::pages/auth/register.form.password_confirmation.label'))
            ->password()
            ->revealable(filament()->arePasswordsRevealable())
            ->required()
            ->dehydrated(false);
    }

    private function getPasswordValidationMessage(string $password): string
{
    $messages = [];

    if (!preg_match('/[a-z]/', $password)) {
        $messages[] = 'at least one lowercase letter';
    }

    if (!preg_match('/[A-Z]/', $password)) {
        $messages[] = 'at least one uppercase letter';
    }

    if (!preg_match('/[0-9]/', $password)) {
        $messages[] = 'at least one number';
    }

    if (!preg_match('/[\W]/', $password)) {
        $messages[] = 'at least one special character';
    }

    if (strlen($password) < 8) {
        $messages[] = 'a minimum of 8 characters';
    }

    // Combine validation messages into a readable string
    return empty($messages)
        ? 'Password meets all requirements.'
        : 'The password must include ' . implode(', ', $messages) . '.';
}



private function calculatePasswordStrength(?string $password): string
{
    if (is_null($password) || strlen($password) < 8) {
        return 'Too weak';
    }

    $score = 0;

    // Increment score based on criteria
    if (preg_match('/[a-z]/', $password)) {
        $score++; // Contains lowercase
    }
    if (preg_match('/[A-Z]/', $password)) {
        $score++; // Contains uppercase
    }
    if (preg_match('/[0-9]/', $password)) {
        $score++; // Contains numbers
    }
    if (preg_match('/[\W]/', $password)) {
        $score++; // Contains special characters
    }
    if (strlen($password) >= 12) {
        $score++; // Bonus for longer passwords
    }

    // Map score to strength levels
    return match ($score) {
        0, 1 => 'Too weak',
        2 => 'Weak',
        3 => 'Moderate',
        4 => 'Strong',
        5 => 'Very strong',
        default => 'Too weak',
    };
}



private function getStrengthColor(string $strength): string
{
    return match ($strength) {
        'Too weak' => '#991b1b',    // Red
        'Weak' => '#c2410c',        // Orange
        'Moderate' => '#fbbf24',    // Yellow
        'Strong' => '#4d7c0f',      // Green
        'Very strong' => '#15803d', // Dark Green
        default => '#94a3b8',       // Light gray (default)
    };
}


protected function getPasswordStrengthFormComponent(): Component
{
    return TextInput::make('password_strength')
    ->label('Password Strength')
    ->disabled()
    ->default('Too weak')
    ->reactive()
    ->extraAttributes(fn ($get) => [
        'style' => 'background-color: ' . $get('password_strength_color') . '; padding: 5px; color: white; text-align: center;',
    ]);
}


    public function loginAction(): Action
    {
        return Action::make('login')
            ->link()
            ->label(__('filament-panels::pages/auth/register.actions.login.label'))
            ->url(filament()->getLoginUrl());
    }

    protected function getUserModel(): string
    {
        if (isset($this->userModel)) {
            return $this->userModel;
        }

        /** @var SessionGuard $authGuard */
        $authGuard = Filament::auth();

        /** @var EloquentUserProvider $provider */
        $provider = $authGuard->getProvider();

        return $this->userModel = $provider->getModel();
    }

    public function getTitle(): string | Htmlable
    {
        return __('filament-panels::pages/auth/register.title');
    }

    public function getHeading(): string | Htmlable
    {
        return __('filament-panels::pages/auth/register.heading');
    }

    /**
     * @return array<Action | ActionGroup>
     */
    protected function getFormActions(): array
    {
        return [
            $this->getRegisterFormAction(),
        ];
    }

    public function getRegisterFormAction(): Action
    {
        return Action::make('register')
            ->label(__('filament-panels::pages/auth/register.form.actions.register.label'))
            ->submit('register');
    }

    protected function hasFullWidthFormActions(): bool
    {
        return true;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    protected function mutateFormDataBeforeRegister(array $data): array
    {

    // Generate a unique salt for the user
    $salt = Str::random(16);

    // Use a securely stored pepper (retrieve from config or environment variable)
    $pepper = config('app.pepper_key');

    // Combine password with salt and pepper, then hash it
    $hashedPassword = Hash::make($data['password'] . $salt . $pepper);

    // Save the hashed password, salt, and pepper in the data array
    $data['password'] = $hashedPassword;
    $data['salt'] = $salt;

    // Note: Pepper is not stored in the database, only used during hashing

    return $data;
    }
}
