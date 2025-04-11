<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/User.php';
require_once __DIR__ . '/Session.php';

class OAuthHandler
{
  private $db;
  private $session;
  private $providerConfigs;
  private $user;

  public function __construct(Session $session, User $user)
  {
    $this->db = (new Database())->getConnection();
    $this->session = $session;
    $this->user = $user;

    // Load provider configurations
    $this->providerConfigs = [
      'google' => [
        'clientId'     => 'YOUR_GOOGLE_CLIENT_ID',
        'clientSecret' => 'YOUR_GOOGLE_CLIENT_SECRET',
        'redirectUri'  => 'http://localhost/your-app/example/oauth_callback.php?provider=google',
      ],
      'facebook' => [
        'clientId'     => 'YOUR_FACEBOOK_APP_ID',
        'clientSecret' => 'YOUR_FACEBOOK_APP_SECRET',
        'redirectUri'  => 'http://localhost/your-app/example/oauth_callback.php?provider=facebook',
      ],
      'github' => [
        'clientId'     => 'YOUR_GITHUB_CLIENT_ID',
        'clientSecret' => 'YOUR_GITHUB_CLIENT_SECRET',
        'redirectUri'  => 'http://localhost/your-app/example/oauth_callback.php?provider=github',
      ]
    ];
  }

  /**
   * Get the authorization URL for a specific provider
   */
  public function getAuthorizationUrl($provider)
  {
    if (!isset($this->providerConfigs[$provider])) {
      throw new Exception("Unsupported OAuth provider: $provider");
    }

    $oauthProvider = $this->createProvider($provider);

    // Store state for CSRF protection
    $this->session->set('oauth_state', $oauthProvider->getState());

    return $oauthProvider->getAuthorizationUrl();
  }

  /**
   * Handle the OAuth callback and authenticate the user
   */
  public function handleCallback($provider, $requestParams)
  {
    if (!isset($this->providerConfigs[$provider])) {
      throw new Exception("Unsupported OAuth provider: $provider");
    }

    // Verify the state parameter (CSRF protection)
    $state = $this->session->get('oauth_state');
    if (empty($state) || $state !== $requestParams['state']) {
      $this->session->set('oauth_state', null);
      throw new Exception('Invalid state parameter. Possible CSRF attack.');
    }

    $oauthProvider = $this->createProvider($provider);

    // Get access token
    $token = $oauthProvider->getAccessToken('authorization_code', [
      'code' => $requestParams['code']
    ]);

    // Get user details from provider
    $oauthUser = $oauthProvider->getResourceOwner($token);

    // Process user data based on provider
    $userData = $this->extractUserData($provider, $oauthUser);

    // Find or create user in your database
    return $this->findOrCreateUser($provider, $userData);
  }

  /**
   * Find existing user or create a new one based on OAuth data
   */
  private function findOrCreateUser($provider, $userData)
  {
    // Check if user already exists with this OAuth ID
    $stmt = $this->db->prepare("SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?");
    $stmt->execute([$provider, $userData['id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
      // User exists, log them in
      $this->session->set('user_id', $user['id']);
      $this->session->set('username', $user['username']);
      return $user['id'];
    } else {
      // Check if email already exists
      if (!empty($userData['email'])) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$userData['email']]);
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingUser) {
          // Update existing user with OAuth info
          $stmt = $this->db->prepare("UPDATE users SET oauth_provider = ?, oauth_id = ? WHERE id = ?");
          $stmt->execute([$provider, $userData['id'], $existingUser['id']]);

          $this->session->set('user_id', $existingUser['id']);
          $this->session->set('username', $existingUser['username']);
          return $existingUser['id'];
        }
      }

      // Create new user
      // Generate random password as the user will use OAuth to log in
      $password = bin2hex(random_bytes(16));
      $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

      $stmt = $this->db->prepare("INSERT INTO users (username, email, password, oauth_provider, oauth_id) VALUES (?, ?, ?, ?, ?)");
      $stmt->execute([
        $userData['username'],
        $userData['email'] ?? null,
        $hashedPassword,
        $provider,
        $userData['id']
      ]);

      $userId = $this->db->lastInsertId();

      $this->session->set('user_id', $userId);
      $this->session->set('username', $userData['username']);

      return $userId;
    }
  }

  /**
   * Extract standardized user data from various providers
   */
  private function extractUserData($provider, $resourceOwner)
  {
    $userData = [];

    switch ($provider) {
      case 'google':
        $userData = [
          'id' => $resourceOwner->getId(),
          'email' => $resourceOwner->getEmail(),
          'username' => $resourceOwner->getName() ?: explode('@', $resourceOwner->getEmail())[0],
        ];
        break;

      case 'facebook':
        $userData = [
          'id' => $resourceOwner->getId(),
          'email' => $resourceOwner->getEmail(),
          'username' => $resourceOwner->getName() ?: explode('@', $resourceOwner->getEmail())[0],
        ];
        break;

      case 'github':
        $userData = [
          'id' => $resourceOwner->getId(),
          'email' => $resourceOwner->getEmail(),
          'username' => $resourceOwner->getNickname() ?: 'github_user_' . $resourceOwner->getId(),
        ];
        break;
    }

    return $userData;
  }

  /**
   * Create OAuth provider instance based on provider name
   */
  private function createProvider($provider)
  {
    $config = $this->providerConfigs[$provider];

    switch ($provider) {
      case 'google':
        return new \League\OAuth2\Client\Provider\Google([
          'clientId'     => $config['clientId'],
          'clientSecret' => $config['clientSecret'],
          'redirectUri'  => $config['redirectUri'],
        ]);

      case 'facebook':
        return new \League\OAuth2\Client\Provider\Facebook([
          'clientId'     => $config['clientId'],
          'clientSecret' => $config['clientSecret'],
          'redirectUri'  => $config['redirectUri'],
          'graphApiVersion' => 'v12.0',
        ]);

      case 'github':
        return new \League\OAuth2\Client\Provider\Github([
          'clientId'     => $config['clientId'],
          'clientSecret' => $config['clientSecret'],
          'redirectUri'  => $config['redirectUri'],
        ]);

      default:
        throw new Exception("Unsupported OAuth provider: $provider");
    }
  }
}
