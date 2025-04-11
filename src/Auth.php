<?php
require_once __DIR__ . '/User.php';
require_once __DIR__ . '/Role.php';
require_once __DIR__ . '/Permission.php';
require_once __DIR__ . '/Session.php';
require_once __DIR__ . '/OAuthHandler.php';

class Auth
{
  private $user;
  private $role;
  private $permission;
  private $session;
  private $oauthHandler;

  public function __construct()
  {
    $this->session = new Session();
    $this->user = new User($this->session);
    $this->role = new Role();
    $this->permission = new Permission();
    $this->oauthHandler = new OAuthHandler($this->session, $this->user);
  }

  public function getUser()
  {
    return $this->user;
  }

  public function getSession()
  {
    return $this->session;
  }

  public function register($username, $email, $password, $contactNumber = null, $cnic = null)
  {
    return $this->user->register($username, $email, $password, $contactNumber, $cnic);
  }

  public function login($email, $password, $remember = false)
  {
    return $this->user->login($email, $password, $remember);
  }

  public function logout()
  {
    $this->user->logout();
  }

  public function isAuthenticated()
  {
    return $this->user->isAuthenticated();
  }

  public function hasRole($userId, $roleName)
  {
    return in_array($roleName, $this->role->getUserRoles($userId));
  }

  public function hasPermission($userId, $permissionName)
  {
    return $this->permission->hasPermission($userId, $permissionName);
  }

  public function assignRole($userId, $roleId)
  {
    return $this->role->assignRole($userId, $roleId);
  }

  public function assignPermissionToRole($roleId, $permissionId)
  {
    return $this->permission->assignPermissionToRole($roleId, $permissionId);
  }

  public function generateCsrfToken()
  {
    return $this->session->generateCsrfToken();
  }

  public function verifyCsrfToken($token)
  {
    return $this->session->verifyCsrfToken($token);
  }

  /**
   * Get OAuth authorization URL
   * 
   * @param string $provider The OAuth provider (google, facebook, github, etc.)
   * @return string The authorization URL
   */
  public function getOAuthAuthorizationUrl($provider)
  {
    return $this->oauthHandler->getAuthorizationUrl($provider);
  }

  /**
   * Handle OAuth callback
   * 
   * @param string $provider The OAuth provider
   * @param array $requestParams The request parameters ($_GET array)
   * @return int|bool User ID on success, false on failure
   */
  public function handleOAuthCallback($provider, $requestParams)
  {
    $userId = $this->oauthHandler->handleCallback($provider, $requestParams);

    // Assign default role if it's a new user
    if ($userId && !$this->hasRole($userId, 'User')) {
      $this->assignRole($userId, 1);  // Assign 'User' role (ID: 1)
    }

    return $userId;
  }
}
