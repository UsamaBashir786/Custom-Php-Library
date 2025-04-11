<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// Redirect to OAuth provider
if (isset($_GET['provider'])) {
  $provider = $_GET['provider'];

  try {
    $authUrl = $auth->getOAuthAuthorizationUrl($provider);
    header('Location: ' . $authUrl);
    exit;
  } catch (Exception $e) {
    die("Error: " . $e->getMessage());
  }
}

// If no provider specified, redirect to login page
header('Location: login.php');
exit;
