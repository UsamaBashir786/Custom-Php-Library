<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// Handle OAuth callback
if (isset($_GET['provider'], $_GET['code'], $_GET['state'])) {
  $provider = $_GET['provider'];

  try {
    $auth->handleOAuthCallback($provider, $_GET);

    // Redirect to dashboard after successful login
    header('Location: dashboard.php');
    exit;
  } catch (Exception $e) {
    // Redirect to login page with error
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['error'] = "OAuth Error: " . $e->getMessage();
    header('Location: login.php');
    exit;
  }
}

// If missing parameters, redirect to login page
header('Location: login.php');
exit;
