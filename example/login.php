<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// If user is already logged in, redirect to dashboard
if ($auth->isAuthenticated()) {
  header('Location: dashboard.php');
  exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    $error = 'Invalid CSRF token';
  } else {
    $email = $_POST['email'];
    $password = $_POST['password'];
    $remember = isset($_POST['remember']) ? true : false;

    if ($auth->login($email, $password, $remember)) {
      header('Location: dashboard.php');
      exit;
    } else {
      $error = "Invalid credentials. Please try again.";
    }
  }
}

// Check for any messages (like from registration)
$message = '';
if (isset($_SESSION['message'])) {
  $message = $_SESSION['message'];
  unset($_SESSION['message']);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login | Role-Based Authentication</title>
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary-color: #6366F1;
      --primary-hover: #4F46E5;
      --secondary-color: #EC4899;
      --dark-color: #1F2937;
      --light-color: #F9FAFB;
      --success-color: #10B981;
      --danger-color: #EF4444;
      --warning-color: #F59E0B;
    }

    body {
      background-color: #F3F4F6;
      font-family: 'Nunito', sans-serif;
      color: #374151;
      min-height: 100vh;
    }

    .auth-layout {
      display: flex;
      min-height: 100vh;
    }

    .auth-sidebar {
      display: none;
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      width: 40%;
      position: relative;
      overflow: hidden;
    }

    @media (min-width: 992px) {
      .auth-sidebar {
        display: block;
      }

      .auth-container {
        width: 60%;
      }
    }

    .auth-container {
      padding: 2rem;
      width: 100%;
      display: flex;
      flex-direction: column;
      justify-content: center;
      max-width: 800px;
      margin: 0 auto;
    }

    .auth-sidebar-content {
      position: relative;
      z-index: 2;
      color: white;
      height: 100%;
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 2rem;
    }

    .sidebar-heading {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 1.5rem;
    }

    .sidebar-text {
      font-size: 1.1rem;
      margin-bottom: 2rem;
      line-height: 1.6;
    }

    .sidebar-svg {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 1;
      opacity: 0.2;
    }

    .pattern-dots {
      position: absolute;
      width: 100%;
      height: 100%;
      top: 0;
      left: 0;
      z-index: 1;
      opacity: 0.3;
      background-image: radial-gradient(#fff 2px, transparent 2px);
      background-size: 30px 30px;
    }

    .card {
      border: none;
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
      border-radius: 0.75rem;
      background-color: white;
    }

    .card-header {
      background-color: white;
      border-bottom: 1px solid #E5E7EB;
      padding: 1.5rem;
      font-weight: 700;
      font-size: 1.5rem;
      border-radius: 0.75rem 0.75rem 0 0 !important;
      display: flex;
      align-items: center;
    }

    .card-header-icon {
      margin-right: 0.75rem;
      width: 1.75rem;
      height: 1.75rem;
      color: var(--primary-color);
    }

    .form-control {
      border-radius: 0.5rem;
      border: 1px solid #D1D5DB;
      padding: 0.75rem 1rem;
      font-size: 0.95rem;
      transition: all 0.2s ease;
    }

    .form-control:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
    }

    .form-label {
      color: #4B5563;
      font-weight: 600;
      font-size: 0.95rem;
      margin-bottom: 0.5rem;
    }

    .form-text {
      color: #6B7280;
      font-size: 0.85rem;
      margin-top: 0.25rem;
    }

    .input-icon {
      position: absolute;
      left: 1rem;
      top: 50%;
      transform: translateY(-50%);
      color: #9CA3AF;
    }

    .form-control.has-icon {
      padding-left: 2.75rem;
    }

    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
      font-weight: 600;
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      transition: all 0.2s ease;
    }

    .btn-primary:hover {
      background-color: var(--primary-hover);
      border-color: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.2), 0 2px 4px -1px rgba(99, 102, 241, 0.1);
    }

    .alert-danger {
      background-color: #FEF2F2;
      border-color: #F87171;
      color: #B91C1C;
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      position: relative;
      overflow: hidden;
    }

    .alert-danger::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      background-color: var(--danger-color);
    }

    .alert-success {
      background-color: #ECFDF5;
      border-color: #6EE7B7;
      color: #047857;
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      position: relative;
      overflow: hidden;
    }

    .alert-success::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      background-color: var(--success-color);
    }

    .is-invalid {
      border-color: var(--danger-color);
    }

    .invalid-feedback {
      color: var(--danger-color);
      font-size: 0.85rem;
      margin-top: 0.25rem;
    }

    .form-check-input:checked {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .auth-footer {
      text-align: center;
      margin-top: 2rem;
      font-size: 0.95rem;
      color: #6B7280;
    }

    .auth-footer a {
      color: var(--primary-color);
      text-decoration: none;
      font-weight: 600;
    }

    .auth-footer a:hover {
      text-decoration: underline;
    }

    .logo {
      text-align: left;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
    }

    .logo svg {
      width: 2.5rem;
      height: 2.5rem;
      margin-right: 0.75rem;
    }

    .logo-text {
      font-weight: 800;
      font-size: 1.75rem;
      color: var(--dark-color);
    }

    .password-toggle-icon {
      position: absolute;
      right: 1rem;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: #6B7280;
    }

    .required::after {
      content: " *";
      color: var(--danger-color);
    }

    .field-icon {
      color: #9CA3AF;
      width: 1.25rem;
      height: 1.25rem;
    }

    .remember-me-container {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
    }

    .form-check-label {
      color: #4B5563;
      font-size: 0.95rem;
    }
  </style>
</head>

<body>
  <div class="auth-layout">
    <!-- Sidebar with pattern and illustration (similar to Laravel) -->
    <div class="auth-sidebar">
      <div class="pattern-dots"></div>
      <div class="auth-sidebar-content">
        <h1 class="sidebar-heading">Welcome Back!</h1>
        <p class="sidebar-text">Sign in to your account to access your dashboard, manage your roles and permissions, and continue your work with the RoleAuth system.</p>

        <div class="sidebar-features">
          <div class="d-flex align-items-center mb-3">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>Secure authentication</span>
          </div>
          <div class="d-flex align-items-center mb-3">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>Role-based permissions</span>
          </div>
          <div class="d-flex align-items-center">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>User management</span>
          </div>
        </div>
      </div>

      <!-- SVG pattern at the bottom of the sidebar -->
      <svg class="sidebar-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320">
        <path fill="rgba(255, 255, 255, 0.2)" fill-opacity="1" d="M0,224L48,213.3C96,203,192,181,288,181.3C384,181,480,203,576,197.3C672,192,768,160,864,144C960,128,1056,128,1152,149.3C1248,171,1344,213,1392,234.7L1440,256L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path>
      </svg>
    </div>

    <!-- Main content area -->
    <div class="auth-container">
      <div class="logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="#6366F1" stroke="#6366F1" />
          <path d="M9 12l2 2 4-4" stroke="white" stroke-width="2" />
        </svg>
        <span class="logo-text">RoleAuth</span>
      </div>

      <?php if (!empty($error)): ?>
        <div class="alert alert-danger p-4 mb-4" role="alert">
          <div class="d-flex">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-3">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <div>
              <h5 class="alert-heading mb-1 fw-bold">Login Failed</h5>
              <p class="mb-0"><?php echo htmlspecialchars($error); ?></p>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <?php if (!empty($message)): ?>
        <div class="alert alert-success p-4 mb-4" role="alert">
          <div class="d-flex">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-3">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <div>
              <h5 class="alert-heading mb-1 fw-bold">Success</h5>
              <p class="mb-0"><?php echo htmlspecialchars($message); ?></p>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <div class="card mb-4">
        <div class="card-header">
          <svg xmlns="http://www.w3.org/2000/svg" class="card-header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          Sign In to Your Account
        </div>
        <div class="card-body p-4">
          <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

            <div class="mb-3">
              <label for="email" class="form-label required">Email Address</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                  <polyline points="22,6 12,13 2,6"></polyline>
                </svg>
                <input type="email" class="form-control has-icon" id="email" name="email" placeholder="name@example.com" required>
              </div>
            </div>

            <div class="mb-3 position-relative">
              <label for="password" class="form-label required">Password</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                <input type="password" class="form-control has-icon" id="password" name="password" placeholder="Enter your password" required>
                <i class="fas fa-eye-slash password-toggle-icon" id="togglePassword"></i>
              </div>
            </div>

            <div class="remember-me-container">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="remember" name="remember">
                <label class="form-check-label" for="remember">
                  Remember me
                </label>
              </div>
              <a href="forgot_password.php" class="text-sm">Forgot password?</a>
            </div>

            <div class="d-grid gap-2">
              <button type="submit" class="btn btn-primary">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
                  <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>
                  <polyline points="10 17 15 12 10 7"></polyline>
                  <line x1="15" y1="12" x2="3" y2="12"></line>
                </svg>
                Sign In
              </button>
            </div>
          </form>
        </div>
      </div>
      <!-- Social Login Buttons -->
      <div class="social-login mb-4">
        <p class="text-center mb-3">Or sign in with</p>
        <div class="d-flex justify-content-center gap-3">
          <a href="oauth_login.php?provider=google" class="btn btn-outline-dark">
            <i class="fab fa-google me-2"></i>Google
          </a>
          <a href="oauth_login.php?provider=facebook" class="btn btn-outline-primary">
            <i class="fab fa-facebook-f me-2"></i>Facebook
          </a>
          <a href="oauth_login.php?provider=github" class="btn btn-outline-secondary">
            <i class="fab fa-github me-2"></i>GitHub
          </a>
        </div>
      </div>
      <div class="auth-footer">
        <p>Don't have an account? <a href="register.php">Create an account</a></p>
      </div>
    </div>
  </div>

  <!-- Bootstrap and other scripts -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Password toggle visibility
    document.getElementById('togglePassword').addEventListener('click', function() {
      const passwordInput = document.getElementById('password');
      const icon = this;

      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      }
    });
  </script>
</body>

</html>