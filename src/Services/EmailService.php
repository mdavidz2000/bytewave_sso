<?php
namespace App\Services;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class EmailService
{
    private $mailer;
    private $fromEmail;
    private $fromName;
    private $appUrl;

    public function __construct(array $config)
    {
        $this->fromEmail = $config['from_email'] ?? 'noreply@example.com';
        $this->fromName = $config['from_name'] ?? 'SSO Auth System';
        $this->appUrl = $config['app_url'] ?? 'http://localhost:8080';

        $this->mailer = new PHPMailer(true);
        
        // SMTP configuration
        if ($config['driver'] === 'smtp') {
            $this->mailer->isSMTP();
            $this->mailer->Host = $config['host'];
            $this->mailer->SMTPAuth = true;
            $this->mailer->Username = $config['username'];
            $this->mailer->Password = $config['password'];
            $this->mailer->SMTPSecure = $config['encryption'] ?? PHPMailer::ENCRYPTION_STARTTLS;
            $this->mailer->Port = $config['port'] ?? 587;
        } else {
            // Use mail() function
            $this->mailer->isMail();
        }
    }

    public function sendVerificationEmail(string $toEmail, string $token): bool
    {
        $verificationUrl = $this->appUrl . "/verify-email?token=" . urlencode($token);
        
        $subject = "Verify Your Email Address";
        $body = $this->renderTemplate('verification_email', [
            'verification_url' => $verificationUrl,
            'expiry_hours' => 24
        ]);

        return $this->sendEmail($toEmail, $subject, $body);
    }

    public function sendPasswordResetEmail(string $toEmail, string $token): bool
    {
        $resetUrl = $this->appUrl . "/reset-password?token=" . urlencode($token);
        
        $subject = "Password Reset Request";
        $body = $this->renderTemplate('password_reset', [
            'reset_url' => $resetUrl,
            'expiry_hours' => 1
        ]);

        return $this->sendEmail($toEmail, $subject, $body);
    }

    public function sendWelcomeEmail(string $toEmail, string $name): bool
    {
        $subject = "Welcome to Our Platform!";
        $body = $this->renderTemplate('welcome', [
            'name' => $name,
            'login_url' => $this->appUrl . "/login"
        ]);

        return $this->sendEmail($toEmail, $subject, $body);
    }

    public function sendSecurityAlert(string $toEmail, string $alertType, array $data = []): bool
    {
        $subject = "Security Alert: " . ucfirst(str_replace('_', ' ', $alertType));
        $body = $this->renderTemplate('security_alert', array_merge($data, [
            'alert_type' => $alertType,
            'support_email' => $this->fromEmail
        ]));

        return $this->sendEmail($toEmail, $subject, $body);
    }

    private function sendEmail(string $to, string $subject, string $body): bool
    {
        try {
            $this->mailer->clearAddresses();
            $this->mailer->setFrom($this->fromEmail, $this->fromName);
            $this->mailer->addAddress($to);
            
            $this->mailer->isHTML(true);
            $this->mailer->Subject = $subject;
            $this->mailer->Body = $body;
            $this->mailer->AltBody = strip_tags($body);

            return $this->mailer->send();
        } catch (Exception $e) {
            error_log('Email sending failed: ' . $e->getMessage());
            return false;
        }
    }

    private function renderTemplate(string $template, array $data): string
    {
        // Simple template rendering - you can replace with Twig or similar
        $templates = [
            'verification_email' => '
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .button { 
                            display: inline-block; 
                            padding: 12px 24px; 
                            background-color: #007bff; 
                            color: white; 
                            text-decoration: none; 
                            border-radius: 4px; 
                            margin: 20px 0; 
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Verify Your Email Address</h2>
                        <p>Please click the button below to verify your email address:</p>
                        <a href="{{verification_url}}" class="button">Verify Email</a>
                        <p>Or copy and paste this link into your browser:<br>
                        <code>{{verification_url}}</code></p>
                        <p>This link will expire in {{expiry_hours}} hours.</p>
                        <p>If you did not create an account, please ignore this email.</p>
                    </div>
                </body>
                </html>
            ',
            
            'password_reset' => '
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .button { 
                            display: inline-block; 
                            padding: 12px 24px; 
                            background-color: #dc3545; 
                            color: white; 
                            text-decoration: none; 
                            border-radius: 4px; 
                            margin: 20px 0; 
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Reset Your Password</h2>
                        <p>You requested to reset your password. Click the button below:</p>
                        <a href="{{reset_url}}" class="button">Reset Password</a>
                        <p>Or copy and paste this link into your browser:<br>
                        <code>{{reset_url}}</code></p>
                        <p>This link will expire in {{expiry_hours}} hour(s).</p>
                        <p>If you did not request a password reset, please ignore this email.</p>
                    </div>
                </body>
                </html>
            '
        ];

        $template = $templates[$template] ?? '<p>{{message}}</p>';
        
        foreach ($data as $key => $value) {
            $template = str_replace('{{' . $key . '}}', $value, $template);
        }
        
        return $template;
    }
}