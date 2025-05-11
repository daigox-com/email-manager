<?php

class EmailManager
{
    private const VALID_EMAIL_DOMAINS = ['gmail.com', 'yahoo.com', 'outlook.com', 'mail.com', 'hotmail.com', 'icloud.com'];

    public static function isEmailValid($email): bool
    {
        $email = self::cleanEmail($email);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }
        return self::isDomainValid($email);
    }

    private static function isDomainValid($email): bool
    {
        $domain = self::extractDomainFromEmail($email, false);
        return in_array($domain, self::VALID_EMAIL_DOMAINS);
    }

    public static function extractDomainFromEmail($email, $validate = true): string|false
    {
        $email = self::cleanEmail($email);
        if (!$validate || self::isEmailValidWithoutDomainCheck($email)) {
            return substr(strrchr($email, "@"), 1);
        }
        return false;
    }

    public static function formatLocalPartOfEmail($email): string|false
    {
        $email = self::cleanEmail($email);
        if (self::isEmailValidWithoutDomainCheck($email)) {
            $localPart = strstr($email, '@', true);
            return strtolower($localPart);
        }
        return false;
    }

    public static function formatCompleteEmail($email): string|false
    {
        $email = self::cleanEmail($email);
        if (self::isEmailValidWithoutDomainCheck($email)) {
            $localPart = self::formatLocalPartOfEmail($email);
            $domain = self::extractDomainFromEmail($email, false);
            return $localPart . '@' . $domain;
        }
        return false;
    }

    public static function cleanEmail($email): string
    {
        $emailParts = explode('@', $email);
        $emailParts[0] = str_replace('.', '', $emailParts[0]);
        return implode('@', $emailParts);
    }

    public static function listValidDomains(): array
    {
        return self::VALID_EMAIL_DOMAINS;
    }

    public static function isEmailValidWithoutDomainCheck($email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
}