<?php

namespace DaigoxCom\Email;

use InvalidArgumentException;
use RuntimeException;

/**
 * Ultimate Email Manager
 * 
 * The most comprehensive email handling library with advanced validation,
 * normalization, generation, and analysis capabilities.
 * 
 * @author DaigoX.com
 * @license MIT
 * @version 2.0.0
 */
class EmailManager
{
    // Email regex patterns
    const PATTERN_BASIC = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
    const PATTERN_STRICT = '/^[a-zA-Z0-9!#$%&\'*+\/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+\/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/';
    const PATTERN_RFC5322 = '/^(?:[a-z0-9!#$%&\'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+\/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$/i';
    
    // Popular email providers
    const PROVIDERS = [
        // Global providers
        'gmail' => ['gmail.com', 'googlemail.com'],
        'outlook' => ['outlook.com', 'hotmail.com', 'live.com', 'msn.com'],
        'yahoo' => ['yahoo.com', 'yahoo.co.uk', 'yahoo.co.jp', 'yahoo.fr', 'yahoo.de', 'yahoo.es', 'yahoo.it', 'yahoo.ca', 'yahoo.com.br', 'yahoo.com.au', 'yahoo.in', 'yahoo.co.id'],
        'apple' => ['icloud.com', 'me.com', 'mac.com'],
        'aol' => ['aol.com', 'aim.com'],
        'proton' => ['protonmail.com', 'protonmail.ch', 'pm.me'],
        
        // Regional providers
        'mail_ru' => ['mail.ru', 'inbox.ru', 'list.ru', 'bk.ru'],
        'yandex' => ['yandex.ru', 'yandex.com', 'ya.ru'],
        'gmx' => ['gmx.com', 'gmx.de', 'gmx.net'],
        'web_de' => ['web.de'],
        'qq' => ['qq.com'],
        '163' => ['163.com', '126.com'],
        'sina' => ['sina.com', 'sina.cn'],
        'naver' => ['naver.com'],
        'daum' => ['daum.net', 'hanmail.net'],
        
        // Privacy-focused
        'tutanota' => ['tutanota.com', 'tutanota.de', 'tutamail.com', 'tuta.io'],
        'fastmail' => ['fastmail.com', 'fastmail.fm'],
        'zoho' => ['zoho.com', 'zohomail.com'],
        'mailfence' => ['mailfence.com'],
        'mailbox' => ['mailbox.org'],
        
        // ISP providers
        'comcast' => ['comcast.net'],
        'verizon' => ['verizon.net'],
        'att' => ['att.net'],
        'cox' => ['cox.net'],
        'charter' => ['charter.net'],
        'earthlink' => ['earthlink.net'],
    ];
    
    // Disposable email domains
    const DISPOSABLE_DOMAINS = [
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.com',
        'throwaway.email', 'yopmail.com', 'maildrop.cc', 'minutemails.com',
        'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net', 'spam4.me',
        'grr.la', 'mailnesia.com', 'trash-mail.com', 'temp-mail.org',
    ];
    
    // Role-based local parts
    const ROLE_BASED = [
        'admin', 'administrator', 'webmaster', 'postmaster', 'hostmaster',
        'info', 'support', 'help', 'contact', 'sales', 'marketing',
        'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'abuse',
        'spam', 'root', 'system', 'null', 'void', 'team', 'staff',
        'office', 'hello', 'mail', 'email', 'test', 'testing'
    ];
    
    // TLD categories
    const TLD_CATEGORIES = [
        'generic' => ['com', 'net', 'org', 'info', 'biz', 'name', 'pro'],
        'sponsored' => ['edu', 'gov', 'mil', 'int', 'coop', 'museum', 'aero'],
        'country' => ['us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in'],
        'new' => ['tech', 'online', 'site', 'xyz', 'top', 'club', 'vip', 'shop'],
    ];
    
    // Custom domain allowlist
    private static array $customAllowedDomains = [];
    
    // Custom domain blocklist
    private static array $customBlockedDomains = [];
    
    // DNS cache
    private static array $dnsCache = [];
    
    // Prevent instantiation
    private function __construct() {}
    
    // ============================= Core Validation =============================
    
    /**
     * Validate email with various levels
     */
    public static function validate(string $email, array $options = []): bool
    {
        $options = array_merge([
            'checkDns' => false,
            'checkMx' => false,
            'checkDisposable' => true,
            'checkRole' => false,
            'allowIdn' => true,
            'allowIp' => false,
            'strict' => false,
        ], $options);
        
        // Basic validation
        if (!self::isValidSyntax($email, $options['strict'])) {
            return false;
        }
        
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return false;
        }
        
        list($local, $domain) = explode('@', $normalized, 2);
        
        // Check if IP address is used as domain
        if (self::isIpDomain($domain)) {
            if (!$options['allowIp']) {
                return false;
            }
        }
        
        // Check disposable
        if ($options['checkDisposable'] && self::isDisposable($email)) {
            return false;
        }
        
        // Check role-based
        if ($options['checkRole'] && self::isRoleBased($email)) {
            return false;
        }
        
        // DNS checks
        if ($options['checkDns'] && !self::hasDnsRecord($domain)) {
            return false;
        }
        
        if ($options['checkMx'] && !self::hasMxRecord($domain)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if email has valid syntax
     */
    public static function isValidSyntax(string $email, bool $strict = false): bool
    {
        if ($strict) {
            return preg_match(self::PATTERN_RFC5322, $email) === 1;
        }
        
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    /**
     * Comprehensive email validation
     */
    public static function isValid(string $email): bool
    {
        return self::validate($email);
    }
    
    // ============================= Normalization =============================
    
    /**
     * Normalize email address
     */
    public static function normalize(string $email): ?string
    {
        $email = trim(mb_strtolower($email, 'UTF-8'));
        
        // Remove any whitespace
        $email = preg_replace('/\s+/', '', $email);
        
        // Basic validation
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return null;
        }
        
        list($local, $domain) = explode('@', $email, 2);
        
        // Normalize based on provider
        $local = self::normalizeLocalPart($local, $domain);
        
        // Convert IDN to ASCII
        $domain = self::toAsciiDomain($domain);
        if ($domain === null) {
            return null;
        }
        
        return $local . '@' . $domain;
    }
    
    /**
     * Normalize local part based on provider rules
     */
    private static function normalizeLocalPart(string $local, string $domain): string
    {
        // Gmail/Googlemail: remove dots and everything after +
        if (in_array($domain, ['gmail.com', 'googlemail.com'])) {
            $local = str_replace('.', '', $local);
            if (($pos = strpos($local, '+')) !== false) {
                $local = substr($local, 0, $pos);
            }
        }
        
        // Outlook/Hotmail: remove everything after +
        elseif (in_array($domain, ['outlook.com', 'hotmail.com', 'live.com'])) {
            if (($pos = strpos($local, '+')) !== false) {
                $local = substr($local, 0, $pos);
            }
        }
        
        // Yahoo: remove - and everything after
        elseif (strpos($domain, 'yahoo.') === 0) {
            if (($pos = strpos($local, '-')) !== false) {
                $local = substr($local, 0, $pos);
            }
        }
        
        // Apple: remove everything after +
        elseif (in_array($domain, ['icloud.com', 'me.com', 'mac.com'])) {
            if (($pos = strpos($local, '+')) !== false) {
                $local = substr($local, 0, $pos);
            }
        }
        
        return $local;
    }
    
    /**
     * Canonicalize email (aggressive normalization)
     */
    public static function canonicalize(string $email): ?string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return null;
        }
        
        list($local, $domain) = explode('@', $normalized, 2);
        
        // Remove all dots from local part (even for non-Gmail)
        $local = str_replace('.', '', $local);
        
        // Remove any numbers at the end
        $local = preg_replace('/\d+$/', '', $local);
        
        return $local . '@' . $domain;
    }
    
    // ============================= Domain Operations =============================
    
    /**
     * Extract domain from email
     */
    public static function getDomain(string $email): ?string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return null;
        }
        
        return substr(strrchr($normalized, '@'), 1);
    }
    
    /**
     * Extract local part from email
     */
    public static function getLocalPart(string $email): ?string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return null;
        }
        
        return strstr($normalized, '@', true);
    }
    
    /**
     * Get provider name
     */
    public static function getProvider(string $email): ?string
    {
        $domain = self::getDomain($email);
        if ($domain === null) {
            return null;
        }
        
        foreach (self::PROVIDERS as $provider => $domains) {
            if (in_array($domain, $domains)) {
                return $provider;
            }
        }
        
        return null;
    }
    
    /**
     * Get TLD from email
     */
    public static function getTld(string $email): ?string
    {
        $domain = self::getDomain($email);
        if ($domain === null) {
            return null;
        }
        
        $parts = explode('.', $domain);
        return end($parts);
    }
    
    /**
     * Get SLD (Second Level Domain)
     */
    public static function getSld(string $email): ?string
    {
        $domain = self::getDomain($email);
        if ($domain === null) {
            return null;
        }
        
        $parts = explode('.', $domain);
        if (count($parts) < 2) {
            return null;
        }
        
        return $parts[count($parts) - 2];
    }
    
    // ============================= DNS & MX Checks =============================
    
    /**
     * Check if domain has DNS records
     */
    public static function hasDnsRecord(string $domain): bool
    {
        if (isset(self::$dnsCache[$domain]['dns'])) {
            return self::$dnsCache[$domain]['dns'];
        }
        
        $result = checkdnsrr($domain, 'ANY');
        self::$dnsCache[$domain]['dns'] = $result;
        
        return $result;
    }
    
    /**
     * Check if domain has MX records
     */
    public static function hasMxRecord(string $domain): bool
    {
        if (isset(self::$dnsCache[$domain]['mx'])) {
            return self::$dnsCache[$domain]['mx'];
        }
        
        $result = checkdnsrr($domain, 'MX');
        self::$dnsCache[$domain]['mx'] = $result;
        
        return $result;
    }
    
    /**
     * Get MX records
     */
    public static function getMxRecords(string $domain): array
    {
        $mxRecords = [];
        if (getmxrr($domain, $mxRecords, $weights)) {
            array_multisort($weights, $mxRecords);
            return $mxRecords;
        }
        
        return [];
    }
    
    /**
     * Get DNS records
     */
    public static function getDnsRecords(string $domain, int $type = DNS_ALL): array|false
    {
        return dns_get_record($domain, $type);
    }
    
    /**
     * Verify email deliverability (advanced check)
     */
    public static function isDeliverable(string $email): bool
    {
        $domain = self::getDomain($email);
        if ($domain === null) {
            return false;
        }
        
        // Check MX records
        if (!self::hasMxRecord($domain)) {
            // Fallback to A record
            if (!self::hasDnsRecord($domain)) {
                return false;
            }
        }
        
        return true;
    }
    
    // ============================= Classification =============================
    
    /**
     * Check if email is disposable/temporary
     */
    public static function isDisposable(string $email): bool
    {
        $domain = self::getDomain($email);
        if ($domain === null) {
            return false;
        }
        
        // Check against known disposable domains
        if (in_array($domain, self::DISPOSABLE_DOMAINS)) {
            return true;
        }
        
        // Check custom blocked domains
        if (in_array($domain, self::$customBlockedDomains)) {
            return true;
        }
        
        // Check common patterns
        $patterns = [
            '/^(temp|tmp|disposable|throwaway|trash|fake|dummy)/i',
            '/\d{5,}/', // Many numbers
            '/mailinator\d*/i',
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $domain)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if email is role-based
     */
    public static function isRoleBased(string $email): bool
    {
        $local = self::getLocalPart($email);
        if ($local === null) {
            return false;
        }
        
        return in_array($local, self::ROLE_BASED);
    }
    
    /**
     * Check if email is free provider
     */
    public static function isFreeProvider(string $email): bool
    {
        $provider = self::getProvider($email);
        
        $freeProviders = ['gmail', 'yahoo', 'outlook', 'aol', 'proton', 'icloud'];
        
        return in_array($provider, $freeProviders);
    }
    
    /**
     * Check if email is corporate
     */
    public static function isCorporate(string $email): bool
    {
        return !self::isFreeProvider($email) && !self::isDisposable($email);
    }
    
    /**
     * Check if domain is IP address
     */
    public static function isIpDomain(string $domain): bool
    {
        // Check for [IP] format
        if (preg_match('/^\[(.+)\]$/', $domain, $matches)) {
            $domain = $matches[1];
        }
        
        return filter_var($domain, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * Get email type
     */
    public static function getType(string $email): string
    {
        if (self::isDisposable($email)) {
            return 'disposable';
        }
        
        if (self::isRoleBased($email)) {
            return 'role-based';
        }
        
        if (self::isFreeProvider($email)) {
            return 'free';
        }
        
        return 'corporate';
    }
    
    // ============================= Generation =============================
    
    /**
     * Generate random email
     */
    public static function generate(array $options = []): string
    {
        $options = array_merge([
            'provider' => 'gmail.com',
            'length' => 10,
            'includeNumbers' => true,
            'includeDots' => false,
            'prefix' => '',
            'suffix' => '',
        ], $options);
        
        $chars = 'abcdefghijklmnopqrstuvwxyz';
        if ($options['includeNumbers']) {
            $chars .= '0123456789';
        }
        
        $local = $options['prefix'];
        
        for ($i = 0; $i < $options['length']; $i++) {
            if ($options['includeDots'] && $i > 0 && $i < $options['length'] - 1 && rand(0, 4) === 0) {
                $local .= '.';
            }
            $local .= $chars[rand(0, strlen($chars) - 1)];
        }
        
        $local .= $options['suffix'];
        
        return $local . '@' . $options['provider'];
    }
    
    /**
     * Generate alias
     */
    public static function generateAlias(string $email, string $alias): ?string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return null;
        }
        
        list($local, $domain) = explode('@', $normalized, 2);
        
        // Gmail style
        if (in_array($domain, ['gmail.com', 'googlemail.com'])) {
            return $local . '+' . $alias . '@' . $domain;
        }
        
        // Outlook style
        if (in_array($domain, ['outlook.com', 'hotmail.com'])) {
            return $local . '+' . $alias . '@' . $domain;
        }
        
        // Yahoo style
        if (strpos($domain, 'yahoo.') === 0) {
            return $local . '-' . $alias . '@' . $domain;
        }
        
        // Default: use + notation
        return $local . '+' . $alias . '@' . $domain;
    }
    
    /**
     * Generate variations
     */
    public static function generateVariations(string $email): array
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return [];
        }
        
        list($local, $domain) = explode('@', $normalized, 2);
        $variations = [];
        
        // Original
        $variations[] = $email;
        
        // With dots (Gmail)
        if (in_array($domain, ['gmail.com', 'googlemail.com'])) {
            $chars = str_split($local);
            $count = count($chars);
            
            // Add some dot variations
            for ($i = 1; $i < min(4, $count); $i++) {
                $variant = implode('', array_slice($chars, 0, $i)) . '.' . 
                          implode('', array_slice($chars, $i));
                $variations[] = $variant . '@' . $domain;
            }
            
            // googlemail variant
            if ($domain === 'gmail.com') {
                $variations[] = $local . '@googlemail.com';
            } elseif ($domain === 'googlemail.com') {
                $variations[] = $local . '@gmail.com';
            }
        }
        
        return array_unique($variations);
    }
    
    // ============================= Formatting & Display =============================
    
    /**
     * Mask email for privacy
     */
    public static function mask(string $email, int $visibleChars = 3, string $maskChar = '*'): string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return $email;
        }
        
        list($local, $domain) = explode('@', $normalized, 2);
        $localLength = strlen($local);
        
        if ($localLength <= $visibleChars * 2) {
            // Too short, mask middle
            $masked = substr($local, 0, 1) . str_repeat($maskChar, $localLength - 2) . substr($local, -1);
        } else {
            // Show first and last n characters
            $masked = substr($local, 0, $visibleChars) . 
                     str_repeat($maskChar, $localLength - $visibleChars * 2) . 
                     substr($local, -$visibleChars);
        }
        
        // Mask domain partially
        $domainParts = explode('.', $domain);
        if (count($domainParts) > 1) {
            $domainParts[0] = substr($domainParts[0], 0, 1) . str_repeat($maskChar, strlen($domainParts[0]) - 1);
            $domain = implode('.', $domainParts);
        }
        
        return $masked . '@' . $domain;
    }
    
    /**
     * Obfuscate email for display
     */
    public static function obfuscate(string $email, string $method = 'html'): string
    {
        switch ($method) {
            case 'html':
                return self::obfuscateHtml($email);
                
            case 'unicode':
                return self::obfuscateUnicode($email);
                
            case 'text':
                return strtr($email, [
                    '@' => ' [at] ',
                    '.' => ' [dot] '
                ]);
                
            case 'reverse':
                return strrev($email);
                
            case 'rot13':
                return str_rot13($email);
                
            default:
                return $email;
        }
    }
    
    /**
     * HTML entity obfuscation
     */
    private static function obfuscateHtml(string $email): string
    {
        $obfuscated = '';
        $length = strlen($email);
        
        for ($i = 0; $i < $length; $i++) {
            $char = $email[$i];
            
            if (rand(0, 1)) {
                $obfuscated .= '&#' . ord($char) . ';';
            } else {
                $obfuscated .= '&#x' . dechex(ord($char)) . ';';
            }
        }
        
        return $obfuscated;
    }
    
    /**
     * Unicode obfuscation
     */
    private static function obfuscateUnicode(string $email): string
    {
        $replacements = [
            'a' => 'а', // Cyrillic
            'e' => 'е', // Cyrillic
            'o' => 'о', // Cyrillic
            'p' => 'р', // Cyrillic
            'c' => 'с', // Cyrillic
            'x' => 'х', // Cyrillic
        ];
        
        return strtr($email, $replacements);
    }
    
    /**
     * Create mailto link
     */
    public static function createMailtoLink(string $email, array $params = []): string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return '';
        }
        
        $link = 'mailto:' . $normalized;
        
        if (!empty($params)) {
            $queryParams = [];
            
            foreach (['subject', 'body', 'cc', 'bcc'] as $param) {
                if (isset($params[$param])) {
                    $queryParams[] = $param . '=' . rawurlencode($params[$param]);
                }
            }
            
            if (!empty($queryParams)) {
                $link .= '?' . implode('&', $queryParams);
            }
        }
        
        return $link;
    }
    
    /**
     * Create Gravatar URL
     */
    public static function getGravatarUrl(string $email, int $size = 80, string $default = 'mp', string $rating = 'g'): string
    {
        $normalized = self::normalize($email);
        if ($normalized === null) {
            return '';
        }
        
        $hash = md5($normalized);
        
        return sprintf(
            'https://www.gravatar.com/avatar/%s?s=%d&d=%s&r=%s',
            $hash,
            $size,
            $default,
            $rating
        );
    }
    
    // ============================= Suggestions =============================
    
    /**
     * Suggest corrections for common typos
     */
    public static function suggest(string $email): array
    {
        $suggestions = [];
        
        // Extract parts
        if (strpos($email, '@') === false) {
            return $suggestions;
        }
        
        list($local, $domain) = explode('@', $email, 2);
        
        // Common domain typos
        $domainTypos = [
            'gmial.com' => 'gmail.com',
            'gmai.com' => 'gmail.com',
            'gmali.com' => 'gmail.com',
            'gnail.com' => 'gmail.com',
            'gmaill.com' => 'gmail.com',
            'yahooo.com' => 'yahoo.com',
            'yaho.com' => 'yahoo.com',
            'yahoo.co' => 'yahoo.com',
            'homail.com' => 'hotmail.com',
            'hotmai.com' => 'hotmail.com',
            'hotmial.com' => 'hotmail.com',
            'outlok.com' => 'outlook.com',
            'iclou.com' => 'icloud.com',
            'icoud.com' => 'icloud.com',
        ];
        
        if (isset($domainTypos[$domain])) {
            $suggestions[] = $local . '@' . $domainTypos[$domain];
        }
        
        // Check TLD typos
        $tldTypos = [
            '.con' => '.com',
            '.cpm' => '.com',
            '.xom' => '.com',
            '.vom' => '.com',
            '.com.' => '.com',
            '.co,' => '.com',
            '.cok' => '.com',
        ];
        
        foreach ($tldTypos as $typo => $correct) {
            if (str_ends_with($domain, $typo)) {
                $correctedDomain = substr($domain, 0, -strlen($typo)) . $correct;
                $suggestions[] = $local . '@' . $correctedDomain;
            }
        }
        
        // Suggest based on similarity
        $popularDomains = array_merge(...array_values(self::PROVIDERS));
        
        foreach ($popularDomains as $popularDomain) {
            $similarity = similar_text($domain, $popularDomain, $percent);
            if ($percent > 80 && $percent < 100) {
                $suggestions[] = $local . '@' . $popularDomain;
            }
        }
        
        return array_unique($suggestions);
    }
    
    /**
     * Check for common mistakes
     */
    public static function getCommonMistakes(string $email): array
    {
        $mistakes = [];
        
        // Missing @
        if (strpos($email, '@') === false) {
            $mistakes[] = 'Missing @ symbol';
        }
        
        // Multiple @
        if (substr_count($email, '@') > 1) {
            $mistakes[] = 'Multiple @ symbols';
        }
        
        // Starts or ends with @
        if (str_starts_with($email, '@') || str_ends_with($email, '@')) {
            $mistakes[] = 'Invalid @ position';
        }
        
        // Space in email
        if (strpos($email, ' ') !== false) {
            $mistakes[] = 'Contains spaces';
        }
        
        // Double dots
        if (strpos($email, '..') !== false) {
            $mistakes[] = 'Contains consecutive dots';
        }
        
        // Invalid characters
        if (preg_match('/[<>()[\]\\,;:\s]/', $email)) {
            $mistakes[] = 'Contains invalid characters';
        }
        
        return $mistakes;
    }
    
    // ============================= Analysis =============================
    
    /**
     * Analyze email comprehensively
     */
    public static function analyze(string $email): array
    {
        $analysis = [
            'valid' => false,
            'normalized' => null,
            'local_part' => null,
            'domain' => null,
            'provider' => null,
            'type' => null,
            'disposable' => false,
            'role_based' => false,
            'free_provider' => false,
            'has_mx' => false,
            'has_dns' => false,
            'tld' => null,
            'sld' => null,
            'suggestions' => [],
            'mistakes' => [],
            'risk_score' => 0,
        ];
        
        // Basic validation
        if (!self::isValidSyntax($email)) {
            $analysis['mistakes'] = self::getCommonMistakes($email);
            $analysis['suggestions'] = self::suggest($email);
            return $analysis;
        }
        
        $analysis['valid'] = true;
        $analysis['normalized'] = self::normalize($email);
        $analysis['local_part'] = self::getLocalPart($email);
        $analysis['domain'] = self::getDomain($email);
        $analysis['provider'] = self::getProvider($email);
        $analysis['type'] = self::getType($email);
        $analysis['disposable'] = self::isDisposable($email);
        $analysis['role_based'] = self::isRoleBased($email);
        $analysis['free_provider'] = self::isFreeProvider($email);
        $analysis['tld'] = self::getTld($email);
        $analysis['sld'] = self::getSld($email);
        
        // DNS checks (only if domain exists)
        if ($analysis['domain']) {
            $analysis['has_dns'] = self::hasDnsRecord($analysis['domain']);
            $analysis['has_mx'] = self::hasMxRecord($analysis['domain']);
        }
        
        // Calculate risk score
        $analysis['risk_score'] = self::calculateRiskScore($analysis);
        
        return $analysis;
    }
    
    /**
     * Calculate risk score (0-100)
     */
    private static function calculateRiskScore(array $analysis): int
    {
        $score = 0;
        
        if (!$analysis['valid']) {
            return 100;
        }
        
        if ($analysis['disposable']) {
            $score += 40;
        }
        
        if ($analysis['role_based']) {
            $score += 20;
        }
        
        if (!$analysis['has_mx']) {
            $score += 30;
        }
        
        if (!$analysis['has_dns']) {
            $score += 10;
        }
        
        // Reduce score for known good providers
        if (in_array($analysis['provider'], ['gmail', 'outlook', 'yahoo', 'apple'])) {
            $score = max(0, $score - 10);
        }
        
        return min(100, $score);
    }
    
    /**
     * Get email statistics
     */
    public static function getStatistics(array $emails): array
    {
        $stats = [
            'total' => count($emails),
            'valid' => 0,
            'invalid' => 0,
            'disposable' => 0,
            'role_based' => 0,
            'free' => 0,
            'corporate' => 0,
            'providers' => [],
            'tlds' => [],
            'risk_distribution' => [
                'low' => 0,    // 0-30
                'medium' => 0, // 31-60
                'high' => 0,   // 61-100
            ],
        ];
        
        foreach ($emails as $email) {
            $analysis = self::analyze($email);
            
            if ($analysis['valid']) {
                $stats['valid']++;
                
                if ($analysis['disposable']) $stats['disposable']++;
                if ($analysis['role_based']) $stats['role_based']++;
                if ($analysis['free_provider']) $stats['free']++;
                if ($analysis['type'] === 'corporate') $stats['corporate']++;
                
                // Provider stats
                if ($analysis['provider']) {
                    $stats['providers'][$analysis['provider']] = 
                        ($stats['providers'][$analysis['provider']] ?? 0) + 1;
                }
                
                // TLD stats
                if ($analysis['tld']) {
                    $stats['tlds'][$analysis['tld']] = 
                        ($stats['tlds'][$analysis['tld']] ?? 0) + 1;
                }
                
                // Risk distribution
                if ($analysis['risk_score'] <= 30) {
                    $stats['risk_distribution']['low']++;
                } elseif ($analysis['risk_score'] <= 60) {
                    $stats['risk_distribution']['medium']++;
                } else {
                    $stats['risk_distribution']['high']++;
                }
            } else {
                $stats['invalid']++;
            }
        }
        
        // Sort providers and TLDs by count
        arsort($stats['providers']);
        arsort($stats['tlds']);
        
        return $stats;
    }
    
    // ============================= Bulk Operations =============================
    
    /**
     * Validate multiple emails
     */
    public static function validateBulk(array $emails, array $options = []): array
    {
        $results = [];
        
        foreach ($emails as $email) {
            $results[$email] = self::validate($email, $options);
        }
        
        return $results;
    }
    
    /**
     * Normalize multiple emails
     */
    public static function normalizeBulk(array $emails): array
    {
        return array_map([self::class, 'normalize'], $emails);
    }
    
    /**
     * Filter valid emails
     */
    public static function filterValid(array $emails): array
    {
        return array_filter($emails, [self::class, 'isValid']);
    }
    
    /**
     * Filter invalid emails
     */
    public static function filterInvalid(array $emails): array
    {
        return array_filter($emails, fn($email) => !self::isValid($email));
    }
    
    /**
     * Group emails by provider
     */
    public static function groupByProvider(array $emails): array
    {
        $grouped = [];
        
        foreach ($emails as $email) {
            $provider = self::getProvider($email) ?? 'other';
            $grouped[$provider][] = $email;
        }
        
        return $grouped;
    }
    
    /**
     * Group emails by domain
     */
    public static function groupByDomain(array $emails): array
    {
        $grouped = [];
        
        foreach ($emails as $email) {
            $domain = self::getDomain($email);
            if ($domain) {
                $grouped[$domain][] = $email;
            }
        }
        
        return $grouped;
    }
    
    /**
     * Remove duplicates (considering aliases)
     */
    public static function removeDuplicates(array $emails): array
    {
        $unique = [];
        $seen = [];
        
        foreach ($emails as $email) {
            $canonical = self::canonicalize($email);
            if ($canonical && !isset($seen[$canonical])) {
                $unique[] = $email;
                $seen[$canonical] = true;
            }
        }
        
        return $unique;
    }
    
    // ============================= Domain Management =============================
    
    /**
     * Add allowed domain
     */
    public static function addAllowedDomain(string $domain): void
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        if (!in_array($domain, self::$customAllowedDomains)) {
            self::$customAllowedDomains[] = $domain;
        }
    }
    
    /**
     * Remove allowed domain
     */
    public static function removeAllowedDomain(string $domain): void
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        self::$customAllowedDomains = array_diff(self::$customAllowedDomains, [$domain]);
    }
    
    /**
     * Add blocked domain
     */
    public static function addBlockedDomain(string $domain): void
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        if (!in_array($domain, self::$customBlockedDomains)) {
            self::$customBlockedDomains[] = $domain;
        }
    }
    
    /**
     * Remove blocked domain
     */
    public static function removeBlockedDomain(string $domain): void
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        self::$customBlockedDomains = array_diff(self::$customBlockedDomains, [$domain]);
    }
    
    /**
     * Get all allowed domains
     */
    public static function getAllowedDomains(): array
    {
        return array_unique(array_merge(
            array_merge(...array_values(self::PROVIDERS)),
            self::$customAllowedDomains
        ));
    }
    
    /**
     * Get all blocked domains
     */
    public static function getBlockedDomains(): array
    {
        return array_unique(array_merge(
            self::DISPOSABLE_DOMAINS,
            self::$customBlockedDomains
        ));
    }
    
    /**
     * Check if domain is allowed
     */
    public static function isDomainAllowed(string $domain): bool
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        return in_array($domain, self::getAllowedDomains());
    }
    
    /**
     * Check if domain is blocked
     */
    public static function isDomainBlocked(string $domain): bool
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        return in_array($domain, self::getBlockedDomains());
    }
    
    // ============================= IDN Support =============================
    
    /**
     * Convert IDN domain to ASCII (Punycode)
     */
    public static function toAsciiDomain(string $domain): ?string
    {
        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            return $ascii === false ? null : $ascii;
        }
        
        // Fallback: check if already ASCII
        if (preg_match('/[^\x20-\x7E]/', $domain)) {
            return null; // Contains non-ASCII
        }
        
        return $domain;
    }
    
    /**
     * Convert ASCII domain to IDN
     */
    public static function toUnicodeDomain(string $domain): ?string
    {
        if (function_exists('idn_to_utf8')) {
            $unicode = idn_to_utf8($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            return $unicode === false ? null : $unicode;
        }
        
        return $domain;
    }
    
    /**
     * Check if domain is IDN
     */
    public static function isIdnDomain(string $domain): bool
    {
        return preg_match('/[^\x20-\x7E]/', $domain) === 1 || 
               str_starts_with($domain, 'xn--');
    }
    
    // ============================= Utilities =============================
    
    /**
     * Clear DNS cache
     */
    public static function clearDnsCache(): void
    {
        self::$dnsCache = [];
    }
    
    /**
     * Export configuration
     */
    public static function exportConfig(): array
    {
        return [
            'allowed_domains' => self::$customAllowedDomains,
            'blocked_domains' => self::$customBlockedDomains,
            'providers' => self::PROVIDERS,
            'disposable_domains' => self::DISPOSABLE_DOMAINS,
            'role_based' => self::ROLE_BASED,
        ];
    }
    
    /**
     * Import configuration
     */
    public static function importConfig(array $config): void
    {
        if (isset($config['allowed_domains'])) {
            self::$customAllowedDomains = $config['allowed_domains'];
        }
        
        if (isset($config['blocked_domains'])) {
            self::$customBlockedDomains = $config['blocked_domains'];
        }
    }
    
    /**
     * Get library version
     */
    public static function getVersion(): string
    {
        return '2.0.0';
    }
    
    // ============================= Comparison =============================
    
    /**
     * Compare two emails (ignoring aliases)
     */
    public static function areEqual(string $email1, string $email2): bool
    {
        $canonical1 = self::canonicalize($email1);
        $canonical2 = self::canonicalize($email2);
        
        return $canonical1 === $canonical2 && $canonical1 !== null;
    }
    
    /**
     * Calculate similarity between emails
     */
    public static function similarity(string $email1, string $email2): float
    {
        similar_text($email1, $email2, $percent);
        return round($percent, 2);
    }
    
    /**
     * Find similar emails
     */
    public static function findSimilar(string $email, array $emails, float $threshold = 80.0): array
    {
        $similar = [];
        
        foreach ($emails as $compareEmail) {
            if ($email === $compareEmail) {
                continue;
            }
            
            $similarity = self::similarity($email, $compareEmail);
            if ($similarity >= $threshold) {
                $similar[] = [
                    'email' => $compareEmail,
                    'similarity' => $similarity
                ];
            }
        }
        
        // Sort by similarity
        usort($similar, fn($a, $b) => $b['similarity'] <=> $a['similarity']);
        
        return $similar;
    }
    
    // ============================= Advanced Features =============================
    
    /**
     * Parse email with name
     */
    public static function parseWithName(string $emailString): array
    {
        $result = [
            'name' => null,
            'email' => null,
            'valid' => false
        ];
        
        // Pattern: "Name" <email@domain.com>
        if (preg_match('/^"?([^"<>]+)"?\s*<([^<>]+)>$/', trim($emailString), $matches)) {
            $result['name'] = trim($matches[1], ' "');
            $result['email'] = $matches[2];
        }
        // Pattern: Name <email@domain.com>
        elseif (preg_match('/^([^<>]+)<([^<>]+)>$/', trim($emailString), $matches)) {
            $result['name'] = trim($matches[1]);
            $result['email'] = $matches[2];
        }
        // Pattern: email@domain.com (Name)
        elseif (preg_match('/^([^\s]+)\s*\(([^)]+)\)$/', trim($emailString), $matches)) {
            $result['email'] = $matches[1];
            $result['name'] = $matches[2];
        }
        // Just email
        else {
            $result['email'] = trim($emailString);
        }
        
        if ($result['email']) {
            $result['valid'] = self::isValid($result['email']);
        }
        
        return $result;
    }
    
    /**
     * Format email with name
     */
    public static function formatWithName(string $email, string $name = null): string
    {
        if (!$name) {
            return $email;
        }
        
        // Quote name if it contains special characters
        if (preg_match('/[,;<>@]/', $name)) {
            $name = '"' . str_replace('"', '\\"', $name) . '"';
        }
        
        return $name . ' <' . $email . '>';
    }
    
    /**
     * Extract emails from text
     */
    public static function extractFromText(string $text): array
    {
        $pattern = '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/';
        preg_match_all($pattern, $text, $matches);
        
        return array_unique(array_filter($matches[0], [self::class, 'isValid']));
    }
    
    /**
     * Generate email permutations from name
     */
    public static function generateFromName(string $firstName, string $lastName, string $domain): array
    {
        $firstName = strtolower(preg_replace('/[^a-zA-Z]/', '', $firstName));
        $lastName = strtolower(preg_replace('/[^a-zA-Z]/', '', $lastName));
        
        if (!$firstName || !$lastName) {
            return [];
        }
        
        $patterns = [
            $firstName . '@' . $domain,                          // john@
            $lastName . '@' . $domain,                           // doe@
            $firstName . '.' . $lastName . '@' . $domain,        // john.doe@
            $firstName . '_' . $lastName . '@' . $domain,        // john_doe@
            $firstName . '-' . $lastName . '@' . $domain,        // john-doe@
            $firstName . $lastName . '@' . $domain,              // johndoe@
            $firstName[0] . $lastName . '@' . $domain,           // jdoe@
            $firstName . $lastName[0] . '@' . $domain,           // johnd@
            $firstName[0] . '.' . $lastName . '@' . $domain,     // j.doe@
            $lastName . '.' . $firstName . '@' . $domain,        // doe.john@
            $lastName . $firstName . '@' . $domain,              // doejohn@
            $firstName . substr($lastName, 0, 1) . '@' . $domain, // johnd@
            substr($firstName, 0, 1) . substr($lastName, 0, 1) . '@' . $domain, // jd@
        ];
        
        return array_unique($patterns);
    }
    
    /**
     * Validate email list format (line by line)
     */
    public static function validateList(string $list): array
    {
        $emails = preg_split('/\r\n|\r|\n/', trim($list));
        $results = [
            'valid' => [],
            'invalid' => [],
            'total' => count($emails)
        ];
        
        foreach ($emails as $email) {
            $email = trim($email);
            if (empty($email)) {
                continue;
            }
            
            if (self::isValid($email)) {
                $results['valid'][] = $email;
            } else {
                $results['invalid'][] = $email;
            }
        }
        
        return $results;
    }
}