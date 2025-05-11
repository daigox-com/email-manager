<?php
declare(strict_types=1);

namespace Daigox\EmailManager;

use InvalidArgumentException;

/**
 * Class EmailManager
 *
 * Robust helpers for validating, normalising and formatting e-mail addresses with
 * first-class support for IDN (Unicode) domains, plus configurable domain allow-lists.
 *
 * @author  DaigoX.com
 * @license MIT
 *
 * @psalm-immutable
 */
final class EmailManager
{
    /** @var string[] Built-in popular public domains. */
    private const DEFAULT_VALID_DOMAINS = [
        'gmail.com', 'yahoo.com', 'outlook.com', 'mail.com', 'hotmail.com', 'icloud.com',
    ];

    /** @psalm-var array<string,true> */
    private static array $customValidDomains = [];

    /** Utility class: prevent instantiation & cloning. */
    private function __construct() {}
    private function __clone() {}

    // ────────────────────────────── Public API ────────────────────────────────

    /**
     * Validates an e-mail address.
     *
     * @param bool $checkDomainInAllowList  Whether to verify the domain against the allow-list.
     * @param bool $checkMxRecord           Whether to ensure an MX/DNS record exists for the domain.
     */
    public static function isEmailValid(
        string $email,
        bool $checkDomainInAllowList = true,
        bool $checkMxRecord = false,
    ): bool {
        $clean = self::normalise($email);
        if ($clean === null) {
            return false;
        }

        if ($checkDomainInAllowList && !self::isDomainAllowed($clean)) {
            return false;
        }

        if ($checkMxRecord && !self::hasMxRecord($clean)) {
            return false;
        }

        return true;
    }

    /**
     * Extracts the domain part of an e-mail. Returns null if invalid.
     */
    public static function getDomain(string $email): ?string
    {
        $clean = self::normalise($email);
        if ($clean === null) {
            return null;
        }

        return substr(strrchr($clean, '@') ?: '', 1);
    }

    /**
     * Extracts and lowercases the local (left-hand) part of an e-mail. Returns null if invalid.
     */
    public static function getLocalPart(string $email): ?string
    {
        $clean = self::normalise($email);
        if ($clean === null) {
            return null;
        }

        return strtolower(strstr($clean, '@', true));
    }

    /**
     * Normalises an e-mail address: trims spaces, removes hidden chars, converts
     * IDN domains to ASCII (punycode), removes Gmail dots & sub-addressing, and
     * returns the canonical lower-case form. Returns null if the address is not
     * syntactically valid.
     */
    public static function normalise(string $email): ?string
    {
        $email = trim(mb_strtolower($email, 'UTF-8'));

        // Quick syntax check.
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return null;
        }

        [$local, $domain] = explode('@', $email, 2);

        // Handle Gmail/Googlemail quirks: ignore dots and text after +
        if (in_array($domain, ['gmail.com', 'googlemail.com'], true)) {
            $local  = str_replace('.', '', $local);
            $local  = preg_replace('/\+.*/', '', $local);
        }

        $asciiDomain = self::toAsciiDomain($domain);
        if ($asciiDomain === null) {
            return null;
        }

        return $local . '@' . $asciiDomain;
    }

    /**
     * Obfuscates an e-mail for display: replaces @ → " at " and . → " dot ".
     */
    public static function obfuscate(string $email): string
    {
        return strtr($email, ['@' => ' at ', '.' => ' dot ']);
    }

    /**
     * Returns the combined allow-list (built-in + dynamic additions).
     *
     * @return string[]
     */
    public static function listAllowedDomains(): array
    {
        return array_keys(self::getAllowedDomainMap());
    }

    /** Adds a domain (case-insensitive) to the allow-list. */
    public static function addAllowedDomain(string $domain): void
    {
        $domain = mb_strtolower($domain, 'UTF-8');
        self::$customValidDomains[$domain] = true;
    }

    /** Removes a domain from the custom allow-list. */
    public static function removeAllowedDomain(string $domain): void
    {
        unset(self::$customValidDomains[mb_strtolower($domain, 'UTF-8')]);
    }

    // ───────────────────────────── Internal helpers ───────────────────────────

    private static function isDomainAllowed(string $email): bool
    {
        $domain = substr(strrchr($email, '@'), 1);
        return isset(self::getAllowedDomainMap()[$domain]);
    }

    /** @psalm-return array<string, true> */
    private static function getAllowedDomainMap(): array
    {
        static $builtInMap = null;
        if ($builtInMap === null) {
            $builtInMap = array_fill_keys(self::DEFAULT_VALID_DOMAINS, true);
        }

        return $builtInMap + self::$customValidDomains;
    }

    private static function hasMxRecord(string $email): bool
    {
        $domain = substr(strrchr($email, '@'), 1);
        return checkdnsrr($domain, 'MX');
    }

    /** Converts an IDN domain to its ASCII representation; returns null on failure. */
    private static function toAsciiDomain(string $domain): ?string
    {
        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($domain, \IDNA_DEFAULT, \INTL_IDNA_VARIANT_UTS46);
            if ($ascii === false) {
                return null;
            }
            return $ascii;
        }

        // intl extension not available – best-effort fallback.
        if (preg_match('/[^\x20-\x7E]/', $domain)) {
            // Contains non-ASCII chars we cannot safely convert.
            return null;
        }

        return $domain;
    }
}
